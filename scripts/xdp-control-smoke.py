#!/usr/bin/env python3
"""Privileged systemd integration test using a new, disposable veth/netns only.

Requires installed fess-xdp and its running local controller. Refuses an existing
configuration, so this must run on a disposable CI machine/container.
"""
import http.client, json, os, pathlib, socket, subprocess, sys, tempfile, time
loadgen = str(pathlib.Path(sys.argv[1]).resolve())
config_path = pathlib.Path('/etc/fess/xdp.json')
control_socket = '/run/fess-xdp-control/control.sock'
suffix = str(os.getpid())
host, peer, namespace = 'fch'+suffix, 'fcp'+suffix, 'fess-control-'+suffix
processes = []
created = False

class UnixHTTP(http.client.HTTPConnection):
 def connect(self):
  self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  self.sock.settimeout(20)
  self.sock.connect(control_socket)

def call(method, path, body=None, want=200):
 c = UnixHTTP('localhost', timeout=20)
 try:
  c.request(method, path, json.dumps(body) if body is not None else None, {'Content-Type':'application/json'})
  r = c.getresponse(); raw = r.read(); assert r.status == want, (method,path,r.status,raw)
  return json.loads(raw)
 finally: c.close()

def command(*args,check=True): return subprocess.run(args,check=check,capture_output=True,text=True)
def get(port): return command('ip','netns','exec',namespace,'curl','--silent','--fail','--max-time','.3',f'http://192.0.2.1:{port}/',check=False)

try:
 if config_path.exists(): raise RuntimeError('refusing to overwrite /etc/fess/xdp.json')
 command('ip','netns','add',namespace)
 command('ip','link','add',host,'type','veth','peer','name',peer)
 command('ip','link','set',peer,'netns',namespace)
 command('ip','addr','add','192.0.2.1/24','dev',host); command('ip','link','set',host,'up')
 command('ip','netns','exec',namespace,'ip','addr','add','192.0.2.2/24','dev',peer)
 command('ip','netns','exec',namespace,'ip','link','set',peer,'up')
 command('ip','netns','exec',namespace,'ip','link','set','lo','up')
 for port in [18080,18081]: processes.append(subprocess.Popen([loadgen,'-serve',f'192.0.2.1:{port}'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE))
 time.sleep(.2)
 assert get(18080).returncode == 0, 'baseline HTTP unavailable'
 cfg = {'interface':host,'mode':'generic','ports':[{'protocol':'tcp','port':18080}],
  'global_budget':{'enabled':True,'packets_per_second':10000,'packet_burst':20000},
  'icmp_ping':{'enabled':True,'packets_per_second':100,'burst':200,'per_ip_packets_per_second':10,'per_ip_burst':20},
  'malformed_packets':{'enabled':True,'invalid_lengths':True,'invalid_tcp_flags':True},
  'temporary_blocks':{'enabled':True,'socket_path':'/run/fess-xdp/blocks.sock','socket_group':'fess','ttl_seconds':2}}
 assert host in [i['name'] for i in call('GET','/interfaces')['items']]
 call('PUT','/config',{'config':cfg}); created = True
 call('POST','/start')
 status = call('GET','/status')
 assert status['service']['ActiveState']=='active' and status['attachment'], status
 assert get(18080).returncode == 0, 'valid HTTP affected with all protections enabled'
 deadline=time.monotonic()+15
 while time.monotonic()<deadline:
  sample=call('GET','/status').get('statistics')
  if sample and sample['interval_seconds']>0 and sample['counters'].get('protected_packets',0)>0: break
  time.sleep(.2)
 else: raise AssertionError('no live kernel statistics published')
 assert not sample['stale'] and sample['interface']==host, sample
 assert sample['rates'].get('protected_packets',0)>0, sample
 call('PUT','/config',{'config':cfg},want=409)
 with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as s: s.sendto(b'192.0.2.2','/run/fess-xdp/blocks.sock')
 time.sleep(.05)
 assert get(18080).returncode != 0, 'temporary ban did not drop protected HTTP'
 assert get(18081).returncode == 0, 'temporary ban affected unprotected port'
 time.sleep(2.1)
 assert get(18080).returncode == 0, 'temporary ban did not expire'
 call('POST','/stop')
 assert get(18080).returncode == 0, 'HTTP unavailable after detach'
 assert not call('GET','/status')['attachment'], 'filter still attached after stop'
 assert not pathlib.Path('/run/fess-xdp/blocks.sock').exists(), 'ban socket remains after stop'
 print('PASS: local controller config, interfaces, service start, kernel attachment, live statistics, live-edit conflict, socket ban, TTL, port scope, stop/detach')
finally:
 if created:
  command('systemctl','stop','fess-xdp.service',check=False)
  config_path.unlink(missing_ok=True)
 for p in reversed(processes):
  if p.poll() is None: p.terminate();p.wait(timeout=5)
 command('ip','link','del',host,check=False)
 command('ip','netns','del',namespace,check=False)
