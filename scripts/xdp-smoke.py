#!/usr/bin/env python3
"""Privileged Linux-only test; attaches only to a new disposable veth pair."""
import json, os, pathlib, subprocess, sys, tempfile, time
binary,loadgen=map(lambda p:str(pathlib.Path(p).resolve()),sys.argv[1:3])
suffix=str(os.getpid());host='fxh'+suffix;peer='fxp'+suffix;namespace='fess-xdp-'+suffix
processes=[]
def command(*args,check=True):return subprocess.run(args,check=check,capture_output=True,text=True)
def get(port):return command('ip','netns','exec',namespace,'curl','--silent','--fail','--max-time','1',f'http://192.0.2.1:{port}/',check=False)
try:
 command('ip','netns','add',namespace);command('ip','link','add',host,'type','veth','peer','name',peer)
 command('ip','link','set',peer,'netns',namespace)
 command('ip','addr','add','192.0.2.1/24','dev',host);command('ip','link','set',host,'up')
 command('ip','netns','exec',namespace,'ip','addr','add','192.0.2.2/24','dev',peer)
 command('ip','netns','exec',namespace,'ip','link','set',peer,'up')
 command('ip','netns','exec',namespace,'ip','link','set','lo','up')
 for port in [18080,18081]:processes.append(subprocess.Popen([loadgen,'-serve',f'192.0.2.1:{port}'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE))
 time.sleep(.2);assert get(18080).returncode==0,'upstream must work before attach'
 with tempfile.TemporaryDirectory(prefix='fess-xdp-') as d:
  cfg=pathlib.Path(d)/'xdp.json';cfg.write_text(json.dumps({'interface':host,'mode':'generic','ports':[{'protocol':'tcp','port':18080}],'block_cidrs':['192.0.2.2/32']}))
  log=open(d+'/xdp.log','w+');guard=subprocess.Popen([binary,'--config',str(cfg)],stdout=log,stderr=log);processes.append(guard)
  for _ in range(100):
   log.flush();log.seek(0);text=log.read()
   if 'attached interface=' in text:break
   if guard.poll() is not None:raise RuntimeError(text)
   time.sleep(.05)
  else:raise RuntimeError('XDP attachment timed out')
  assert get(18080).returncode!=0,'blocked source reached protected port'
  assert get(18081).returncode==0,'unprotected management port was affected'
  other=subprocess.run([binary,'--config',str(cfg)],capture_output=True,text=True,timeout=5)
  assert other.returncode!=0,'must refuse to replace an existing XDP program'
  assert get(18080).returncode!=0,'second attachment removed the first filter'
  guard.terminate();guard.wait(timeout=5);assert guard.returncode==0
  assert get(18080).returncode==0,'filter did not detach cleanly'
  log.close()
 print('PASS: veth attachment, CIDR drop, management pass, no replacement, clean detach')
finally:
 for p in reversed(processes):
  if p.poll() is None:p.terminate();p.wait(timeout=5)
 command('ip','link','del',host,check=False);command('ip','netns','del',namespace,check=False)
