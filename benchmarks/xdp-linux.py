#!/usr/bin/env python3
"""Root Linux benchmark. All generated packets stay on a disposable veth pair.
No default route is installed in the client namespace. Never attaches to a host NIC.
"""
import argparse, datetime, json, os, pathlib, platform, subprocess, tempfile, time, urllib.request

P=argparse.ArgumentParser(description=__doc__)
P.add_argument('--seconds',type=int,default=12)
P.add_argument('--repeats',type=int,default=3)
P.add_argument('--pps',type=int,default=50000)
P.add_argument('--mode',choices=['generic','native'],default='generic')
P.add_argument('--output',default='benchmarks/xdp-linux-results.json')
A=P.parse_args()
assert os.geteuid()==0 and 1<=A.seconds<=60 and 1<=A.repeats<=10 and 1<=A.pps<=100000
ROOT=pathlib.Path(__file__).resolve().parent.parent
BIN={n:str(ROOT/'dist'/n) for n in ['fess','fess-xdp','fess-load','fess-rawload','fess-xdpstats']}
suffix=str(os.getpid());host='fxh'+suffix;peer='fxp'+suffix;ns='fess-bench-'+suffix
processes=[]
def cmd(*a,check=True):return subprocess.run(a,check=check,capture_output=True,text=True)
def client(*a):return ['ip','netns','exec',ns,*a]
def api(method,path,body=None):
 req=urllib.request.Request('http://127.0.0.1:18082/api/v1'+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=30) as r:return json.load(r)
def load(seconds):
 r=cmd(*client(BIN['fess-load'],'-url','http://192.0.2.1:18080/pass','-host','app.test','-duration',f'{seconds}s','-concurrency','16'),check=False)
 data=json.loads(r.stdout);data['exit_code']=r.returncode;return data
def stop(p):
 if p and p.poll() is None:p.terminate();p.wait(timeout=35)
def ticks(pid):
 s=pathlib.Path(f'/proc/{pid}/stat').read_text().split(') ',1)[1].split();return int(s[11])+int(s[12])
def cpu():return list(map(int,pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
def netstats():
 out=cmd('cat','/proc/net/netstat').stdout.splitlines();result={}
 for h,v in zip(out[::2],out[1::2]):
  names=h.split();vals=v.split()
  if names[0]=='TcpExt:':result={k:int(v) for k,v in zip(names[1:],vals[1:]) if k in ['ListenDrops','ListenOverflows','SyncookiesSent','TCPReqQFullDoCookies','TCPReqQFullDrop']}
 return result
REPORT={'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'machine':{'platform':platform.platform(),'cpus':os.cpu_count(),'affinity':sorted(os.sched_getaffinity(0)),'cpu_model':next((l.split(':',1)[1].strip() for l in pathlib.Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')),'unknown')},'mode':A.mode,'seconds':A.seconds,'repeats':A.repeats,'requested_pps':A.pps,'runs':[],
 'conditions':['Linux GitHub Actions shared runner; veth, no physical NIC throughput claim.','FESS, upstream, HTTP and packet generators share CPUs; measured offered PPS can differ between pairs.','HTTP: 16 closed-loop clients, keep-alive, SQLite batch journal, one nonmatching WAF rule; ClamAV/rate/bots disabled.','Attack: valid IPv4 SYN or empty UDP to protected port 18080 from isolated 192.0.2.3. Legitimate HTTP uses 192.0.2.2.','CIDR cases deny attack source. Rate cases: 10000 PPS and 1000 SYN/s per IP; legitimate 192.0.2.2 explicitly allowed to isolate attack protection.','3 paired repetitions, alternating off/on order. Fresh FESS/SQLite each probe. One second HTTP warmup before measurement.','Counters cover measured flood and HTTP drain, captured before journal flush. Log totals checked after flush. CPU metrics are whole-host CPU and FESS process, not isolated networking CPU.']}
output=pathlib.Path(A.output).resolve()
def save():output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(REPORT,indent=2))
try:
 cmd('ip','netns','add',ns);cmd('ip','link','add',host,'type','veth','peer','name',peer);cmd('ip','link','set',peer,'netns',ns)
 cmd('ip','addr','add','192.0.2.1/24','dev',host);cmd('ip','link','set',host,'up')
 for addr in ['192.0.2.2/24','192.0.2.3/24']:cmd(*client('ip','addr','add',addr,'dev',peer))
 cmd(*client('ip','link','set',peer,'up'));cmd(*client('ip','link','set','lo','up'))
 # Suppress synthetic client's RSTs so SYN backlog pressure is exercised.
 cmd(*client('iptables','-A','OUTPUT','-s','192.0.2.3','-p','tcp','--tcp-flags','RST','RST','-j','DROP'))
 mac=pathlib.Path(f'/sys/class/net/{host}/address').read_text().strip()
 up=subprocess.Popen([BIN['fess-load'],'-serve','127.0.0.1:18081'],stdout=subprocess.DEVNULL);processes.append(up)
 time.sleep(.2)
 for repeat in range(A.repeats):
  for scenario in ['normal','cidr-syn','rate-syn','cidr-udp','rate-udp']:
   for enabled in ([False,True] if repeat%2==0 else [True,False]):
    with tempfile.TemporaryDirectory(prefix='fess-xdp-bench-') as d:
     guard=flood=server=None
     with open(d+'/server.log','w+') as log,open(d+'/xdp.log','w+') as xlog:
      try:
       env=os.environ.copy();env.update(FENCE_AUTH_DISABLED='1',FESS_LOG_MODE='batch')
       server=subprocess.Popen([BIN['fess'],'--data-dir',d,'--admin','127.0.0.1:18082','--http','192.0.2.1:18080','--https',''],env=env,stdout=log,stderr=log);processes.append(server)
       for _ in range(200):
        try:api('GET','/sites');break
        except OSError:time.sleep(.05)
       else:raise RuntimeError('FESS failed to start')
       api('PUT','/settings/rate-limit',{'config':{'enabled':False}})
       cfg=api('GET','/settings/malware');cfg['clamd']['enabled']=False;cfg['icap']['enabled']=False;api('PUT','/settings/malware',cfg)
       cfg=api('GET','/settings/bot-protection');cfg['enabled']=False;api('PUT','/settings/bot-protection',cfg)
       policy=api('POST','/policies',{'name':'xdp-probe','mode':'block','priority':1})['id']
       api('POST',f'/policies/{policy}/rules',{'name':'nonmatching','action':'block','priority':1,'condition_json':{'path_prefix':'/never-block'}})
       api('POST',f'/policies/{policy}/publish',{})
       site=api('POST','/sites',{'name':'probe','host_pattern':'app.test','policy_id':policy,'priority':1})['id']
       api('POST',f'/sites/{site}/backends',{'name':'origin','base_url':'http://127.0.0.1:18081','priority':1})
       if enabled:
        cfg={'interface':host,'mode':A.mode,'ports':[{'protocol':'tcp','port':18080},{'protocol':'udp','port':18080}],'allow_cidrs':['192.0.2.2/32']}
        if scenario.startswith('cidr'):cfg['block_cidrs']=['192.0.2.3/32']
        if scenario.startswith('rate'):cfg.update(packets_per_second=10000,syns_per_second=1000)
        path=pathlib.Path(d)/'xdp.json';path.write_text(json.dumps(cfg))
        guard=subprocess.Popen([BIN['fess-xdp'],'--config',str(path)],stdout=xlog,stderr=xlog);processes.append(guard)
        for _ in range(100):
         xlog.flush();xlog.seek(0);text=xlog.read()
         if guard.poll() is not None:raise RuntimeError(text)
         if 'attached interface='+host in text:break
         time.sleep(.05)
        else:raise RuntimeError('XDP attach timed out')
       warm=load(1);assert warm['transport_errors']==0,warm
       before_rows=api('GET','/proxy-access-logs?limit=1')['total']
       before_x=json.loads(cmd(BIN['fess-xdpstats']).stdout) if enabled else {}
       before_net=netstats();before_cpu=cpu();before_ticks=ticks(server.pid);start=time.monotonic()
       if scenario!='normal':
        flood=subprocess.Popen(client(BIN['fess-rawload'],'-interface',peer,'-destination-mac',mac,'-protocol','syn' if scenario.endswith('syn') else 'udp','-pps',str(A.pps),'-duration',f'{A.seconds}s'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append(flood)
       result=load(A.seconds)
       attack=None
       if flood:
        out,err=flood.communicate(timeout=15);assert flood.returncode==0,err;attack=json.loads(out)
       elapsed=time.monotonic()-start;after_ticks=ticks(server.pid);after_cpu=cpu();after_net=netstats()
       after_x=json.loads(cmd(BIN['fess-xdpstats']).stdout) if enabled else {}
       drain_start=time.monotonic();rows=api('GET','/proxy-access-logs?limit=1')['total']-before_rows;drain=time.monotonic()-drain_start
       successes=result['status_codes'].get('200',0)
       assert rows==successes,(rows,result)
       delta=[b-a for a,b in zip(before_cpu,after_cpu)];total=sum(delta);idle=delta[3]+delta[4]
       row={'repeat':repeat+1,'scenario':scenario,'xdp':enabled,'http':result,'attack':attack,'access_rows':rows,'journal_drain_seconds':drain,'successful_rps_including_drain':successes/(result['elapsed_seconds']+drain),'wall_seconds':elapsed,'fess_cpu_percent_one_core':100*(after_ticks-before_ticks)/os.sysconf('SC_CLK_TCK')/elapsed,'host_busy_percent':100*(total-idle)/total,'host_softirq_percent':100*delta[6]/total,'tcp_ext_delta':{k:after_net[k]-v for k,v in before_net.items()},'xdp_delta':{k:after_x[k]-v for k,v in before_x.items()}}
       REPORT['runs'].append(row);save();print(json.dumps(row),flush=True)
      finally:
       stop(flood);stop(guard);stop(server)
 # A detached filter must leave normal HTTP available on the interface (upstream control).
 REPORT['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
finally:
 for p in reversed(processes):stop(p)
 cmd('ip','link','del',host,check=False);cmd('ip','netns','del',ns,check=False)
