#!/usr/bin/env python3
"""Paired native FESS before/after probes. Uses only Python's standard library.
Run on an isolated test host: generates real traffic and disposable databases.
PostgreSQL admin DSN is read from FESS_BENCH_POSTGRES (CREATE DATABASE required).
"""
import argparse, datetime, json, os, pathlib, platform, shutil, signal, socket
import subprocess, tempfile, time, urllib.parse, urllib.request, uuid

P = argparse.ArgumentParser(description=__doc__)
P.add_argument('--before', required=True)
P.add_argument('--after', required=True)
P.add_argument('--loadgen', default='dist/fess-load')
P.add_argument('--seconds', type=int, default=10)
P.add_argument('--workers', default='16,64')
P.add_argument('--backends', default='sqlite,postgres')
P.add_argument('--output', default='benchmarks/batch-comparison-2026-10-20.json')
A = P.parse_args()
BEFORE, AFTER, LOAD = map(lambda p: str(pathlib.Path(p).resolve()), (A.before,A.after,A.loadgen))
OUTPUT = pathlib.Path(A.output).resolve()
REPORT = {'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'machine':{'platform':platform.platform(), 'logical_cpus':os.cpu_count()},
          'conditions':['Paired probes; fresh storage for every version/scenario/concurrency.',
                        'Fixed-worker closed-loop HTTP over loopback; all components share the host.',
                        '1 second warmup, then configured measurement duration.',
                        'One policy with path-block and body-contains rules; rate limit, bots, ClamAV disabled.',
                        'Request body is 64 KiB for body probes; upstream response is 9 bytes.',
                        'Access/WAF rows are counted after a flush barrier; effective RPS includes drain/count time.',
                        'Background desktop applications and antivirus remain active; short probes are not production sizing.'],
          'seconds':A.seconds, 'runs':[]}

def save():
    OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    OUTPUT.write_text(json.dumps(REPORT,indent=2))

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def request(port,method,path,body=None):
    req=urllib.request.Request(f'http://127.0.0.1:{port}'+path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=60) as response:
        return json.load(response)

def load(url,workers,scenario,duration):
    args=[LOAD,'-url',url,'-host','app.test','-concurrency',str(workers),'-duration',f'{duration}s']
    if scenario=='body-64KiB': args+=['-method','POST','-body-bytes','65536']
    p=subprocess.run(args,capture_output=True,text=True,timeout=duration+30)
    r=json.loads(p.stdout)
    assert p.returncode==0,r
    expected='403' if scenario=='block' else '200'
    assert set(r['status_codes'])=={expected},r
    return r

upstream_port=free_port()
upstream=subprocess.Popen([LOAD,'-serve',f'127.0.0.1:{upstream_port}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
time.sleep(.2)
PSQL=os.environ.get('FESS_BENCH_PSQL','psql')
ADMIN=os.environ.get('FESS_BENCH_POSTGRES','')

def probe(backend,scenario,workers,version):
    pg_name='fess_probe_'+uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='fess-probe-') as directory:
        admin_port,gw_port=free_port(),free_port()
        env=os.environ.copy();env['FENCE_AUTH_DISABLED']='1';env['FESS_LOG_MODE']='sync' if version=='after-sync' else 'batch'
        binary=BEFORE if version=='before' else AFTER
        args=[binary,'--data-dir',directory,'--admin',f'127.0.0.1:{admin_port}', '--http',f'127.0.0.1:{gw_port}','--https','']
        pg_created=False
        if backend=='postgres':
            if not ADMIN: raise RuntimeError('Set FESS_BENCH_POSTGRES to a disposable test PostgreSQL admin DSN')
            subprocess.run([PSQL,ADMIN,'-v','ON_ERROR_STOP=1','-c',f'CREATE DATABASE "{pg_name}"'],capture_output=True,check=True)
            pg_created=True;u=urllib.parse.urlsplit(ADMIN);dsn=urllib.parse.urlunsplit(u._replace(path='/'+pg_name))
            args+=['--db','postgres','--dsn',dsn]
        with open(directory+'/server.log','w') as log:
            p=subprocess.Popen(args,env=env,stdout=log,stderr=log)
            try:
                for _ in range(200):
                    if p.poll() is not None: raise RuntimeError('FESS exited during startup')
                    try:
                        urllib.request.urlopen(f'http://127.0.0.1:{admin_port}/healthz',timeout=1).close();break
                    except OSError: time.sleep(.05)
                else: raise RuntimeError('FESS did not start')
                api=lambda method,path,body=None:request(admin_port,method,'/api/v1'+path,body)
                api('PUT','/settings/rate-limit',{'config':{'enabled':False}})
                cfg=api('GET','/settings/malware');cfg['clamd']['enabled']=False;cfg['icap']['enabled']=False;api('PUT','/settings/malware',cfg)
                pid=api('POST','/policies',{'name':'paired-probe','mode':'block','priority':1})['id']
                for name,condition in [('block',{'path_prefix':'/blocked'}),('body',{'body_contains':'never-match-needle'})]:
                    api('POST',f'/policies/{pid}/rules',{'name':name,'action':'block','priority':1 if name=='block' else 2,'condition_json':condition})
                api('POST',f'/policies/{pid}/publish',{})
                sid=api('POST','/sites',{'name':'probe','host_pattern':'app.test','policy_id':pid,'priority':1})['id']
                api('POST',f'/sites/{sid}/backends',{'name':'origin','base_url':f'http://127.0.0.1:{upstream_port}','priority':1})
                time.sleep(.05)
                path='/blocked' if scenario=='block' else '/pass'
                target=f'http://127.0.0.1:{gw_port}'+path
                load(target,workers,scenario,1)
                warm_rows=api('GET','/proxy-access-logs?limit=1')['total']
                warm_waf=api('GET','/logs?limit=1')['total']
                r=load(target,workers,scenario,A.seconds)
                started=time.monotonic();rows=api('GET','/proxy-access-logs?limit=1')['total'];drain=time.monotonic()-started
                waf_rows=api('GET','/logs?limit=1')['total']
                assert rows-warm_rows==r['requests'],(version,backend,'lost access rows',rows-warm_rows,r['requests'])
                assert waf_rows-warm_waf==(r['requests'] if scenario=='block' else 0),(version,backend,'lost WAF rows')
                log.flush();errors=[line for line in pathlib.Path(directory+'/server.log').read_text().splitlines() if 'insert failed' in line or 'retained (' in line or 'enqueue failed' in line]
                assert not errors,errors[:3]
                r.update(backend=backend,scenario=scenario,version=version,
                         drain_and_count_seconds=drain,effective_rps=r['requests']/(r['elapsed_seconds']+drain),
                         persisted_access_rows=rows-warm_rows,persisted_waf_rows=waf_rows-warm_waf,log_errors=errors)
                REPORT['runs'].append(r);save()
                print(backend,scenario,workers,version,round(r['effective_rps']),round(r['p95_ms'],2),flush=True)
            finally:
                p.send_signal(signal.SIGTERM);p.wait(timeout=25)
                assert p.returncode==0,(p.returncode,pathlib.Path(directory+'/server.log').read_text()[-1000:])
                if pg_created:
                    subprocess.run([PSQL,ADMIN,'-v','ON_ERROR_STOP=1','-c',f'DROP DATABASE "{pg_name}"'],capture_output=True,check=True)
try:
    for backend in A.backends.split(','):
        for scenario in ['proxy','block','body-64KiB']:
            for workers in map(int,A.workers.split(',')):
                versions=['before','after'] if workers==16 else ['after','before']
                for version in versions: probe(backend,scenario,workers,version)
            # Isolate the body-buffer improvement from batching at 16 clients.
            if scenario=='body-64KiB': probe(backend,scenario,16,'after-sync')
finally:
    upstream.terminate();upstream.wait();REPORT['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
