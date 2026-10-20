#!/usr/bin/env python3
"""Summarize same-runner XDP ramp JSONs, normalizing each repeat to its baseline."""
import argparse, json, statistics, pathlib

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('files',nargs='+')
p.add_argument('--output',required=True)
a=p.parse_args()
documents=[json.loads(pathlib.Path(f).read_text()) for f in a.files]
first=documents[0]
for d in documents:
    for field in ['machine','mode','levels','source_commit','service_cpus','generator_cpus']:
        assert d[field]==first[field],f'inconsistent {field}'
runs=[r for d in documents for r in d['runs']]
identities=[(r['repeat'],r['scenario'],r['requested_pps'],r['xdp']) for r in runs]
assert len(identities)==len(set(identities)),'duplicate probes'
baselines={(r['repeat'],r['xdp']):r['successful_rps_including_drain'] for r in runs if r['scenario']=='normal'}
repeat_ids={r['repeat'] for r in runs}
assert len(baselines)==2*len(repeat_ids),'missing baselines'
for r in runs:
    assert r['access_rows']==sum(r['http']['status_codes'].values()),'log count mismatch'
median=statistics.median
rows=[]
for scenario in ['normal','cidr-syn','rate-syn','cidr-udp','rate-udp']:
    for level in ([0] if scenario=='normal' else first['levels']):
        for enabled in [False,True]:
            group=[r for r in runs if r['scenario']==scenario and r['requested_pps']==level and r['xdp']==enabled]
            if not group:continue
            assert {r['repeat'] for r in group}==repeat_ids,'incomplete repetition group'
            rps=[r['successful_rps_including_drain'] for r in group]
            retention=[r['successful_rps_including_drain']/baselines[r['repeat'],enabled] for r in group]
            pps=[r['attack']['actual_pps'] if r['attack'] else 0 for r in group]
            sent=sum(r['attack']['sent'] for r in group if r['attack'])
            drops=sum(r['xdp_delta'].get('cidr_drop',0)+r['xdp_delta'].get('rate_drop',0) for r in group)
            rows.append({'scenario':scenario,'requested_pps':level,'xdp':enabled,'repeats':len(group),
                'actual_pps':median(pps),'actual_pps_min':min(pps),'actual_pps_max':max(pps),
                'target_attainment':median(pps)/level if level else 1,
                'rps':median(rps),'rps_min':min(rps),'rps_max':max(rps),
                'retained_http':median(retention),'retained_min':min(retention),'retained_max':max(retention),
                'p95_ms':median(r['http']['p95_ms'] for r in group),'p99_ms':median(r['http']['p99_ms'] for r in group),
                'transport_errors':sum(r['http']['transport_errors'] for r in group),
                'unexpected_http':sum(n for r in group for code,n in r['http']['status_codes'].items() if code!='200'),
                'sent':sent,'xdp_drops':drops,'drop_fraction':drops/sent if sent and enabled else None,
                'syn_cookies':sum(r['tcp_ext_delta']['SyncookiesSent'] for r in group),
                'softirq_cpu_percent':median(r['host_softirq_percent'] for r in group),
                'host_busy_percent':median(r['host_busy_percent'] for r in group)})
thresholds=[]
for scenario in ['cidr-syn','rate-syn','cidr-udp','rate-udp']:
    for enabled in [False,True]:
        series=[r for r in rows if r['scenario']==scenario and r['xdp']==enabled]
        hit=next((r for r in series if r['retained_http']<.9),None)
        saturated=next((r for r in series if r['target_attainment']<.9),None)
        thresholds.append({'scenario':scenario,'xdp':enabled,'first_10_percent_decline':hit,
                           'first_offered_pps_below_90_percent_target':saturated})
report={'source_files':a.files,'source_commit':first['source_commit'],'machine':first['machine'],
        'mode':first['mode'],'generator_cpus':first['generator_cpus'],'service_cpus':first['service_cpus'],
        'threshold_rule':'first requested step with median per-repeat HTTP retention <90%; not a physical NIC limit',
        'started_at':min(d['started_at'] for d in documents),'finished_at':max(d.get('finished_at',d['started_at']) for d in documents),
        'probe_count':len(runs),'http_requests':sum(r['http']['requests'] for r in runs),
        'attack_packets':sum(r['attack']['sent'] for r in runs if r['attack']),
        'transport_errors':sum(r['http']['transport_errors'] for r in runs),'rows':rows,'thresholds':thresholds}
pathlib.Path(a.output).write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'probe_count':len(runs),'http_requests':report['http_requests'],'thresholds':thresholds},indent=2))
