"""Cisco SmartDiff parsing and comparison. No connections or configuration changes."""
from __future__ import annotations
import re
import json
import csv
from pathlib import Path
from datetime import datetime
from collections import Counter

MARKER = re.compile(r'^COMMAND:\s*(.+?)\s*$', re.M)
SEPARATOR = re.compile(r'^#{15,}\s*$', re.M)
ERROR = re.compile(r'% (?:Invalid input|Ambiguous command|Incomplete command)|\[COMMAND ERROR\]|Error opening|authorization failed', re.I)


def extract(text):
    """Split by original COMMAND markers, without interpreting Cisco output as a command."""
    matches = list(MARKER.finditer(text))
    output = {}
    for i, hit in enumerate(matches):
        name = ' '.join(hit.group(1).lower().split())
        if name in output:
            raise ValueError(f'Duplicate command section: {name}')
        begin = hit.end()
        end = matches[i+1].start() if i+1 < len(matches) else len(text)
        piece = text[begin:end]
        piece = re.sub(r'^\s*#{15,}\s*\n', '', piece, count=1)
        # Cut trailing delimiter preceding the next COMMAND.
        piece = re.sub(r'\n#{15,}\s*\Z', '', piece)
        output[name] = piece.strip()
    if not output:
        raise ValueError('No COMMAND: sections found; unsupported checks file')
    return output


def version(body):
    m = re.search(r'Cisco IOS XE Software, Version\s+(\d+)\.(\d+)\.(\d+)', body, re.I)
    if not m:
        m = re.search(r'Catalyst L3 Switch Software.*?Version\s+(\d+)\.(\d+)\.(\d+)', body, re.I)
    if not m:
        raise ValueError('IOS-XE version not found')
    return {'ios_xe_version': '.'.join(str(int(x)) for x in m.groups())}


def bgp(body):
    m = re.search(r'local AS number\s+(\d+)', body)
    if not m: raise ValueError('BGP local AS not detected')
    peers={}
    for line in body.splitlines():
        x=re.match(r'^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+4\s+(\d+)\s+(.+)$', line)
        if not x: continue
        columns=x.group(3).split()
        if len(columns)<7: continue
        state=columns[-1]
        prefixes=int(state) if state.isdigit() else None
        peers[x.group(1)]={'remote_as':int(x.group(2)), 'state':'Established' if prefixes is not None else state,
                           'prefixes_received':prefixes}
    if 'Neighbor' in body and not peers:
        raise ValueError('BGP peer table could not be parsed')
    return {'local_as':int(m.group(1)), 'neighbors':peers}


def ip_brief(body):
    entries={}
    for line in body.splitlines():
        p=line.split()
        if len(p)>=6 and re.match(r'^(?:Gi|Te|Fa|Eth|Vlan|Loopback|Port-channel|GigabitEthernet|TenGigabitEthernet)',p[0],re.I):
            entries[p[0]]={'ip':p[1],'admin_oper':' '.join(p[4:-1]).lower(),'protocol':p[-1].lower()}
    if not entries: raise ValueError('No interfaces parsed')
    return {'interfaces':entries}


def interface_status(body):
    entries={}
    for line in body.splitlines():
        p=line.split()
        if len(p)>=6 and re.match(r'^(?:Gi|Te|Fa|Po|Eth)\d',p[0],re.I):
            # Description may contain spaces; find known status token.
            idx=next((i for i,t in enumerate(p[1:],1) if t.lower() in ('connected','notconnect','disabled','err-disabled','inactive','monitoring','suspended')),None)
            if idx and len(p)>idx+2:
                entries[p[0]]={'description':' '.join(p[1:idx]), 'status':p[idx].lower(), 'vlan':p[idx+1]}
    if not entries: raise ValueError('No interface status rows parsed')
    return {'interfaces':entries}


def vlan(body):
    entries={}
    for line in body.splitlines():
        m=re.match(r'^\s*(\d{1,4})\s+(\S+)\s+(active|suspended|act/unsup)\b', line,re.I)
        if m: entries[m.group(1)]={'name':m.group(2),'state':m.group(3).lower()}
    if not entries: raise ValueError('No VLAN entries parsed')
    return {'vlans':entries}


def routes(body):
    entries={}
    for line in body.splitlines():
        m=re.match(r'^\s*([BCSLORiD\*]+)\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s+(.+)$',line)
        if m:
            rest=m.group(3)
            via=re.search(r'\bvia\s+(\d{1,3}(?:\.\d{1,3}){3})',rest)
            connected=re.search(r'directly connected,\s*(\S+)',rest)
            entries[m.group(2)]={'source':m.group(1),'next_hop':via.group(1) if via else None,'interface':connected.group(1) if connected else None}
    if not entries: raise ValueError('No routing entries parsed')
    return {'routes':entries}


def portsecurity(body):
    entries={}
    for line in body.splitlines():
        m=re.match(r'^\s*(\S+\d+/\d+/\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)',line)
        if m:
            entries[m.group(1)]={'maximum':int(m.group(2)), 'current':int(m.group(3)),
                                 'violations':int(m.group(4)), 'action':m.group(5).lower()}
    if not entries: raise ValueError('No port-security entries parsed')
    return {'ports':entries}


def env(body):
    entries={}
    for line in body.splitlines():
        x=re.match(r'^(.+?)(?:\s+is\s+|\s+Status:\s*)(OK|Failed|Faulty|Not Present|Bad)\b',line,re.I)
        if x: entries[x.group(1).strip().lower()]=x.group(2).upper()
    if not entries: raise ValueError('Environment statuses not found')
    return {'components':entries}


def config(body):
    # Strip ephemeral metadata, comments and pagination. Preserve ordered config lines
    # within each stanza, but compare independent stanzas by their headers.
    stanzas={}; current='global'; stanzas[current]=[]
    for line in body.splitlines():
        stripped=line.strip()
        if not stripped or stripped.startswith('!') or stripped.startswith('Building configuration') or stripped.startswith('Current configuration'):
            continue
        if not line.startswith((' ', '\t')) and stripped != 'end':
            if stripped.startswith('version '): continue  # exact software version is show version
            if stripped in stanzas: raise ValueError(f'Duplicate top-level stanza: {stripped}')
            current=stripped; stanzas[current]=[]
        elif stripped != 'end':
            stanzas.setdefault(current,[]).append(stripped)
    if len(stanzas)<5: raise ValueError('Running-config incomplete or unrecognized')
    return {'stanzas':stanzas}

PARSERS = {
 'show version':version, 'show ip bgp summary':bgp, 'show ip interface brief':ip_brief,
 'show interface status':interface_status, 'show interfaces status':interface_status,
 'show vlan brief':vlan, 'show ip route':routes, 'show port-security':portsecurity,
 'show environment all':env, 'show running-config':config,
}


def parse_file(path):
    text=Path(path).read_text(encoding='utf-8-sig',errors='replace')
    commands=extract(text)
    result={}
    for name, raw in commands.items():
        if ERROR.search(raw):
            result[name]={'status':'COMMAND_ERROR','error':'Device returned command error'}
        elif name not in PARSERS:
            result[name]={'status':'UNSUPPORTED','raw_lines':len(raw.splitlines())}
        else:
            try:
                data=PARSERS[name](raw)
                result[name]={'status':'PARSED','data':data}
            except Exception as exc:
                result[name]={'status':'PARSE_ERROR','error':str(exc)}
    return {'source':str(Path(path).name),'command_count':len(commands),'commands':result}


def flatten(obj,prefix=''):
    if isinstance(obj,dict):
        for k,v in obj.items():
            yield from flatten(v, f'{prefix}.{k}' if prefix else str(k))
    else:
        yield prefix,obj


def diff(pre,post,expected_version=None):
    reports=[]
    a=pre['commands']; b=post['commands']
    for command in dict.fromkeys([*a,*b]):
        left=a.get(command); right=b.get(command)
        item={'command':command,'status':None,'changes':[]}
        if left is None: item['status']='MISSING_PRE'
        elif right is None: item['status']='MISSING_POST'
        elif left['status']!='PARSED' or right['status']!='PARSED':
            item['status']='UNSUPPORTED' if left['status']==right['status']=='UNSUPPORTED' else 'NOT_EVALUATED'
            item['pre_status']=left['status'];item['post_status']=right['status']
        else:
            da=dict(flatten(left['data'])); db=dict(flatten(right['data']))
            for field in sorted(set(da)|set(db)):
                l=da.get(field,'<MISSING>');r=db.get(field,'<MISSING>')
                if l!=r:
                    # Dynamic port-security addresses are useful to track but not config regressions.
                    severity='CHANGE'
                    if command=='show version' and field=='ios_xe_version' and expected_version and r==expected_version:
                        severity='EXPECTED'
                    elif command=='show port-security' and field.endswith('.current'):
                        severity='INFO'
                    item['changes'].append({'field':field,'pre':l,'post':r,'severity':severity})
            item['status']=('CHANGE' if any(x['severity']=='CHANGE' for x in item['changes']) else
                            'EXPECTED' if any(x['severity']=='EXPECTED' for x in item['changes']) else
                            'INFO' if item['changes'] else 'PASS')
            if command=='show version' and expected_version and db.get('ios_xe_version') != expected_version:
                item['status']='ERROR';item['changes'].append({'field':'expected_version','pre':expected_version,'post':db.get('ios_xe_version'),'severity':'ERROR'})
        reports.append(item)
    return {'pre':pre['source'],'post':post['source'],'expected_version':expected_version,
            'counts':dict(Counter(x['status'] for x in reports)),'results':reports}


def save_report(report, folder):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True)
    (folder/'smart_diff.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    lines=['CISCO SMART PRE / POST DIFF','='*78,f"PRE:  {report['pre']}",f"POST: {report['post']}",
           f"EXPECTED IOS-XE: {report['expected_version'] or 'Not specified'}",'-'*78]
    for i in report['results']:
        lines.append(f"[{i['status']:<14}] {i['command']}")
        for change in i.get('changes',[]):
            lines.append(f"  {change['severity']:8} {change['field']}: {change['pre']} -> {change['post']}")
        if i['status']=='NOT_EVALUATED':
            lines.append(f"  PRE={i.get('pre_status')} POST={i.get('post_status')}")
    lines+=['-'*78,'SUMMARY: '+', '.join(f'{k}={v}' for k,v in sorted(report['counts'].items()))]
    (folder/'smart_diff.diff').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    with (folder/'summary.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.writer(f);w.writerow(['Command','Status','Changes'])
        for row in report['results']:w.writerow([row['command'],row['status'],len(row['changes'])])
