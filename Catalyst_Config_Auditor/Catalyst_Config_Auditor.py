#!/usr/bin/env python3
"""Standalone Catalyst Configuration Auditor v1.0.1 — offline/SSH extraction and roundtrip checks.

Author: peskicorp. Read-only on network equipment.
"""
import argparse
import getpass
import json
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table


from dataclasses import dataclass, field, asdict
from typing import Any
from jinja2 import Environment, StrictUndefined
import csv
import difflib
import html
from collections import Counter
from copy import deepcopy


# ===== models/device_config.py =====
"""Normalized inventory facts and parser result structures."""

@dataclass
class DeviceFacts:
    target: str
    hostname: str = ""
    model: str = "unknown"
    family: str = "unknown"
    ios_version: str = "unknown"
    stack: dict[str, Any] = field(default_factory=lambda: {"enabled": None, "member_count": None, "members": []})
    serials: list[str] = field(default_factory=list)
    discovery_warnings: list[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

# ===== core/connection.py =====
"""Single SSH connection per target. Read-only operations."""

def collect(target, username, password, timeout=25):
    from netmiko import ConnectHandler
    conn=ConnectHandler(device_type='cisco_ios',host=target,username=username,password=password,conn_timeout=timeout,auth_timeout=timeout,read_timeout_override=90)
    try:
        # Netmiko automatically manages terminal length for cisco_ios.
        commands={'running':'show running-config','version':'show version','inventory':'show inventory','switch':'show switch'}
        outputs={}
        warnings=[]
        for key,cmd in commands.items():
            try:
                val=conn.send_command(cmd,read_timeout=120 if key=='running' else 45)
                if val.lstrip().startswith(('% Invalid','% Ambiguous','% Incomplete')):
                    warnings.append(f'{cmd}: not supported')
                    val=''
                outputs[key]=val
            except Exception as ex:
                if key=='running':raise
                outputs[key]=''
                warnings.append(f'{cmd}: {type(ex).__name__}')
        if not outputs['running'].strip():raise RuntimeError('Empty running-config; backup aborted')
        return outputs,warnings
    finally:
        conn.disconnect()

# ===== core/discovery.py =====
"""Parse inventory commands. Never infer ports solely from chassis family."""

def discover(target, running, version="", inventory="", switches=""):
    host = re.search(r"^hostname\s+(\S+)", running, re.M)
    facts = DeviceFacts(target=target, hostname=host.group(1) if host else target)
    pids = re.findall(r'PID:\s*([^,\s]+)', inventory)
    candidates = pids + re.findall(r'\b(C(?:9300|9407|9410|9500)[A-Za-z0-9-]*)\b', version)
    for model in candidates:
        if re.match(r'^C(?:9300|9407|9410|9500)', model, re.I):
            facts.model = model
            break
    for prefix in ('C9300', 'C9407', 'C9410', 'C9500'):
        if facts.model.upper().startswith(prefix):
            facts.family = prefix
            break
    ver = re.search(r'Cisco IOS XE Software, Version\s+([^\s,]+)', version, re.I) or re.search(r'Version\s+(1[567]\.[0-9]+(?:\.[0-9]+)?)', version)
    if ver: facts.ios_version = ver.group(1)
    facts.serials = list(dict.fromkeys(re.findall(r'SN:\s*([^,\s]+)', inventory)))
    members = []
    for line in switches.splitlines():
        # Typical "*1 Active ..." output.  Never claim certainty without evidence.
        m = re.match(r'^\s*\*?\s*(\d+)\s+(Active|Standby|Member|Ready)\b', line, re.I)
        if m: members.append({"number":int(m.group(1)),"role":m.group(2).lower()})
    if members:
        members = list({v['number']:v for v in members}.values())
        facts.stack={"enabled":len(members)>1,"member_count":len(members),"members":members}
    else:
        facts.discovery_warnings.append('Stack membership not verified (show switch unavailable or unrecognized).')
    if facts.family == 'unknown':
        facts.discovery_warnings.append('Unable to positively identify supported model; --model may be required offline.')
    return facts

# ===== core/renderer.py =====
"""Render Jinja templates under strict variable checking."""

def render(template, variables):
    env=Environment(undefined=StrictUndefined,autoescape=False,keep_trailing_newline=True)
    return env.from_string(template).render(**variables)

# ===== core/reporting.py =====
"""Write CSV, HTML, and textual differences without external services."""

def save_diff(current, expected, output):
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    a=current.splitlines();b=expected.splitlines()
    diff='\n'.join(difflib.unified_diff(a,b,fromfile='CURRENT',tofile='EXPECTED',lineterm=''))+'\n'
    (output/'Config_Diff.txt').write_text(diff,encoding='utf-8')
    page=difflib.HtmlDiff(wrapcolumn=100).make_file(a,b,'Current','Expected',context=True,numlines=3)
    (output/'Config_Diff.html').write_text(page,encoding='utf-8')
    return not bool(list(difflib.unified_diff(a,b)))

def summary_report(results,root):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    cols=['target','hostname','model','stack_members','backup','extract','roundtrip','status','message']
    with (root/'Summary.csv').open('w',newline='',encoding='utf-8-sig') as f:
        writer=csv.DictWriter(f,fieldnames=cols,extrasaction='ignore');writer.writeheader();writer.writerows(results)
    rows=''.join('<tr>'+''.join('<td>'+html.escape(str(r.get(c,'')))+'</td>' for c in cols)+'</tr>' for r in results)
    page='<html><head><meta charset="utf-8"><style>body{font-family:Arial;margin:30px}table{border-collapse:collapse;width:100%}td,th{padding:9px;border:1px solid #aaa}th{background:#22374a;color:white}</style></head><body><h1>Catalyst Configuration Auditor</h1><table><tr>'+''.join('<th>'+html.escape(c)+'</th>' for c in cols)+'</tr>'+rows+'</table></body></html>'
    (root/'Summary.html').write_text(page,encoding='utf-8')

# ===== parsers/extractor.py =====
"""Conservative IOS-XE parsing and lossless Jinja2 variable substitution.

The template preserves original lines and their order. Only known non-secret
fields are parameterized. No assertion of corporate configuration compliance.
"""

IP = r'(?:\d{1,3}\.){3}\d{1,3}'
SECRET = re.compile(r'(?i)(password|secret|key-string|private-key|certificate|crypto pki|tacacs-server key|snmp-server community|username\s+\S+\s+(?:secret|password))')

def extract(raw):
    result = {
      'hostname': None, 'ntp_servers': [], 'tacacs_servers': [],
      'vlans': [], 'svis': [], 'interfaces': [],
      'bgp': {'enabled': False, 'asn': None, 'neighbors': []},
      'ospf': {'enabled': False, 'processes': []},
      'aaa': {'enabled':False, 'commands':[]},
      'warnings': [], 'extraction': {'parameterized_lines':0, 'preserved_lines':0},
    }
    lines=raw.splitlines(keepends=True)
    replacements={}
    current=None
    vlan=None
    bgp=None
    ospf=None
    intf=None
    svi=None
    tac=None
    def replace(i, expression, original):
        if SECRET.search(original): return
        replacements[i]=expression
    def item_token(section,index,key):return '{{ '+section+'['+str(index)+'].'+key+' }}'
    for i,line in enumerate(lines):
        text=line.rstrip('\r\n')
        stripped=text.strip()
        if not stripped or stripped=='!':
            if stripped=='!': current=vlan=bgp=ospf=intf=svi=tac=None
            continue
        if not text[0].isspace():
            current=vlan=bgp=ospf=intf=svi=tac=None
            a=re.fullmatch(r'hostname\s+(\S+)',text)
            if a:
                result['hostname']=a.group(1)
                replace(i,'hostname {{ hostname }}',text)
                continue
            a=re.fullmatch(r'vlan\s+(\d+)',text)
            if a:
                vlan={'id':int(a.group(1)),'name':None}
                result['vlans'].append(vlan)
                idx=len(result['vlans'])-1
                replace(i,'vlan '+item_token('vlans',idx,'id'),text)
                current=('vlans',idx)
                continue
            a=re.match(r'interface\s+(\S+)$',text)
            if a:
                name=a.group(1)
                if re.match(r'(?i)^Vlan\d+$',name):
                    svi={'name':name,'description':None,'ip':None,'mask':None,'vrf':None,'shutdown':None}
                    result['svis'].append(svi)
                    current=('svis',len(result['svis'])-1)
                else:
                    number=re.search(r'(?:Ethernet)(\d+)/',name,re.I)
                    intf={'name':name,'member':int(number.group(1)) if number else None,'description':None,'mode':None,'data_vlan':None,'voice_vlan':None,'shutdown':None}
                    result['interfaces'].append(intf)
                    current=('interfaces',len(result['interfaces'])-1)
                replace(i,'interface '+item_token(current[0],current[1],'name'),text)
                continue
            a=re.match(r'router bgp\s+(\d+)\s*$',text)
            if a:
                result['bgp']['enabled']=True;result['bgp']['asn']=int(a.group(1));current=('bgp',0)
                replace(i,'router bgp {{ bgp.asn }}',text)
                continue
            a=re.match(r'router ospf\s+(\d+)(?:\s+vrf\s+(\S+))?$',text)
            if a:
                proc={'process_id':int(a.group(1)),'vrf':a.group(2),'router_id':None}
                result['ospf']['enabled']=True;result['ospf']['processes'].append(proc)
                current=('ospf',len(result['ospf']['processes'])-1)
                replace(i,'router ospf {{ ospf.processes['+str(current[1])+'].process_id }}'+(' vrf '+str(a.group(2)) if a.group(2) else ''),text)
                continue
            a=re.match(r'tacacs server\s+(\S+)',text)
            if a:
                tac={'name':a.group(1),'ip':None}
                result['tacacs_servers'].append(tac)
                current=('tacacs_servers',len(result['tacacs_servers'])-1)
                replace(i,'tacacs server '+item_token('tacacs_servers',current[1],'name'),text)
                continue
            a=re.match(r'ntp server\s+(?:(?:vrf\s+\S+)\s+)?(\S+)(.*)$',text)
            if a:
                result['ntp_servers'].append({'address':a.group(1),'options':a.group(2).strip(),'command':text})
                # Preserve options, including VRF and authentication attributes, verbatim.
                addr=a.group(1); start=text.find(addr)
                replace(i,text[:start]+item_token('ntp_servers',len(result['ntp_servers'])-1,'address')+text[start+len(addr):],text)
                continue
            if text.startswith('aaa '):
                result['aaa']['enabled']=True
                if not SECRET.search(text):result['aaa']['commands'].append(text)
                continue
        if text.startswith((' ','\t')) and current:
            kind,idx=current
            prefix=text[:len(text)-len(text.lstrip())]
            obj=(result[kind][idx] if kind in ('vlans','svis','interfaces','tacacs_servers') else None)
            if kind=='vlans':
                m=re.fullmatch(r'name\s+(.+)',stripped)
                if m:
                    obj['name']=m.group(1);replace(i,prefix+'name '+item_token('vlans',idx,'name'),text)
            elif kind in ('svis','interfaces'):
                m=re.fullmatch(r'description\s+(.+)',stripped)
                if m:
                    obj['description']=m.group(1)
                    replace(i,prefix+'description '+item_token(kind,idx,'description'),text)
                if stripped in ('shutdown','no shutdown'):obj['shutdown']=(stripped=='shutdown')
                if kind=='interfaces':
                    m=re.fullmatch(r'switchport access vlan\s+(\d+)',stripped)
                    if m:
                        obj['data_vlan']=int(m.group(1));replace(i,prefix+'switchport access vlan '+item_token(kind,idx,'data_vlan'),text)
                    m=re.fullmatch(r'switchport voice vlan\s+(\d+)',stripped)
                    if m:
                        obj['voice_vlan']=int(m.group(1));replace(i,prefix+'switchport voice vlan '+item_token(kind,idx,'voice_vlan'),text)
                    m=re.fullmatch(r'switchport mode\s+(\S+)',stripped)
                    if m:obj['mode']=m.group(1)
                else:
                    m=re.fullmatch(r'ip address\s+('+IP+r')\s+('+IP+r')(?:\s+secondary)?',stripped)
                    if m and obj['ip'] is None:
                        obj['ip']=m.group(1);obj['mask']=m.group(2)
                        suffix=' secondary' if stripped.endswith(' secondary') else ''
                        replace(i,prefix+'ip address '+item_token(kind,idx,'ip')+' '+item_token(kind,idx,'mask')+suffix,text)
                    m=re.fullmatch(r'vrf forwarding\s+(\S+)',stripped)
                    if m:obj['vrf']=m.group(1)
            elif kind=='tacacs_servers':
                m=re.fullmatch(r'address ipv4\s+('+IP+r')(.*)',stripped)
                if m:
                    obj['ip']=m.group(1)
                    replace(i,prefix+'address ipv4 '+item_token(kind,idx,'ip')+m.group(2),text)
            elif kind=='bgp':
                m=re.fullmatch(r'neighbor\s+(\S+)\s+remote-as\s+(\S+)',stripped)
                if m:
                    result['bgp']['neighbors'].append({'address':m.group(1),'remote_as':m.group(2)})
                    ni=len(result['bgp']['neighbors'])-1
                    replace(i,prefix+'neighbor {{ bgp.neighbors['+str(ni)+'].address }} remote-as {{ bgp.neighbors['+str(ni)+'].remote_as }}',text)
            elif kind=='ospf':
                m=re.fullmatch(r'router-id\s+('+IP+r')',stripped)
                if m:
                    result['ospf']['processes'][idx]['router_id']=m.group(1)
                    replace(i,prefix+'router-id {{ ospf.processes['+str(idx)+'].router_id }}',text)
    if not result['hostname']:result['warnings'].append('Hostname not found.')
    if result['aaa']['enabled'] and not result['aaa']['commands']:
        result['warnings'].append('AAA commands present but none safe to export.')
    template=''.join((replacements.get(i,line.rstrip('\r\n')) + ('\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else '')) for i,line in enumerate(lines))
    result['extraction']['parameterized_lines']=len(replacements)
    result['extraction']['preserved_lines']=len(lines)-len(replacements)
    result['warnings'].append('Unrecognized and sensitive lines are retained literally in the template; protect output like a running-config.')
    return result,template

__version__='1.0.1'
__author__='peskicorp'
console=Console()

EXAMPLES="""Examples:
  Single device backup:
    python Catalyst_Config_Auditor.py -ho SW01 --backup

  Single device backup + extract:
    python Catalyst_Config_Auditor.py -ho SW01 --backup --extract

  Multi-device backup + extract:
    python Catalyst_Config_Auditor.py -hf inventory/hosts.txt --backup --extract

  Specify user, output and workers:
    python Catalyst_Config_Auditor.py -hf inventory/hosts.txt -u admin -o Audit_Results -w 20 --backup --extract

  Process a previously saved running-config without SSH:
    python Catalyst_Config_Auditor.py --from-config SW01_running.cfg --model C9300-24P --extract

  Render template using edited YAML (offline):
    python Catalyst_Config_Auditor.py --generate --template SW01.j2 --variables SW01.yaml -o Rendered

  Compare local running-config to a rendered template:
    python Catalyst_Config_Auditor.py --audit --from-config SW01_running.cfg --template SW01.j2 --variables SW01.yaml

Notes:
  - --backup is read-only on network devices.
  - --extract generates a candidate template, NOT an approved baseline.
  - Keep backups, YAML and generated Jinja files private: sensitive data may exist.
  - Prefer interactive password prompt; command-line -p may expose credentials.
"""

def cli(argv=None):
    p=argparse.ArgumentParser(description='Cisco Catalyst 9000 Configuration Backup, Jinja2 Extraction & Comparison',formatter_class=argparse.RawDescriptionHelpFormatter,epilog=EXAMPLES)
    targets=p.add_mutually_exclusive_group()
    targets.add_argument('-ho','--host',help='Single switch hostname or management IP')
    targets.add_argument('-hf','--host-file','--hosts-file',dest='host_file',metavar='FILE',help='Text file containing device hostnames or IPs')
    targets.add_argument('--from-config',metavar='FILE',help='Offline running-config input')
    p.add_argument('-u','--username',help='SSH username (prompted when omitted)')
    p.add_argument('-p','--password',help='SSH password (interactive prompt recommended)')
    p.add_argument('-o','--output',default='output',help='Output directory (default: output)')
    p.add_argument('--backup',action='store_true',help='Save original running-config and discovery outputs')
    p.add_argument('--extract',action='store_true',help='Create YAML variables, candidate Jinja2 and roundtrip report')
    p.add_argument('--generate',action='store_true',help='Render existing Jinja2 template and YAML')
    p.add_argument('--audit',action='store_true',help='Compare existing config to rendered template (offline)')
    p.add_argument('--template',help='Jinja2 file for --generate and --audit')
    p.add_argument('--variables',help='YAML variable file for --generate and --audit')
    p.add_argument('--model',help='Override platform model when using --from-config')
    p.add_argument('-w','--workers',type=int,default=20,help='Concurrent SSH workers (default: 20)')
    p.add_argument('--overwrite',action='store_true',help='Allow replacing existing output files')
    p.add_argument('--debug',action='store_true',help='Verbose diagnostics in console and log')
    p.add_argument('--no-color',action='store_true',help='Disable terminal colors')
    p.add_argument('--version',action='version',version=f'%(prog)s v{__version__}')
    a=p.parse_args(argv)
    if a.workers<1 or a.workers>100:p.error('--workers must be between 1 and 100')
    if a.generate or a.audit:
        if not a.template or not a.variables:p.error('--generate/--audit require --template and --variables')
        if a.audit and not a.from_config:p.error('--audit requires --from-config')
        if a.backup or a.extract:p.error('--generate/--audit cannot be combined with --backup/--extract')
    else:
        if not (a.host or a.host_file or a.from_config):p.error('Specify -ho, -hf or --from-config')
        if not (a.backup or a.extract):p.error('Specify --backup or --extract')
    if a.from_config and a.backup:p.error('--backup requires SSH; use --extract with --from-config')
    if a.generate and a.audit:p.error('Choose either --generate or --audit')
    return a

def safe_name(name):
    s=re.sub(r'[^A-Za-z0-9_.-]+','_',name).strip('._')
    return s[:80] or 'device'

def save_text(path,text,overwrite):
    path=Path(path)
    if path.exists() and not overwrite:raise FileExistsError(f'Output exists: {path} (use --overwrite or change -o)')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',encoding='utf-8',newline='') as f:f.write(text)

def load_hosts(path):
    file=Path(path)
    items=[line.strip() for line in file.read_text(encoding='utf-8-sig').splitlines() if line.strip() and not line.lstrip().startswith('#')]
    return list(dict.fromkeys(items))

def process(target,raw,outputs,warnings,args):
    facts=discover(target,raw,outputs.get('version',''),outputs.get('inventory',''),outputs.get('switch',''))
    if args.model:
        facts.model=args.model
        facts.family=next((m for m in ['C9300','C9407','C9410','C9500'] if args.model.upper().startswith(m)),'unknown')
    folder=Path(args.output)/safe_name(facts.hostname)
    status={'target':target,'hostname':facts.hostname,'model':facts.model,'stack_members':facts.stack['member_count'] if facts.stack['member_count'] is not None else 'UNKNOWN','backup':'NO','extract':'NO','roundtrip':'N/A','status':'PASS','message':''}
    if args.backup:
        for key,filename in [('running','Running_Config.txt'),('version','Show_Version.txt'),('inventory','Show_Inventory.txt'),('switch','Show_Switch.txt')]:
            save_text(folder/'Backups'/filename,outputs.get(key,''),args.overwrite)
        status['backup']='PASS'
    if args.extract:
        data,templ=extract(raw)
        data['device']=facts.to_dict()
        variable_file=folder/'Variables'/f'{safe_name(facts.hostname)}.yaml'
        template_file=folder/'Templates'/f'{safe_name(facts.hostname)}.j2'
        save_text(variable_file,yaml.safe_dump(data,sort_keys=False,allow_unicode=True),args.overwrite)
        save_text(template_file,templ,args.overwrite)
        rebuilt=render(templ,data)
        save_text(folder/'Reports'/'Reconstructed_Config.cfg',rebuilt,args.overwrite)
        passed=(rebuilt==raw)
        # Report artifacts are guarded before writing as well.
        if (folder/'Reports'/'Config_Diff.txt').exists() and not args.overwrite:
            raise FileExistsError('Diff output exists; use --overwrite')
        save_diff(raw,rebuilt,folder/'Reports')
        status['extract']='PASS';status['roundtrip']='PASS' if passed else 'DIFFERENT'
        if not passed:status['status']='WARNING'
        details={'device':facts.to_dict(),'line_counts':data['extraction'],'warnings':warnings+facts.discovery_warnings+data['warnings'],'roundtrip_exact':passed}
        save_text(folder/'Reports'/'Extraction_Report.json',json.dumps(details,indent=2),args.overwrite)
    return status

def main(argv=None):
    args=cli(argv)
    if args.no_color:console.no_color=True
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING,format='%(asctime)s %(levelname)s %(message)s')
    console.print(f'\n[bold cyan]CATALYST CONFIG AUDITOR[/bold cyan] v{__version__} — [dim]peskicorp[/dim]')
    root=Path(args.output)
    if args.generate or args.audit:
        values=yaml.safe_load(Path(args.variables).read_text(encoding='utf-8'))
        if not isinstance(values,dict):raise ValueError('Variables YAML must be a mapping')
        expected=render(Path(args.template).read_text(encoding='utf-8'),values)
        if args.generate:
            save_text(root/'Generated_Config.cfg',expected,args.overwrite)
            console.print('[green]Generated Config:[/green]',root/'Generated_Config.cfg')
        else:
            current=Path(args.from_config).read_text(encoding='utf-8')
            for filename in ('Config_Diff.txt','Config_Diff.html'):
                if (root/filename).exists() and not args.overwrite:raise FileExistsError(f'{root/filename} exists')
            same=save_diff(current,expected,root)
            console.print('Comparison:', '[green]MATCH[/green]' if same else '[yellow]DIFFERENT[/yellow]')
            console.print('[yellow]Note: this is a textual comparison, not proof of corporate compliance.[/yellow]')
        return 0
    if args.from_config:
        path=Path(args.from_config)
        if not path.is_file():raise FileNotFoundError(path)
        raw=path.read_text(encoding='utf-8')
        if not raw.strip():raise ValueError('Input configuration is empty')
        results=[process(path.stem,raw,{'running':raw},[],args)]
    else:
        targets=[args.host] if args.host else load_hosts(args.host_file)
        if not targets:raise ValueError('No hosts supplied')
        username=args.username or input('SSH Username: ').strip()
        if not username:raise ValueError('Username cannot be empty')
        password=args.password if args.password is not None else getpass.getpass('SSH Password: ')
        results=[]
        def task(target):
            try:
                outputs,warnings=collect(target,username,password)
                return process(target,outputs['running'],outputs,warnings,args)
            except Exception as ex:
                logging.exception('Device error: %s',target)
                return {'target':target,'hostname':target,'model':'UNKNOWN','stack_members':'UNKNOWN','backup':'ERROR','extract':'ERROR','roundtrip':'N/A','status':'ERROR','message':f'{type(ex).__name__}: {ex}'}
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_map={executor.submit(task,target):target for target in targets}
            for future in as_completed(future_map):
                r=future.result();results.append(r)
                console.print(f"[{ 'green' if r['status']=='PASS' else 'red'}]{r['target']}: {r['status']}[/]",r['message'])
        results.sort(key=lambda r:r['target'])
    # Store summary only after checking protection.
    for name in ('Summary.csv','Summary.html'):
        if (root/name).exists() and not args.overwrite:raise FileExistsError(f'{root/name} exists; use --overwrite')
    summary_report(results,root)
    table=Table(title='Catalyst Audit Summary')
    for name in ('Target','Model','Backup','Extract','Roundtrip','Status'):table.add_column(name)
    for r in results:table.add_row(*(str(r[k]) for k in ('target','model','backup','extract','roundtrip','status')))
    console.print(table)
    console.print(f'Reports: {root.resolve()}')
    return 1 if any(x['status']!='PASS' for x in results) else 0

if __name__=='__main__':
    try:sys.exit(main())
    except (OSError, ValueError, RuntimeError) as ex:
        console.print(f'[red]ERROR:[/red] {ex}')
        sys.exit(2)
