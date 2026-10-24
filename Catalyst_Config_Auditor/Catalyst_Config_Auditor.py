#!/usr/bin/env python3
"""Catalyst Config Auditor v1.2.2 — standalone read-only collector, Excel, YAML and Jinja2 renderer.

Dependencies: pip install netmiko pyyaml jinja2
Excel output is implemented with Python's standard-library ZIP/XML writer (no Excel package).
Python 3.10+. Never sends configuration commands. Treat backups as sensitive.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
import ipaddress
import re
import sys
import traceback
from xml.sax.saxutils import escape as xml_escape
from zipfile import ZipFile, ZIP_DEFLATED
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError

VERSION = '1.2.2'
DEFAULT_COMMANDS = ['show version', 'show inventory', 'show switch', 'show interfaces status',
                    'show ip interface brief', 'show ip bgp summary']
DEFAULT_SELECTION = {
 'extract': {
  'hostname': True,
  'banner': {'serial_number': True, 'location': True, 'city': False},
  'vlans': {'enabled': True, 'ids': []},
  'svis': {'enabled': True, 'include_all': True, 'fields': ['name','description','shutdown','ip_addresses']},
  'loopbacks': {'enabled': True, 'include_all': True},
  'routed_interfaces': {'enabled': True, 'include_all': True},
  'bgp': {'enabled': True, 'fields': ['asn','router_id','neighbors'], 'include_passwords': True},
  'interfaces': {'enabled': True, 'mode': 'access', 'fields': ['name','access_vlan','voice_vlan','description'],
                 'compact': False},
  'ntp': {'enabled': False}, 'tacacs': {'enabled': False}, 'ospf': {'enabled': False}
 }
}
EXAMPLES = '''EXAMPLES:
  python Catalyst_Config_Auditor.py -ho SW01 -AIO
  python Catalyst_Config_Auditor.py -hf hosts.txt -AIO -o Results -w 20
  python Catalyst_Config_Auditor.py -ho SW01 --backup
  python Catalyst_Config_Auditor.py -ho SW01 --excel --cmd-file cmd.txt
  python Catalyst_Config_Auditor.py -ho SW01 -AIO --cmd-file cmd.txt
  python Catalyst_Config_Auditor.py -hf hosts.txt --excel --yaml -w 20
  python Catalyst_Config_Auditor.py -hf hosts.txt --backup --excel --yaml -o AuditResults
  python Catalyst_Config_Auditor.py -ho SW01 --yaml --selection variables_selection.yaml
  python Catalyst_Config_Auditor.py --from-config SW01_running.cfg --yaml --model C9300-24P
  python Catalyst_Config_Auditor.py --create_config --template 9k-template.j2 --variables output/SW01/Variables/SW01.yaml
  python Catalyst_Config_Auditor.py --create_config   (prompts for missing paths)
  python Catalyst_Config_Auditor.py --help

NOTES:
  -AIO / --all-in-one performs --backup + --yaml + --excel in one collection.
  -AIO does not generate configs: --create_config remains offline and separate.
  --excel creates one Excel workbook per device; sheets: Summary + one per command.
  --yaml requires a running-config, obtained automatically via SSH or --from-config.
  --create_config only reads local files and does NOT connect to a switch.
  Prompts for command file on --excel/-AIO unless --cmd-file is specified.
  YAML creates SW01.yaml and interface.yaml; sample_9k.j2 is a starter, not full recovery config.
  BGP passwords may be sensitive; selection include_passwords must be explicitly approved.
  Outputs per device use Backups/ and Variables/ only.
  Neither SSH collection nor rendering changes device configuration.
  Passwords supplied with -p can be visible to other local processes.
'''

def cli(argv=None):
    p=argparse.ArgumentParser(description=f'Catalyst Config Auditor v{VERSION} | Excel, selective YAML and Jinja2',
                              formatter_class=argparse.RawDescriptionHelpFormatter,epilog=EXAMPLES)
    targets=p.add_mutually_exclusive_group()
    targets.add_argument('-ho','--host',help='Single hostname or management IP')
    targets.add_argument('-hf','--host-file','--hosts-file',dest='host_file',help='File with one hostname/IP per line')
    targets.add_argument('--from-config',help='Read an existing local running-config instead of connecting over SSH')
    p.add_argument('-u','--username',help='SSH username (prompt when missing)')
    p.add_argument('-p','--password',help='SSH password (interactive prompt recommended)')
    p.add_argument('-o','--output',default='output',help='Root output folder (default: output)')
    p.add_argument('-AIO','--all-in-one',dest='aio',action='store_true',help='All-in-one: backup + selected YAML + Excel in one run')
    p.add_argument('--backup',action='store_true',help='Save running-config and collected command output')
    p.add_argument('--excel',action='store_true',help='One XLSX workbook per device, Summary and command sheets')
    p.add_argument('--yaml',action='store_true',help='Extract only selected YAML variables')
    p.add_argument('--create_config',action='store_true',help='Render local Jinja2 + YAML into a Cisco config (offline)')
    p.add_argument('--cmd-file',help='Command list for --excel; asks interactively when omitted (default cmd.txt)')
    p.add_argument('--selection',default='variables_selection.yaml',help='YAML field selection file')
    p.add_argument('--template',help='Jinja2 template for --create_config')
    p.add_argument('--variables',help='YAML variable file for --create_config')
    p.add_argument('--model',help='Model hint for offline running-config processing')
    p.add_argument('-w','--workers',type=int,default=20,help='Concurrent SSH sessions (default: 20)')
    p.add_argument('--overwrite',action='store_true',help='Allow overwriting existing output files')
    p.add_argument('--debug',action='store_true',help='Display detailed exceptions')
    p.add_argument('--version',action='version',version=f'%(prog)s v{VERSION}')
    args=p.parse_args(argv)
    if args.workers < 1: p.error('--workers must be >= 1')
    if args.aio:
        args.backup = True
        args.excel = True
        args.yaml = True
    if not (args.backup or args.excel or args.yaml or args.create_config): p.error('Choose --backup, --excel, --yaml or --create_config')
    if args.create_config and (args.backup or args.excel or args.yaml or args.host or args.host_file or args.from_config):
        p.error('--create_config is an offline standalone mode')
    if not args.create_config and not (args.host or args.host_file or args.from_config): p.error('Provide -ho, -hf or --from-config')
    return args

def read_commands(path):
    file=Path(path)
    if not file.exists():
        print(f'[!] {file} not found; using built-in default command list')
        return DEFAULT_COMMANDS[:]
    commands=[]
    for raw in file.read_text(encoding='utf-8-sig').splitlines():
        cmd=raw.strip()
        if cmd and not cmd.startswith('#') and cmd not in commands: commands.append(cmd)
    if not commands: raise ValueError('Command list is empty')
    if any(not re.match(r'^(?:show|sh)\s+',c,re.I) for c in commands):
        raise ValueError('cmd.txt supports show commands only (read-only policy)')
    return commands

def read_selection(path):
    if not Path(path).exists():
        print(f'[!] {path} not found; using built-in default YAML field selection')
        return DEFAULT_SELECTION['extract']
    data=yaml.safe_load(Path(path).read_text(encoding='utf-8-sig'))
    if not isinstance(data,dict) or not isinstance(data.get('extract'),dict):
        raise ValueError('Selection YAML must contain an extract: mapping')
    return data['extract']

def ensure_write(path, overwrite=False):
    path=Path(path)
    if path.exists() and not overwrite: raise FileExistsError(f'Output exists: {path} (use --overwrite)')
    path.parent.mkdir(parents=True,exist_ok=True)
    return path

def safe_filename(value):
    return (re.sub(r'[^A-Za-z0-9_.-]+','_',str(value)).strip('._') or 'UNKNOWN')[:100]

def error_output(value):
    return bool(re.search(r'(?mi)^\s*%\s*(?:Invalid|Ambiguous|Incomplete|Error|Unrecognized)',value))

def collect(host, username, password, cmds, need_running):
    from netmiko import ConnectHandler
    conn=ConnectHandler(device_type='cisco_ios',host=host,username=username,password=password,
                        conn_timeout=25,auth_timeout=25,read_timeout_override=120)
    out={}; errors={}
    try:
        all_cmds=list(dict.fromkeys(['show version','show inventory']+(['show running-config'] if need_running else [])+cmds))
        for command in all_cmds:
            try:
                response=conn.send_command(command,read_timeout=140 if command=='show running-config' else 70)
                if error_output(response): raise RuntimeError(response.strip()[:250])
                out[command]=response
            except Exception as exc:
                errors[command]=f'{type(exc).__name__}: {exc}'
                out[command]=''
        if need_running and not out.get('show running-config','').strip():
            raise RuntimeError('Unable to retrieve show running-config: '+errors.get('show running-config','empty output'))
        return out,errors
    finally:
        conn.disconnect()

def device_facts(target, commands, model_hint=None):
    running=commands.get('show running-config','')
    version=commands.get('show version','')
    inventory=commands.get('show inventory','')
    hostname=re.search(r'(?m)^hostname\s+(\S+)',running)
    if not hostname:
        hostname=re.search(r'(?m)^\s*(\S+)\s+uptime is',version)
    model=model_hint or next(iter(re.findall(r'PID:\s*(C(?:9300|9407|9410|9500)[-\w]*)',inventory,re.I)),None)
    if not model:
        model=next(iter(re.findall(r'\bC(?:9300|9407|9410|9500)[-\w]*\b',version,re.I)),'unknown')
    serials=list(dict.fromkeys(re.findall(r'SN:\s*([^,\s]+)',inventory)))
    if not serials:
        serials=re.findall(r'(?mi)^\s*Processor board ID\s+(\S+)',version)
    uptime=re.search(r'(?mi)^.*?uptime is (.+)$',version)
    image=re.search(r'System image file is\s+"?([^"\n]+)',version,re.I)
    if not image: image=re.search(r'(?m)^\s*System image file is\s+(\S+)',version)
    return {'mgmt_ip':target,'hostname':hostname.group(1) if hostname else target,
            'serial':', '.join(serials),'uptime':uptime.group(1) if uptime else '',
            'model':model,'image':image.group(1).strip('"') if image else '',
            'collected_at_utc':datetime.now(timezone.utc).isoformat(timespec='seconds')}

def blocks(config):
    """Read IOS-style indentation blocks while preserving interface and router hierarchy."""
    result=[]; parent=None
    for line in config.splitlines():
        if line.startswith('!') or not line.strip():
            parent=None;continue
        if line[0].isspace() and parent is not None: parent['children'].append(line.strip())
        elif not line[0].isspace():
            parent={'header':line.strip(),'children':[]};result.append(parent)
    return result

def parse_ip_lines(lines):
    values=[]
    for line in lines:
        match=re.fullmatch(r'ip address\s+(\S+)\s+(\S+)(\s+secondary)?',line)
        if match:
            try: ipaddress.IPv4Address(match.group(1));ipaddress.IPv4Address(match.group(2))
            except ValueError:continue
            values.append({'ip':match.group(1),'mask':match.group(2),'secondary':bool(match.group(3))})
    return values

def field_filter(obj,fields):
    if not isinstance(fields,list) or not fields:return obj
    return {k:v for k,v in obj.items() if k in fields}

def config_extract(config, facts, selection):
    """Extract selected values only. Missing fields become null or absent, never guessed."""
    parsed=blocks(config)
    out={}
    host=next((b['header'].split(maxsplit=1)[1] for b in parsed if b['header'].startswith('hostname ')),None)
    if selection.get('hostname',False):out['hostname']=host or facts['hostname']
    banner=selection.get('banner',{})
    if isinstance(banner,dict):
        if banner.get('serial_number'):out['Serial_Number']=facts.get('serial') or None
        if banner.get('location'):
            loc=next((b['header'][len('snmp-server location '):] for b in parsed if b['header'].startswith('snmp-server location ')),None)
            out['Location']=loc
        if banner.get('city'):out['City']=None  # never derive city from device name
    vlan_opt=selection.get('vlans',{})
    if isinstance(vlan_opt,dict) and vlan_opt.get('enabled'):
        whitelist=set(int(x) for x in vlan_opt.get('ids',[]) or [])
        vlans=[]
        for b in parsed:
            m=re.fullmatch(r'vlan\s+(\d+)',b['header'])
            if m and (not whitelist or int(m.group(1)) in whitelist):
                name=next((c[len('name '):] for c in b['children'] if c.startswith('name ')),None)
                vlans.append({'id':int(m.group(1)),'name':name})
        out['vlans']=vlans
    iface_data=[]
    for b in parsed:
        m=re.fullmatch(r'interface\s+(\S+)',b['header'])
        if not m:continue
        name=m.group(1);ch=b['children']
        description=next((c[12:] for c in ch if c.startswith('description ')),None)
        data=next((int(x.split()[-1]) for x in ch if re.fullmatch(r'switchport access vlan\s+\d+',x)),None)
        voice=next((int(x.split()[-1]) for x in ch if re.fullmatch(r'switchport voice vlan\s+\d+',x)),None)
        mode=next((x.split()[-1] for x in ch if x.startswith('switchport mode ')),None)
        it={'name':name,'description':description,'shutdown':True if 'shutdown' in ch else False if 'no shutdown' in ch else None,
            'ip_addresses':parse_ip_lines(ch),'access_vlan':data,'voice_vlan':voice,'mode':mode}
        iface_data.append(it)
    def enabled(key):
        item=selection.get(key,{})
        return isinstance(item,dict) and item.get('enabled',False)
    if enabled('svis'):
        cfg=selection['svis']; data=[]
        for it in iface_data:
            if re.fullmatch(r'Vlan\d+',it['name'],re.I):
                if cfg.get('include_all',True) or it['ip_addresses']:
                    data.append(field_filter(it,cfg.get('fields',[])))
        out['svis']=data
    if enabled('loopbacks'):
        out['loopback_interfaces']=[{'name':i['name'],'ip_addresses':i['ip_addresses']} for i in iface_data if re.fullmatch(r'Loopback\d+',i['name'],re.I)]
    if enabled('routed_interfaces'):
        out['routed_interfaces']=[{'name':i['name'],'ip_addresses':i['ip_addresses']} for i in iface_data if i['ip_addresses'] and not re.fullmatch(r'(?:Vlan|Loopback)\d+',i['name'],re.I)]
    if enabled('interfaces'):
        cfg=selection['interfaces']; mode=cfg.get('mode','access')
        candidates=[i for i in iface_data if not re.match(r'(?i)^(?:Vlan|Loopback|Port-channel|Tunnel)',i['name'])]
        if mode=='access':
            candidates=[i for i in candidates if i['mode']=='access' or (i['mode'] is None and (i['access_vlan'] is not None or i['voice_vlan'] is not None))]
        elif mode!='all':raise ValueError("interfaces.mode must be 'access' or 'all'")
        fields=cfg.get('fields',['name','access_vlan','voice_vlan','description'])
        candidates=[field_filter(i,fields) for i in candidates]
        if cfg.get('compact',False):
            # Only known explicitly configured values are eligible for a common default.
            defaults={}
            for key in ('access_vlan','voice_vlan'):
                freq=Counter(x.get(key) for x in candidates if x.get(key) is not None)
                defaults[key]=freq.most_common(1)[0][0] if freq else None
            out['interface_defaults']=defaults
            out['interfaces']=[{'name':i['name'],**{k:v for k,v in i.items() if k!='name' and (k not in defaults or v!=defaults[k])}} for i in candidates]
            out['interface_defaults_note']='Missing access_vlan/voice_vlan is not equivalent to an explicit default; review before deployment.'
        else:out['interfaces']=candidates
    if enabled('bgp'):
        cfg=selection['bgp'];bgp_blocks=[b for b in parsed if re.match(r'^router bgp\s+\d+',b['header'])]
        if not bgp_blocks: bgp={'enabled':False,'asn':None,'router_id':None,'neighbors':[]}
        else:
            b=bgp_blocks[0];asn=int(b['header'].split()[2]);rid=None;neighbors={}
            for c in b['children']:
                m=re.fullmatch(r'bgp router-id\s+(\S+)',c)
                if m:rid=m.group(1)
                m=re.match(r'^neighbor\s+(\S+)\s+(.+)$',c)
                if m:
                    addr=m.group(1);entry=neighbors.setdefault(addr,{'address':addr,'remote_as':None,'description':None,'password_type':None,'password':None,'timers':None})
                    attr=m.group(2)
                    remote=re.fullmatch(r'remote-as\s+(\S+)',attr)
                    if remote:entry['remote_as']=remote.group(1)
                    desc=re.fullmatch(r'description\s+(.+)',attr)
                    if desc:entry['description']=desc.group(1)
                    timers=re.fullmatch(r'timers\s+(\d+)\s+(\d+)',attr)
                    if timers:entry['timers']={'keepalive':int(timers.group(1)),'holdtime':int(timers.group(2))}
                    passwd=re.fullmatch(r'password(?:\s+(\d+))?\s+(.+)',attr)
                    if passwd:
                        entry['password_type']=passwd.group(1)
                        if cfg.get('include_passwords',False):
                            entry['password']=passwd.group(2)
                            # WARNING: May be encrypted type 7 or plaintext (type 0).
                    # Some IOS-XE releases use neighbor ... password from AF / inherited peers.

            if not cfg.get('include_passwords',False):
                for entry in neighbors.values(): entry.pop('password',None)
            bgp={'enabled':True,'asn':asn,'router_id':rid,'neighbors':list(neighbors.values())}
        fields=cfg.get('fields',[])
        out['bgp']={'enabled':bgp['enabled'],**{k:v for k,v in bgp.items() if k!='enabled' and (not fields or k in fields)}}
    if enabled('ntp'):
        out['ntp_servers']=[b['header'] for b in parsed if b['header'].startswith('ntp server ')]
    if enabled('tacacs'):
        out['tacacs_servers']=[{'name':b['header'].split(maxsplit=2)[-1], 'addresses': [c for c in b['children'] if c.startswith('address ipv4 ')]} for b in parsed if b['header'].startswith('tacacs server ')]
    if enabled('ospf'):
        out['ospf']=[{'process':b['header'],'router_id':next((c.split()[-1] for c in b['children'] if c.startswith('router-id ')),None)} for b in parsed if b['header'].startswith('router ospf ')]
    return out

# Self-contained minimal XLSX writer: OOXML with styles, frozen headers and autofilter.
def excel_col(index):
    result=''
    while index:
        index,rem=divmod(index-1,26);result=chr(65+rem)+result
    return result

def excel_sheet_name(text,used):
    base=re.sub(r"[\\/*?:\[\]]","_",text).strip(" '") or "Sheet"
    base=base[:31]
    name=base;index=2
    while name.casefold() in used:
        suffix=f'_{index}';name=base[:31-len(suffix)]+suffix;index+=1
    used.add(name.casefold());return name

def xml_text(text):
    # strip XML 1.0 prohibited chars; Excel strings should never be treated as formulae
    text=''.join(x for x in str(text) if ord(x) in (9,10,13) or ord(x)>=32)
    return xml_escape(text,{'"':'&quot;',"'":'&apos;'})

def workbook_xlsx(path, sheets, overwrite=False):
    """Create a compliant basic .xlsx file; each sheet receives header row + rows."""
    path=ensure_write(path,overwrite);used=set();normalized=[]
    for title,headers,rows in sheets:
        name=excel_sheet_name(title,used)
        normalized.append((name,[str(x) for x in headers],rows))
    with ZipFile(path,'w',ZIP_DEFLATED) as z:
        types='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'''
        types+=''.join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(1,len(normalized)+1))+'</Types>'
        z.writestr('[Content_Types].xml',types)
        z.writestr('_rels/.rels','''<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>''')
        wb='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'''
        wb+=''.join(f'<sheet name="{xml_text(n)}" sheetId="{i}" r:id="rId{i}"/>' for i,(n,_,_) in enumerate(normalized,1))+'</sheets></workbook>'
        z.writestr('xl/workbook.xml',wb)
        rel='''<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'''
        rel+=''.join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1,len(normalized)+1))
        rel+='<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'
        z.writestr('xl/_rels/workbook.xml.rels',rel)
        z.writestr('xl/styles.xml','''<?xml version="1.0" encoding="UTF-8"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Aptos"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Aptos"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF16324F"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf xfId="0" fontId="0" fillId="0" borderId="0"/><xf xfId="0" fontId="1" fillId="2" borderId="0" applyFont="1" applyFill="1"/></cellXfs></styleSheet>''')
        for si,(name,headers,rows) in enumerate(normalized,1):
            allrows=[headers]+[[str(c) if c is not None else '' for c in r] for r in rows]
            lines=['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">']
            lines.append('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>')
            lines.append('<cols>'+''.join(f'<col min="{i}" max="{i}" width="{min(45,max(16,len(x)+5))}" customWidth="1"/>' for i,x in enumerate(headers,1))+'</cols>')
            lines.append('<sheetData>')
            for ri,row in enumerate(allrows,1):
                lines.append(f'<row r="{ri}">')
                for ci,value in enumerate(row,1):
                    # Force all values to text: safe for hostname values and raw CLI output.
                    addr=f'{excel_col(ci)}{ri}'
                    lines.append(f'<c r="{addr}" t="inlineStr"'+(' s="1"' if ri==1 else '')+f'><is><t xml:space="preserve">{xml_text(value)}</t></is></c>')
                lines.append('</row>')
            lines.append('</sheetData>')
            end=f'{excel_col(max(len(headers),1))}{max(len(allrows),1)}'
            lines.append(f'<autoFilter ref="A1:{end}"/></worksheet>')
            z.writestr(f'xl/worksheets/sheet{si}.xml',''.join(lines))
    return path

def command_table(command,output):
    """Known commands are converted to tables; otherwise store text without losing content."""
    c=command.lower().strip()
    if c in ('show ip interface brief','sh ip interface brief'):
        entries=[]
        for line in output.splitlines():
            parts=re.split(r'\s{2,}',line.strip())
            if len(parts)>=5 and parts[0].lower()!='interface': entries.append(parts[:5])
        if entries:return ['Interface','IP Address','OK?','Method','Status / Protocol'],entries
    if c in ('show interfaces status','show interface status','sh interfaces status'):
        # Parse from the RIGHT so descriptions containing spaces (including very long
        # descriptions) do not merge with Status. Supported IOS-XE statuses vary.
        entries=[]
        status_pat=r'(?:notconnect|connected|disabled|err-disabled|inactive|monitoring|suspended|sfpAbsent|xcvrAbsen|notpresent|faulty|up|down|unassigned|channelDown|onboard|secure-shutdown)'
        for raw in output.splitlines():
            line=raw.rstrip()
            if not line.strip() or re.match(r'^\s*Port\s+Name\s+Status\s+Vlan',line,re.I): continue
            # Port, arbitrary-length Name, Status, VLAN, Duplex, Speed, Type
            m=re.match(r'^\s*(\S+)\s+(.*?)\s+('+status_pat+r')\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?\s*$',line,re.I)
            if m:
                port,name,status,vlan,duplex,speed,ptype=m.groups()
                entries.append([port,name.strip(),status,vlan,duplex,speed,(ptype or '').strip()])
            else:
                # A short or unknown-status line is kept intact rather than misaligned.
                entries.append([line.strip(),'','','','','','UNPARSED - review raw output'])
        if entries:return ['Port','Name','Status','Vlan','Duplex','Speed','Type'],entries
    if c=='show inventory':
        rows=[];name=None;descr=None
        for line in output.splitlines():
            m=re.search(r'NAME:\s*"([^"]+)"\s*,\s*DESCR:\s*"([^"]*)"',line)
            if m:name,descr=m.groups()
            m=re.search(r'PID:\s*(\S+)\s*,\s*VID:\s*([^,]*)\s*,\s*SN:\s*(\S+)',line)
            if m:rows.append([name or '',descr or '',*m.groups()]);name=descr=None
        if rows:return ['Name','Description','PID','VID','Serial'],rows
    if c=='show version':
        rows=[]
        for line in output.splitlines():
            if any(key in line.lower() for key in ('uptime is','ios xe software','system image file','processor board id')):
                rows.append([line.strip()])
        if rows:return ['Version fact'],rows
    # Preserve every line, including blanks (one cell per source line).
    return ['Raw output'],[[line] for line in output.splitlines()] or [['(empty output)']]

def sample_jinja(data):
    """Starter template based solely on the extracted and selected fields.

    This is NOT a complete write-erase replacement. Review missing global lines,
    interface roles, feature dependencies, and any credential handling.
    """
    parts=['! EXAMPLE ONLY — REVIEW BEFORE ANY NETWORK CHANGE',
           'hostname {{ hostname }}', '!']
    if 'vlans' in data:
        parts+=['{% for vlan in vlans %}', 'vlan {{ vlan.id }}',
                '{% if vlan.name %} name {{ vlan.name }}{% endif %}',
                '!','{% endfor %}']
    if 'svis' in data:
        parts+=['{% for svi in svis %}', 'interface {{ svi.name }}',
                '{% if svi.description %} description {{ svi.description }}{% endif %}',
                '{% for ip in svi.ip_addresses %} ip address {{ ip.ip }} {{ ip.mask }}{% if ip.secondary %} secondary{% endif %}',
                '{% endfor %}', '!', '{% endfor %}']
    if 'loopback_interfaces' in data:
        parts+=['{% for lo in loopback_interfaces %}', 'interface {{ lo.name }}',
                '{% for ip in lo.ip_addresses %} ip address {{ ip.ip }} {{ ip.mask }}{% if ip.secondary %} secondary{% endif %}',
                '{% endfor %}', '!', '{% endfor %}']
    parts+=['! Interface values read from separate interface.yaml',
            "{% for intf in interfaces %}", 'interface {{ intf.name }}',
            '{% if intf.description %} description {{ intf.description }}{% endif %}',
            ' switchport mode access',
            '{% if intf.access_vlan is not none %} switchport access vlan {{ intf.access_vlan }}{% endif %}',
            '{% if intf.voice_vlan is not none %} switchport voice vlan {{ intf.voice_vlan }}{% endif %}',
            '!', '{% endfor %}']
    if data.get('bgp',{}).get('enabled'):
        parts+=['router bgp {{ bgp.asn }}',
                '{% if bgp.router_id %} bgp router-id {{ bgp.router_id }}{% endif %}',
                '{% for peer in bgp.neighbors %}',
                '{% if peer.remote_as %} neighbor {{ peer.address }} remote-as {{ peer.remote_as }}{% endif %}',
                '{% if peer.description %} neighbor {{ peer.address }} description {{ peer.description }}{% endif %}',
                '{% if peer.get("password") %} neighbor {{ peer.address }} password{% if peer.password_type %} {{ peer.password_type }}{% endif %} {{ peer.password }}{% endif %}',
                '{% endfor %}', '!']
    return '\n'.join(parts)+'\n'

def render_config(args):
    tp=args.template or input('Jinja2 Template: ').strip()
    vp=args.variables or input('Variables YAML: ').strip()
    if not tp or not vp:raise ValueError('Both template and variables are required')
    tpath,vpath=Path(tp),Path(vp)
    data=yaml.safe_load(vpath.read_text(encoding='utf-8-sig'))
    if not isinstance(data,dict):raise ValueError('Variables YAML must be a mapping')
    ipath=vpath.parent/'interface.yaml'
    if ipath.exists():
        interface_data=yaml.safe_load(ipath.read_text(encoding='utf-8-sig')) or {}
        if not isinstance(interface_data,dict) or not isinstance(interface_data.get('interfaces'),list):
            raise ValueError(f'Invalid interface.yaml: {ipath}')
        data['interfaces']=interface_data['interfaces']

    env=Environment(loader=FileSystemLoader(str(tpath.parent or Path('.'))),undefined=StrictUndefined,autoescape=False,keep_trailing_newline=True)
    generated=env.get_template(tpath.name).render(**data)
    hostname=safe_filename(data.get('hostname') or vpath.stem)
    dest=Path(args.output)/hostname/'Variables'/f'{hostname}_generated.cfg'
    ensure_write(dest,args.overwrite).write_text(generated,encoding='utf-8')
    print(f'[PASS] Generated: {dest}')
    return 0

def device_process(target, outputs, errors, args, commands, selection):
    facts=device_facts(target,outputs,args.model)
    name=safe_filename(facts['hostname'])
    root=Path(args.output)/name
    backups=root/'Backups';variables=root/'Variables'
    paths=[]
    if args.backup:
        if outputs.get('show running-config'):
            p=ensure_write(backups/'Running_Config.txt',args.overwrite);p.write_text(outputs['show running-config'],encoding='utf-8');paths.append(p)
        # Combined readable output; do not create a separate folder for each command.
        combined=''.join(f'\n{"="*68}\n{cmd}\n{"="*68}\n{value}\n' for cmd,value in outputs.items() if cmd!='show running-config')
        p=ensure_write(backups/'Commands_Output.txt',args.overwrite);p.write_text(combined,encoding='utf-8');paths.append(p)
    if args.yaml:
        running=outputs.get('show running-config','')
        if not running.strip():raise ValueError('YAML extraction requires show running-config')
        data=config_extract(running,facts,selection)
        p=ensure_write(variables/f'{name}.yaml',args.overwrite)
        p.write_text(yaml.safe_dump(data,sort_keys=False,allow_unicode=True,width=120),encoding='utf-8');paths.append(p)
        interface_data={'interfaces':data.pop('interfaces',[])}
        # Re-write main YAML without the access-port list; interface.yaml owns it.
        p.write_text(yaml.safe_dump(data,sort_keys=False,allow_unicode=True,width=120),encoding='utf-8')
        ifile=ensure_write(variables/'interface.yaml',args.overwrite)
        ifile.write_text(yaml.safe_dump(interface_data,sort_keys=False,allow_unicode=True,width=120),encoding='utf-8');paths.append(ifile)
        data['interfaces']=interface_data['interfaces']
        jpath=ensure_write(variables/'sample_9k.j2',args.overwrite)
        jpath.write_text(sample_jinja(data),encoding='utf-8');paths.append(jpath)

    if args.excel:
        available=[c for c in commands]
        success=sum(bool(outputs.get(c,'')) and c not in errors for c in available)
        failure=len(available)-success
        summary=dict(facts,success_count=success,fail_count=failure,failed_commands='; '.join(c for c in available if c in errors))
        sheets=[('Summary',list(summary.keys()),[list(summary.values())])]
        for command in commands:
            if command in errors:sheets.append((command,['Error'],[[errors[command]]]))
            else:
                headers,rows=command_table(command,outputs.get(command,''))
                sheets.append((command,headers,rows))
        p=workbook_xlsx(backups/f'{name}_Commands.xlsx',sheets,args.overwrite);paths.append(p)
    print(f'[{name}] PASS | {facts["model"]} | '+', '.join(str(p.relative_to(Path(args.output))) for p in paths))
    for command,error in errors.items():print(f'  [WARN] {command}: {error[:130]}')
    return name

def main(argv=None):
    args=cli(argv)
    print('='*74+'\n CATALYST CONFIG AUDITOR v'+VERSION+'\n'+'='*74)
    try:
        if args.create_config:return render_config(args)
        cmd_path=args.cmd_file
        if args.excel and not cmd_path:
            try: cmd_path=input('Command file [cmd.txt]: ').strip() or 'cmd.txt'
            except EOFError: cmd_path='cmd.txt'
        commands=read_commands(cmd_path) if args.excel else []
        selection=read_selection(args.selection) if args.yaml else {}
        if args.from_config:
            file=Path(args.from_config)
            content=file.read_text(encoding='utf-8-sig',errors='replace')
            target=file.stem
            output={'show running-config':content}
            if args.excel:
                print('[!] Offline mode: no command outputs are available; Excel command sheets will be empty.')
            device_process(target,output,{},args,commands,selection)
            return 0
        targets=([args.host] if args.host else [x.strip() for x in Path(args.host_file).read_text(encoding='utf-8-sig').splitlines() if x.strip() and not x.lstrip().startswith('#')])
        targets=list(dict.fromkeys(targets))
        if not targets:raise ValueError('No devices found')
        username=args.username or input('SSH Username: ').strip()
        password=args.password if args.password is not None else getpass('SSH Password: ')
        if not username:raise ValueError('SSH username cannot be empty')
        print(f'[+] Collecting {len(targets)} devices with {min(args.workers,len(targets))} worker(s)...')
        success=failed=0
        def worker(target):
            outputs,errors=collect(target,username,password,commands,args.backup or args.yaml)
            return device_process(target,outputs,errors,args,commands,selection)
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures={pool.submit(worker,t):t for t in targets}
            for future in as_completed(futures):
                try:future.result();success+=1
                except Exception as exc:
                    failed+=1;print(f'[FAIL] {futures[future]}: {type(exc).__name__}: {exc}')
                    if args.debug:traceback.print_exc()
        print(f'Finished: PASS={success} FAIL={failed}')
        return 1 if failed else 0
    except (OSError,ValueError,TemplateError,yaml.YAMLError) as exc:
        print(f'[ERROR] {type(exc).__name__}: {exc}',file=sys.stderr)
        if args.debug:traceback.print_exc()
        return 2

if __name__=='__main__':sys.exit(main())
