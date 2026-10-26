#!/usr/bin/env python3
"""Catalyst Config Auditor v1.3.0 — standalone read-only collector, Excel, YAML and Jinja2 renderer.

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
import json
import logging
from xml.sax.saxutils import escape as xml_escape
from zipfile import ZipFile, ZIP_DEFLATED
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError

__version__ = '1.3.0'
VERSION = __version__
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
EXAMPLES = """EXAMPLES:
  python Catalyst_Config_Auditor.py -ho SW01 --collect
  python Catalyst_Config_Auditor.py -hf hosts.txt --collect --cmd-file cmd.txt -w 20
  python Catalyst_Config_Auditor.py -ho SW01 --vars
  python Catalyst_Config_Auditor.py -hf hosts.txt --vars
  python Catalyst_Config_Auditor.py --vars --from-config Running_Config.txt
  python Catalyst_Config_Auditor.py -ho SW01 --excel
  python Catalyst_Config_Auditor.py --create
  python Catalyst_Config_Auditor.py --create --template output/SW01/Variables/SW01_main.j2 --variables output/SW01/Variables/SW01.yaml
  python Catalyst_Config_Auditor.py -ho SW01 -AIO
  python Catalyst_Config_Auditor.py -ho SW01 --vars --overwrite

MODES:
  --collect: online SSH collection; saves Running_Config.txt, Commands_Output.txt and XLSX.
  --vars: offline extraction from a saved or external running-config; creates two YAML and two Jinja2 files.
  --excel: offline regeneration of workbook from saved Commands_Output.txt.
  --create: offline Jinja2 render from YAML; never sends changes to a device.
  -AIO: online collect then offline variable extraction.
LOGS:
  Per-device timestamped detail logs in output/Logs_<hostname>/.
  Only a concise progress summary appears on the console.
  Existing outputs are never overwritten without --overwrite.
"""

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
    p.add_argument('-AIO','--all-in-one',dest='aio',action='store_true',help='Online collect + offline YAML/Jinja2 extraction')
    p.add_argument('--collect',action='store_true',help='Online backup, commands and Excel')
    p.add_argument('--vars',action='store_true',help='Offline YAML and dual Jinja2 generation')
    p.add_argument('--create','--create_config',dest='create_config',action='store_true',help='Offline render from Jinja2 + YAML')
    p.add_argument('--interface-template',help='Optional interface Jinja2 file')
    p.add_argument('--interface-vars',help='Optional interface YAML file')
    p.add_argument('--backup',action='store_true',help='Alias for --collect (online)')
    p.add_argument('--excel',action='store_true',help='Regenerate XLSX from local Commands_Output.txt (offline)')
    p.add_argument('--yaml',action='store_true',help='Alias for --vars (offline)')
    
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
    if args.aio: args.collect=True; args.vars=True
    if args.backup: args.collect=True
    if args.yaml: args.vars=True
    if not (args.collect or args.vars or args.excel or args.create_config):
        p.error('Choose --collect, --vars, --excel, --create or -AIO')
    if args.create_config and (args.collect or args.vars or args.excel):
        p.error('--create is a standalone offline mode')
    if not args.create_config and not (args.host or args.host_file or args.from_config):
        p.error('Provide -ho, -hf or --from-config')
    if args.collect and args.from_config:
        p.error('--collect requires a hostname; use --vars --from-config for offline files')
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

def running_config_jinja(config, data, interface_data):
    """Parametrize supported source lines, preserving every other IOS line verbatim.

    Jinja substitutions are applied only when a matching YAML field is available.
    This is an as-is source template, NOT a compliance-approved golden configuration.
    """
    intfs=interface_data.get('interfaces',[])
    interface_indexes={item['name']:idx for idx,item in enumerate(intfs) if item.get('name')}
    section_indexes={}
    for field in ('svis','loopback_interfaces','routed_interfaces'):
        section_indexes[field]={item['name']:idx for idx,item in enumerate(data.get(field,[])) if item.get('name')}
    vlan_indexes={str(item['id']):idx for idx,item in enumerate(data.get('vlans',[]))}
    bgp=data.get('bgp',{})
    neighbors={str(item['address']):idx for idx,item in enumerate(bgp.get('neighbors',[]))}
    lines=[];current_iface=None;current_bgp=False;current_vlan=None;ip_index=0
    for line in config.splitlines(keepends=True):
        core=line.rstrip('\r\n');newline=line[len(core):]
        stripped=core.strip()
        # Block context follows top-level section, not '!' separators.
        if core and not core[0].isspace():
            current_iface=None;current_bgp=False;current_vlan=None;ip_index=0
            im=re.fullmatch(r'interface\s+(\S+)',stripped)
            vm=re.fullmatch(r'vlan\s+(\d+)',stripped)
            if im:current_iface=im.group(1)
            if vm:current_vlan=vm.group(1)
            if re.fullmatch(r'router bgp\s+\d+',stripped):current_bgp=True
        replace=None
        if stripped.startswith('hostname ') and not core[0].isspace() and data.get('hostname') is not None:
            replace='hostname {{ hostname }}'
        elif current_iface and core[0].isspace():
            i=interface_indexes.get(current_iface)
            if i is not None:
                item=intfs[i]
                if stripped.startswith('description ') and item.get('description') is not None:
                    replace=f' description {{{{ interfaces[{i}].description }}}}'
                elif re.fullmatch(r'switchport access vlan\s+\d+',stripped) and item.get('access_vlan') is not None:
                    replace=f' switchport access vlan {{{{ interfaces[{i}].access_vlan }}}}'
                elif re.fullmatch(r'switchport voice vlan\s+\d+',stripped) and item.get('voice_vlan') is not None:
                    replace=f' switchport voice vlan {{{{ interfaces[{i}].voice_vlan }}}}'
            for field in ('svis','loopback_interfaces','routed_interfaces'):
                idx=section_indexes[field].get(current_iface)
                if idx is None:continue
                ips=data[field][idx].get('ip_addresses')
                if ips is None:continue
                if re.fullmatch(r'ip address\s+\S+\s+\S+(?:\s+secondary)?',stripped):
                    if ip_index < len(ips):
                        value=ips[ip_index]
                        if value.get('ip') and value.get('mask'):
                            replace=f' ip address {{{{ {field}[{idx}].ip_addresses[{ip_index}].ip }}}} {{{{ {field}[{idx}].ip_addresses[{ip_index}].mask }}}}'
                            if value.get('secondary'):
                                replace+=' secondary'
                    ip_index+=1
                break
        elif current_vlan is not None and core[0].isspace() and stripped.startswith('name '):
            idx=vlan_indexes.get(current_vlan)
            if idx is not None and data['vlans'][idx].get('name') is not None:
                replace=f' name {{{{ vlans[{idx}].name }}}}'
        elif current_bgp and core[0].isspace():
            if stripped.startswith('bgp router-id ') and bgp.get('router_id'):
                replace=' bgp router-id {{ bgp.router_id }}'
            m=re.match(r'neighbor\s+(\S+)\s+(.+)$',stripped)
            if m:
                idx=neighbors.get(m.group(1))
                if idx is not None:
                    neighbor=bgp['neighbors'][idx];attr=m.group(2)
                    prefix=f' neighbor {{{{ bgp.neighbors[{idx}].address }}}} '
                    if re.fullmatch(r'remote-as\s+\S+',attr) and neighbor.get('remote_as'):
                        replace=prefix+f'remote-as {{{{ bgp.neighbors[{idx}].remote_as }}}}'
                    elif attr.startswith('description ') and neighbor.get('description') is not None:
                        replace=prefix+f'description {{{{ bgp.neighbors[{idx}].description }}}}'
                    elif re.fullmatch(r'password(?:\s+\d+)?\s+.+',attr) and neighbor.get('password') is not None:
                        kind=neighbor.get('password_type')
                        replace=prefix+'password '+(f'{{{{ bgp.neighbors[{idx}].password_type }}}} ' if kind else '')+f'{{{{ bgp.neighbors[{idx}].password }}}}'
                    elif re.fullmatch(r'timers\s+\d+\s+\d+',attr) and neighbor.get('timers'):
                        replace=prefix+f'timers {{{{ bgp.neighbors[{idx}].timers.keepalive }}}} {{{{ bgp.neighbors[{idx}].timers.holdtime }}}}'
        if replace is not None:
            # Keep the original line indentation and newline convention.
            indent=core[:len(core)-len(core.lstrip())]
            lines.append(indent+replace.lstrip()+newline)
        else:
            # Escape accidental Jinja delimiters in unmodified config.
            # IOS templates with literal {{...}} / {%...%} can be left intact
            # only if they do not conflict with Jinja; reject on render mismatch.
            lines.append(line)
    return ''.join(lines)


def render_running_template(template_text, data, interfaces):
    env=Environment(undefined=StrictUndefined,autoescape=False,keep_trailing_newline=True)
    return env.from_string(template_text).render(**dict(data,interfaces=interfaces))

# -------------------- LOGGING / OUTPUT --------------------

def banner(mode):
    print('=' * 78)
    print('                       CATALYST CONFIG AUDITOR')
    print('=' * 78)
    print(f'                    MODE: {mode}\n')


def log_for(root, hostname, mode):
    folder=Path(root)/('Logs_'+safe_filename(hostname))
    folder.mkdir(parents=True,exist_ok=True)
    stamp=datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]
    target=folder/f'{safe_filename(hostname)}_{mode}_{stamp}.log'
    logger=logging.getLogger(f'cca.{hostname}.{mode}.{stamp}')
    logger.setLevel(logging.DEBUG)
    logger.propagate=False
    handler=logging.FileHandler(target,encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-7s | %(message)s'))
    logger.addHandler(handler)
    return logger,target


def close_log(logger):
    for handler in list(logger.handlers):
        handler.close();logger.removeHandler(handler)


def save_text(path,value,overwrite):
    ensure_write(path,overwrite).write_text(value,encoding='utf-8')
    return path


def parse_saved_commands(path):
    raw=Path(path).read_text(encoding='utf-8-sig',errors='replace')
    marker=re.compile(r'\n={68}\n(.*?)\n={68}\n',re.S)
    matches=list(marker.finditer(raw));result={}
    for i,m in enumerate(matches):
        name=m.group(1).strip()
        body=raw[m.end():matches[i+1].start() if i+1<len(matches) else len(raw)]
        result[name]=body.strip('\n')
    return result


def split_template(full,name):
    # Preserve source blocks; access/interface configuration belongs to a separate file.
    # All physical interface stanzas are grouped at their first source occurrence.
    # An IOS running-config may interleave sections, so roundtrip may report DIFFERENT.
    lines=full.splitlines(keepends=True)
    head=[];intfs=[];inside=False;inserted=False
    for line in lines:
        top=bool(line.strip()) and not line[0].isspace()
        if top and re.match(r'^interface\s+(?!Vlan|Loopback|Port-channel|Port-Channel|Null|Tunnel|BDI|MgmtEth)(?:[A-Za-z]+\S*)$',line.strip(),re.I):
            inside=True
            if not inserted:
                head.append("{% include '"+name+"_interfaces.j2' %}\n")
                inserted=True
        elif top and not line.startswith('!'):
            inside=False
        if inside:intfs.append(line)
        else:head.append(line)
    # Handle ! separators without dropping neighboring config sections.
    return ''.join(head),''.join(intfs)


def get_targets(args):
    if args.from_config:return [Path(args.from_config).stem]
    if args.host:return [args.host]
    raw=Path(args.host_file).read_text(encoding='utf-8-sig')
    return list(dict.fromkeys(line.strip() for line in raw.splitlines() if line.strip() and not line.lstrip().startswith('#')))


def offline_source(args,target):
    if args.from_config:return Path(args.from_config)
    preferred=Path(args.output)/safe_filename(target)/'Backups'/'Running_Config.txt'
    if preferred.exists():return preferred
    # hostname in backup might differ from its SSH alias: locate by extracted hostname.
    for p in Path(args.output).glob('*/Backups/Running_Config.txt'):
        if p.parent.parent.name.lower()==str(target).lower():return p
    return preferred


def offline_vars(args,target,selection):
    source=offline_source(args,target)
    if not source.is_file():raise FileNotFoundError(f'Backup not found: {source}')
    running=source.read_text(encoding='utf-8-sig',errors='replace')
    facts=device_facts(target,{'show running-config':running},args.model)
    hostname=safe_filename(facts['hostname'])
    folder=Path(args.output)/hostname/'Variables'
    logger,logpath=log_for(args.output,hostname,'VARS')
    try:
        print('[+] Loading local configuration...')
        print(f'    Hostname           : {hostname}')
        print(f'    Source             : {source}')
        print('\n[+] Loading variable selection...')
        print(f'    File               : {args.selection}')
        print('    Status             : VALID' if Path(args.selection).exists() else '    Status             : DEFAULTS USED')
        print('\n[+] Extracting configuration variables...')
        data=config_extract(running,facts,selection)
        interface_data={'interfaces':data.pop('interfaces',[])}
        for field in ('hostname','vlans','svis','loopback_interfaces','routed_interfaces','bgp'):
            val=data.get(field);logger.info('Extracted %s: %s',field, len(val) if isinstance(val,list) else ('PRESENT' if val else 'NONE'))
        logger.info('Access Interfaces: %d',len(interface_data['interfaces']))
        logger.info('Descriptions: %d',sum(bool(x.get('description')) for x in interface_data['interfaces']))
        logger.info('Data VLANs: %d',sum(x.get('access_vlan') is not None for x in interface_data['interfaces']))
        logger.info('Voice VLANs: %d',sum(x.get('voice_vlan') is not None for x in interface_data['interfaces']))
        mainyaml=folder/f'{hostname}.yaml'
        intyaml=folder/f'{hostname}_interface.yaml'
        mainfile=folder/f'{hostname}_main.j2'
        intfile=folder/f'{hostname}_interfaces.j2'
        allfiles=[mainyaml,intyaml,mainfile,intfile]
        for f in allfiles:ensure_write(f,args.overwrite)
        print('\n[+] Generating YAML files...')
        save_text(mainyaml,yaml.safe_dump(data,sort_keys=False,allow_unicode=True,width=120),args.overwrite)
        save_text(intyaml,yaml.safe_dump(interface_data,sort_keys=False,allow_unicode=True,width=120),args.overwrite)
        print(f'    {mainyaml.name:<22}: CREATED')
        print(f'    {intyaml.name:<22}: CREATED')
        print('\n[+] Generating Jinja2 templates...')
        full=running_config_jinja(running,{**data,'interfaces':interface_data['interfaces']},interface_data)
        mainj,intsj=split_template(full,hostname)
        save_text(mainfile,mainj,args.overwrite);save_text(intfile,intsj,args.overwrite)
        print(f'    {mainfile.name:<22}: CREATED')
        print(f'    {intfile.name:<22}: CREATED')
        env=Environment(loader=FileSystemLoader(str(folder)),undefined=StrictUndefined,autoescape=False,keep_trailing_newline=True)
        rebuilt=env.get_template(mainfile.name).render(**data,**interface_data)
        result='MATCH' if rebuilt==running else 'DIFFERENT'
        logger.info('Template reconstruction: original LOADED, generated RENDERED, roundtrip %s',result)
        logger.info('Template files: %s; %s',mainfile,intfile)
        print('\n[+] Variable extraction completed.')
        print(f'\nFiles created in: {folder.resolve()}')
        return True
    except Exception:
        logger.exception('Variable extraction failed')
        raise
    finally:close_log(logger)


def save_workbook(hostname,outputs,commands,errors,args,folder,logger):
    facts=device_facts(hostname,outputs,args.model)
    success=sum(bool(outputs.get(c,'')) and c not in errors for c in commands)
    summary=dict(facts,success_count=success,fail_count=len(commands)-success)
    sheets=[('Summary',list(summary.keys()),[list(summary.values())])]
    for command in commands:
        if command in errors:sheets.append((command,['Error'],[[errors[command]]]))
        else:
            hdr,rows=command_table(command,outputs.get(command,''))
            sheets.append((command,hdr,rows))
        logger.info('Command %s: %s',command,'FAIL' if command in errors else 'PASS')
    file=folder/f'{safe_filename(hostname)}_Commands.xlsx'
    workbook_xlsx(file,sheets,args.overwrite)
    logger.info('Saved workbook %s',file)
    return file


def online_collect(args,target,commands):
    logger,logpath=log_for(args.output,target,'COLLECT')
    try:
        logger.info('Connecting to %s',target)
        out,errors=collect(target,args._username,args._password,commands,True)
        facts=device_facts(target,out,args.model)
        hostname=safe_filename(facts['hostname'])
        logger.info('Connection SUCCESS | Platform Cisco IOS-XE | Model %s | Device %s',facts['model'],hostname)
        for cmd in out:
            logger.info('Collect %s: %s',cmd,'FAIL' if cmd in errors else 'PASS')
        for cmd,error in errors.items():logger.error('Command %s: %s',cmd,error)
        backup=Path(args.output)/hostname/'Backups'
        if (backup/'Running_Config.txt').exists() and not args.overwrite:
            raise FileExistsError(f'{backup}/Running_Config.txt already exists; use --overwrite')
        save_text(backup/'Running_Config.txt',out['show running-config'],args.overwrite)
        combined=''.join(f'\n{"="*68}\n{cmd}\n{"="*68}\n{value}\n' for cmd,value in out.items() if cmd!='show running-config')
        save_text(backup/'Commands_Output.txt',combined,args.overwrite)
        save_workbook(hostname,out,commands,errors,args,backup,logger)
        return hostname,backup
    except Exception:
        logger.exception('Collect failed for %s',target)
        raise
    finally:close_log(logger)


def offline_excel(args,target):
    folder=Path(args.output)/safe_filename(target)/'Backups'
    path=folder/'Commands_Output.txt'
    if not path.exists():raise FileNotFoundError(f'Missing saved commands: {path}')
    outputs=parse_saved_commands(path)
    commands=[c for c in outputs if c!='show running-config']
    logger,_=log_for(args.output,target,'EXCEL')
    try:return save_workbook(target,outputs,commands,{},args,folder,logger)
    except Exception:logger.exception('Excel generation failed');raise
    finally:close_log(logger)


def create_config(args):
    banner('CONFIG GENERATOR')
    print('[+] Configuration Generator\n')
    tp=args.template or input('Main Template: ').strip()
    vp=args.variables or input('Variables YAML: ').strip()
    if not tp or not vp:raise ValueError('Template and variables are required')
    tpath,vpath=Path(tp),Path(vp)
    data=yaml.safe_load(vpath.read_text(encoding='utf-8-sig'))
    if not isinstance(data,dict):raise ValueError('Global YAML must contain a mapping')
    hostname=safe_filename(data.get('hostname') or vpath.stem)
    ipath=Path(args.interface_vars) if args.interface_vars else vpath.parent/f'{hostname}_interface.yaml'
    if not ipath.exists():raise FileNotFoundError(f'Interface YAML missing: {ipath}')
    interface_data=yaml.safe_load(ipath.read_text(encoding='utf-8-sig'))
    if not isinstance(interface_data,dict) or not isinstance(interface_data.get('interfaces'),list):raise ValueError('Invalid interface YAML')
    data['interfaces']=interface_data['interfaces']
    logger,_=log_for(args.output,hostname,'CREATE')
    try:
        logger.info('Main Template: %s',tpath)
        logger.info('Interface Template: %s',args.interface_template or tpath.parent/f'{hostname}_interfaces.j2')
        logger.info('Variables YAML: %s',vpath)
        logger.info('Interface YAML: %s',ipath)
        env=Environment(loader=FileSystemLoader(str(tpath.parent)),undefined=StrictUndefined,autoescape=False,keep_trailing_newline=True)
        main=env.get_template(tpath.name)
        print('[+] Loading Jinja2 templates...         : PASS')
        logger.info('Main Template PASS | Interface Template checked on render')
        print('[+] Loading YAML variables...          : PASS')
        logger.info('Global Variables PASS | Interface Variables PASS')
        rendered=main.render(**data)
        logger.info('Rendering configuration: PASS')
        print('[+] Validating configuration...        : PASS')
        dest=Path(args.output)/hostname/'Variables'/f'{hostname}_generated.cfg'
        save_text(dest,rendered,args.overwrite)
        logger.info('Generated config at: %s',dest)
        print(f'[+] Saving generated configuration... {dest.name} : CREATED')
        print('[+] Configuration generation completed successfully.')
        print(f'\nFiles created in: {dest.parent.resolve()}')
        return 0
    except Exception:logger.exception('Create mode failed');raise
    finally:close_log(logger)


def main(argv=None):
    args=cli(argv)
    try:
        if args.create_config:return create_config(args)
        targets=get_targets(args)
        if not targets:raise ValueError('Empty device inventory')
        if args.collect:
            banner('COLLECT')
            cmd=args.cmd_file
            if not cmd:
                try:cmd=input('[+] Command file\n    Enter command file [cmd.txt]: ').strip() or 'cmd.txt'
                except EOFError:cmd='cmd.txt'
            commands=read_commands(cmd)
            print('\n[+] Loading device inventory...')
            if len(targets)==1:print(f'Device  : {targets[0]}')
            else:print(f'Devices : {len(targets)}')
            args._username=args.username or input('SSH Username: ').strip()
            args._password=args.password if args.password is not None else getpass('SSH Password: ')
            if not args._username:raise ValueError('SSH username required')
            failures=[];results=[]
            def worker(target):return online_collect(args,target,commands)
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                futures={pool.submit(worker,t):t for t in targets}
                for future in as_completed(futures):
                    target=futures[future]
                    try:
                        name,folder=future.result()
                        results.append((name,folder))
                        print('\n[+] Saving backup...')
                        print('[+] Generating Excel workbook...')
                        print(f'[+] {name} Collection completed.')
                        print(f'\nFiles created in: {folder.resolve()}')
                    except Exception as exc:
                        print(f'[!] {target}: {type(exc).__name__}: {exc}')
                        failures.append(target)
            if args.vars:
                for name,_ in results:
                    print('\n'+'-'*32)
                    banner('VARIABLE EXTRACTION')
                    offline_vars(args,name,read_selection(args.selection))
            return 1 if failures else 0
        if args.vars:
            banner('VARIABLE EXTRACTION')
            sel=read_selection(args.selection)
            bad=0
            for target in targets:
                try:offline_vars(args,target,sel)
                except Exception as exc:bad+=1;print(f'[!] {target}: {type(exc).__name__}: {exc}')
            return 1 if bad else 0
        if args.excel:
            banner('EXCEL')
            for target in targets:
                p=offline_excel(args,target)
                print(f'[+] {target} Excel created.\nFiles created in: {p.parent.resolve()}')
            return 0
        raise ValueError('No operation selected')
    except (OSError,ValueError,TemplateError,yaml.YAMLError) as exc:
        print(f'[ERROR] {type(exc).__name__}: {exc}',file=sys.stderr)
        if args.debug:traceback.print_exc()
        return 2

if __name__=='__main__':sys.exit(main())
