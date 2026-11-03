"""Interface state, counters, trunk and address parsers."""
import re
from utils.core import clean_lines, normalize_interface, integer

def parse_status(raw):
    out=[]
    for line in clean_lines(raw):
        m=re.match(r'^(\S+)\s{2,}(.+?)\s{2,}(connected|notconnect|disabled|err-disabled|inactive|monitoring|suspended|sfpAbsent|unknown)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$',line,re.I)
        if m:
            port,name,status,vlan,duplex,speed,typ=m.groups()
            out.append({'interface':normalize_interface(port),'description':name.strip(),'status':status,'vlan':vlan,'duplex':duplex,'speed':speed,'type':typ or ''})
    return out

def parse_description(raw):
    out=[]
    for line in clean_lines(raw):
        m=re.match(r'^(\S+)\s+(up|down|admin down|administratively down)\s+(up|down)\s*(.*)$',line,re.I)
        if m:
            a,b,c,d=m.groups();out.append({'interface':normalize_interface(a),'status':b,'protocol':c,'description':d})
    return out

def parse_counters(raw):
    out={}; direction=None; fields=[]
    for line in clean_lines(raw):
        if re.match(r'^Port\s+InOctets',line): direction='in'; fields=['octets','ucast','mcast','bcast'];continue
        if re.match(r'^Port\s+OutOctets',line): direction='out'; fields=['octets','ucast','mcast','bcast'];continue
        parts=line.split()
        if direction and len(parts)==5 and re.match(r'^[A-Za-z]+\d',parts[0]):
            key=normalize_interface(parts[0]);row=out.setdefault(key,{'interface':key})
            row.update({direction+'_'+f:integer(v) for f,v in zip(fields,parts[1:])})
    return list(out.values())

def parse_errors(raw):
    lines=clean_lines(raw);out=[];fields=[]
    for line in lines:
        if line.startswith('Port '): fields=[v.lower().replace('-','_') for v in line.split()[1:]];continue
        p=line.split()
        if fields and len(p)==len(fields)+1 and re.match(r'^[A-Za-z]+\d',p[0]):
            out.append({'interface':normalize_interface(p[0]), **{k:integer(v) for k,v in zip(fields,p[1:])}})
    return out

def parse_ip_brief(raw):
    out=[]
    for line in clean_lines(raw):
        p=line.split()
        if len(p)>=6 and p[2] in ('YES','NO') and re.match(r'^[A-Za-z-]+\d',p[0]):
            out.append({'interface':normalize_interface(p[0]),'ip_address':p[1],'ok':p[2],'method':p[3],'status':' '.join(p[4:-1]),'protocol':p[-1]})
    return out

def parse_trunk(raw):
    records={};section=''
    for line in clean_lines(raw):
        if line.startswith('Port '):
            if 'Native vlan' in line:section='main'
            elif 'Vlans allowed and active' in line:section='active'
            elif 'Vlans allowed on trunk' in line:section='allowed'
            elif 'Vlans in spanning tree' in line:section='forwarding'
            continue
        p=line.split()
        if not p or not re.match(r'^[A-Za-z]+\d',p[0]):continue
        key=normalize_interface(p[0]);row=records.setdefault(key,{'interface':key})
        if section=='main' and len(p)>=5:row.update({'mode':p[1],'encapsulation':p[2],'status':p[3],'native_vlan':p[4]})
        elif section and len(p)>=2:row[section+'_vlans']=' '.join(p[1:])
    return list(records.values())
