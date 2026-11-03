"""System, inventory and environment parsers."""
import re
from utils.core import clean_lines

def parse_version(raw):
    patterns = {'hostname': r'(?m)^(\S+) uptime is ', 'version': r'Cisco IOS Software.*?Version\s+([\d.]+)', 'model':r'\b(C\d{4}[\w-]*)\s+\(.*?\) processor', 'uptime':r'uptime is (.+)', 'image':r'System image file is "([^"]+)"', 'serial':r'Processor board ID\s+(\S+)'}
    result = {k:(m.group(1) if (m:=re.search(p,raw)) else None) for k,p in patterns.items()}
    if not result['version']:
        m=re.search(r'Cisco IOS XE Software, Version\s+([\d.]+)',raw)
        if m: result['version']=m.group(1)
    return [result] if any(result.values()) else []

def parse_inventory(raw):
    rows=[]
    for match in re.finditer(r'NAME:\s*"([^"]+)",\s*DESCR:\s*"([^"]+)"\s*\nPID:\s*([^,\n]+),\s*VID:\s*([^,\n]+),\s*SN:\s*(\S+)', raw, re.I):
        rows.append(dict(zip(['name','description','pid','vid','serial'], [x.strip() for x in match.groups()])))
    return rows

def parse_environment(raw):
    rows=[]
    for line in clean_lines(raw):
        m=re.match(r'(Switch\s+\d+\s+.+?)\s+is\s+(OK|NOT PRESENT|FAILED|WARNING|UNKNOWN)(?:\s+.*)?$',line,re.I)
        if m: rows.append({'component':m.group(1),'status':m.group(2)})
    return rows
