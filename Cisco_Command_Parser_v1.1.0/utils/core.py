"""Command splitting and Cisco interface normalization."""
import re

SEPARATOR = re.compile(r'^={20,}\s*$')

def split_commands(text):
    """Accept repeated separator / command / separator blocks; retain duplicates."""
    lines = text.replace('\r\n', '\n').replace('\r', '\n').splitlines()
    blocks, i = [], 0
    while i < len(lines):
        if SEPARATOR.fullmatch(lines[i].strip()) and i+2 < len(lines) and lines[i+1].strip().lower().startswith('show ') and SEPARATOR.fullmatch(lines[i+2].strip()):
            command = ' '.join(lines[i+1].strip().lower().split())
            i += 3
            data = []
            while i < len(lines) and not (SEPARATOR.fullmatch(lines[i].strip()) and i+2 < len(lines) and lines[i+1].strip().lower().startswith('show ') and SEPARATOR.fullmatch(lines[i+2].strip())):
                data.append(lines[i]); i += 1
            blocks.append({'command': command, 'raw_output': '\n'.join(data).strip()})
        else:
            i += 1
    return blocks

PREFIXES = {'gigabitethernet': 'Gi','tengigabitethernet':'Te','twentyfivegige':'Twe','fortygigabitethernet':'Fo','hundredgigabitethernet':'Hu','fastethernet':'Fa','port-channel':'Po','portchannel':'Po','vlan':'Vl','loopback':'Lo','ethernet':'Eth','gig':'Gi','ten':'Te'}
def normalize_interface(name):
    value = str(name or '').strip()
    match = re.match(r'^([A-Za-z-]+)\s*(\d+(?:/\d+)*(?:\.\d+)?)$', value)
    if not match: return value
    return PREFIXES.get(match.group(1).lower(), match.group(1)) + match.group(2)

def clean_lines(raw):
    return [line.rstrip() for line in raw.splitlines() if line.strip()]

def integer(value):
    try: return int(value.replace(',', ''))
    except (ValueError, AttributeError): return value
