#!/usr/bin/env python3
"""Offline parsing of Cisco IOS-XE CLI outputs with locally maintained templates.

Requires: pip install textfsm ttp (ttp only for running-config).
No connection to the network. No device credentials.
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAPPING = {
    'show environment all': 'cisco_ios_show_environment_all.textfsm',
    'show interfaces counters': 'cisco_ios_show_interfaces_counters.textfsm',
    'show interfaces counters errors': 'cisco_ios_show_interfaces_counters_errors.textfsm',
    'show interfaces trunk': 'cisco_ios_show_interfaces_trunk.textfsm',
    'show ip arp inspection interfaces': 'cisco_ios_show_ip_arp_inspection_interfaces.textfsm',
    'show ip protocols': 'cisco_ios_show_ip_protocols.textfsm',
    'show ip dhcp snooping': 'cisco_ios_show_ip_dhcp_snooping.textfsm',
    'show device-tracking database': 'cisco_ios_show_device-tracking_database.textfsm',
}

def normalize(rows: list[dict], command: str) -> list[dict]:
    """Fold repeated per-interface blocks together; preserve all other rows."""
    if command not in {'show interfaces trunk', 'show interfaces counters'}:
        return rows
    grouped: dict[str,dict] = {}
    for row in rows:
        key = row.get('PORT', '').strip()
        if not key:
            continue
        current = grouped.setdefault(key, {'PORT': key})
        for field, value in row.items():
            if field != 'PORT' and value not in (None, ''):
                if field in current and current[field] != value:
                    raise ValueError(f'Conflicting {field} for {key}')
                current[field] = value
    return list(grouped.values())

def parse_textfsm(command: str, data: str) -> list[dict]:
    try:
        import textfsm
    except ImportError as e:
        raise SystemExit('Missing dependency: python -m pip install textfsm') from e
    name = MAPPING[command]
    with (ROOT / 'TextFSM' / name).open(encoding='utf-8') as f:
        parser = textfsm.TextFSM(f)
        rows = [dict(zip(parser.header, values)) for values in parser.ParseText(data)]
    return normalize(rows, command)

def parse_ttp(data: str) -> object:
    try:
        from ttp import ttp
    except ImportError as e:
        raise SystemExit('Missing dependency: python -m pip install ttp') from e
    template = (ROOT/'TTP'/'cisco_ios_show_running-config.ttp').read_text(encoding='utf8')
    engine = ttp(data=data, template=template)
    engine.parse()
    return engine.result(structure='flat_list')

def save_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True,exist_ok=True)
    cols=list(dict.fromkeys(k for row in rows for k in row.keys()))
    if not cols:
        raise RuntimeError('Parser returned no rows: check command, output version and template')
    # Avoid formula injection when viewing the CSV in Excel.
    def clean(v: object)->object:
        if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')):
            return "'"+v
        return v
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=cols)
        w.writeheader()
        w.writerows([{k:clean(v) for k,v in row.items()} for row in rows])

def main()->None:
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--list',action='store_true',help='Show custom commands')
    p.add_argument('--command',choices=[*MAPPING,'show running-config'])
    p.add_argument('--input',type=Path,help='Offline CLI output file')
    p.add_argument('--output',type=Path,help='CSV for TextFSM or JSON for TTP')
    p.add_argument('--test-all',action='store_true',help='Run all nine fixtures (dependencies required)')
    args=p.parse_args()
    if args.list:
        print('\n'.join([*MAPPING,'show running-config']))
        return
    if args.test_all:
        failures=[]
        for cmd in [*MAPPING, 'show running-config']:
            path=ROOT/'fixtures'/ (cmd.replace(' ','_')+'.txt')
            try:
                data=path.read_text(encoding='utf8')
                rows=parse_ttp(data) if cmd=='show running-config' else parse_textfsm(cmd,data)
                if not rows: raise ValueError('No parsed rows')
                print(f'PASS {cmd}: {len(rows)} structured row(s)')
            except Exception as e:
                failures.append((cmd,str(e)))
                print(f'FAIL {cmd}: {e}')
        if failures: raise SystemExit(1)
        return
    if not args.command or not args.input:
        p.error('--command and --input required, or specify --list/--test-all')
    raw=args.input.read_text(encoding='utf8')
    if args.command == 'show running-config':
        records=parse_ttp(raw)
        output=args.output or Path('parsed_running_config.json')
        output.write_text(json.dumps(records,indent=2,ensure_ascii=False),encoding='utf8')
    else:
        records=parse_textfsm(args.command,raw)
        output=args.output or Path('parsed_output.csv')
        save_csv(records,output)
    print(f'PARSED {args.command}: {len(records)} record(s), saved to {output.resolve()}')

if __name__=='__main__':main()
