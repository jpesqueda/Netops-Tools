#!/usr/bin/env python3
"""Offline structured PRE/POST comparison. No SSH or switch modifications."""
import argparse
import json
from pathlib import Path
from SmartDiff.engine import parse_file, diff, save_report


def main():
    p=argparse.ArgumentParser(description='Compare Cisco PRE/POST TXT captures safely offline.',formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog='EXAMPLES:\n  python SmartDiff.py --pre SW01_PRE.txt --post SW01_POST.txt\n  python SmartDiff.py --pre SW01_PRE.txt --post SW01_POST.txt --expected-version 17.5.6 -o Reports')
    p.add_argument('--pre',required=True,help='PRE checks TXT')
    p.add_argument('--post',required=True,help='POST checks TXT')
    p.add_argument('-o','--output',default='Smart_Diff',help='Report directory')
    p.add_argument('--expected-version',help='Expected IOS-XE release, e.g. 17.5.6')
    args=p.parse_args()
    root=Path(args.output); (root/'JSON').mkdir(parents=True,exist_ok=True)
    a=parse_file(args.pre);b=parse_file(args.post)
    for typ, doc in [('PRE',a),('POST',b)]:
        (root/'JSON'/f'{Path(doc["source"]).stem}_{typ}.json').write_text(json.dumps(doc,indent=2,ensure_ascii=False),encoding='utf-8')
    report=diff(a,b,args.expected_version)
    save_report(report,root)
    print('='*72+'\n                    CISCO SMART PRE / POST DIFF\n'+'='*72)
    print(f'PRE Commands   : {a["command_count"]}\nPOST Commands  : {b["command_count"]}')
    for status,n in sorted(report['counts'].items()): print(f'{status:<16}: {n}')
    print(f'\nReports        : {root.resolve()}')
    return 2 if any(row['status'] in ('CHANGE','ERROR','MISSING_PRE','MISSING_POST','NOT_EVALUATED') for row in report['results']) else 0

if __name__=='__main__':raise SystemExit(main())
