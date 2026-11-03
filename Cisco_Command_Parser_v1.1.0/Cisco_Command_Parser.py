#!/usr/bin/env python3
"""Cisco Command Parser v1.1.1. Parse offline Cisco command captures to JSON/Excel.

Requires Python 3.10+ and openpyxl (Excel export only).
No pyATS, Genie or live device connection required.
"""
__version__='1.1.1'
import argparse
import json
import logging
import sys
import time
from pathlib import Path
from collections import defaultdict
from parsers import PARSERS,ALIASES
from utils.core import split_commands
from utils.consolidate import consolidate
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn
from rich.panel import Panel
from rich.text import Text

console = Console()
STATUS_STYLES = {
    'PARSED': 'green', 'UNSUPPORTED': 'yellow',
    'UNPARSED': 'yellow', 'EMPTY': 'yellow', 'ERROR': 'red',
}


def show_results(summary, device, master, paths, log_path, duration):
    """Display a readable summary after processing, preserving CLI output semantics."""
    hostname = device.get('hostname', 'UNKNOWN')
    console.print(Panel(f'[bold]CISCO COMMAND PARSER[/bold]  [cyan]v{__version__}[/cyan]\n'
                        f'Device: [bold]{hostname}[/bold]', border_style='cyan'))
    table = Table(show_header=True, header_style='bold cyan', expand=False)
    table.add_column('COMMAND', style='white', no_wrap=False)
    table.add_column('RECORDS', justify='right', style='bright_white')
    table.add_column('STATUS', justify='center')
    for row in summary:
        status = row['status']
        table.add_row(row['command'], str(row['records']),
                      Text(status, style=f'bold {STATUS_STYLES.get(status, "white")}'))
    console.print(table)
    counts = {name: sum(r['status'] == name for r in summary) for name in STATUS_STYLES}
    console.print('\n[bold]SUMMARY[/bold]')
    console.print(f'  Commands: {len(summary)}   [green]Parsed: {counts["PARSED"]}[/green]'
                  f'   [yellow]Skipped: {counts["UNSUPPORTED"] + counts["UNPARSED"] + counts["EMPTY"]}[/yellow]'
                  f'   [red]Errors: {counts["ERROR"]}[/red]')
    console.print(f'  Master interfaces: {len(master)}   Duration: {duration:.2f}s')
    console.print('[bold]GENERATED FILES[/bold]')
    for path in paths:
        console.print(f'  [green]PASS[/green]  {path}')
    console.print(f'  [dim]Log: {log_path}[/dim]')



def parse_capture(src, progress=None, task_id=None):
    blocks=split_commands(src)
    results=defaultdict(list);summary=[]
    for b in blocks:
        cmd=b['command'];canonical=ALIASES.get(cmd,cmd)
        try:
            if canonical not in PARSERS:status='UNSUPPORTED';records=[];error='No parser registered'
            elif not b['raw_output']:status='EMPTY';records=[];error='No command output'
            else:
                records=PARSERS[canonical](b['raw_output'])
                status='PARSED' if records else 'UNPARSED';error='' if records else 'No records matched; check output format'
                if records:results[canonical].extend(records)
        except Exception as exc:
            status='ERROR';records=[];error=f'{type(exc).__name__}: {exc}'
            logging.exception('Parser error for %s',cmd)
        b.update(status=status,records=len(records),error=error)
        summary.append({'command':cmd,'status':status,'records':len(records),'error':error})
        logging.info('%s | %s | %s records | %s',cmd,status,len(records),error)
        if progress is not None:
            progress.advance(task_id)
    device=results.get('show version',[{}])[0] if results.get('show version') else {}
    return blocks,dict(results),device,summary


def main(argv=None):
    arg=argparse.ArgumentParser(description='Offline Cisco IOS-XE command capture parser (v'+__version__+')',formatter_class=argparse.RawDescriptionHelpFormatter,epilog='Examples:\n  python Cisco_Command_Parser.py Commands_Output.txt\n  python Cisco_Command_Parser.py Commands_Output.txt -o SW01_Audit.xlsx\n  python Cisco_Command_Parser.py Commands_Output.txt --json\n  python Cisco_Command_Parser.py Commands_Output.txt --json --excel\n  python Cisco_Command_Parser.py Commands_Output.txt --raw-json --overwrite')
    arg.add_argument('input',type=Path,help='Input TXT with ===== / show command / ===== blocks')
    arg.add_argument('-o','--output',type=Path,help='Output Excel file or directory (default: <input>_Audit.xlsx)')
    arg.add_argument('--json',action='store_true',help='Export structured JSON as well as Excel (unless --no-excel)')
    arg.add_argument('--no-excel',action='store_true',help='Skip Excel generation (use with --json)')
    arg.add_argument('--excel',action='store_true',help='Explicitly enable Excel generation (default)')
    arg.add_argument('--raw-json',action='store_true',help='Include raw command outputs in JSON')
    arg.add_argument('--overwrite',action='store_true',help='Allow replacing existing output files')
    args=arg.parse_args(argv)
    if args.no_excel and not args.json:arg.error('Nothing to export: specify --json or remove --no-excel')
    if not args.input.is_file():arg.error(f'Input file does not exist: {args.input}')
    dest=args.output or args.input.with_name(args.input.stem+'_Audit.xlsx')
    if dest.suffix.lower()=='.xlsx':excel_path=dest;json_path=dest.with_suffix('.json')
    elif not dest.suffix:excel_path=dest/(args.input.stem+'_Audit.xlsx');json_path=excel_path.with_suffix('.json')
    else:arg.error('Output must be an .xlsx filename or directory')
    paths=([excel_path] if not args.no_excel else [])+([json_path] if args.json else [])
    existing=[str(p) for p in paths if p.exists()]
    if existing and not args.overwrite:arg.error('Files already exist (use --overwrite): '+', '.join(existing))
    for p in paths:p.parent.mkdir(parents=True,exist_ok=True)
    log_dir=excel_path.parent/'Logs';log_dir.mkdir(parents=True,exist_ok=True)
    logging.basicConfig(filename=log_dir/'parser.log',filemode='a',level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s',encoding='utf-8')
    start=time.monotonic()
    try:text=args.input.read_text(encoding='utf-8-sig',errors='replace')
    except OSError as exc:arg.error(str(exc))
    block_count = len(split_commands(text))
    with Progress(
        TextColumn('[bold cyan]Parsing commands[/bold cyan]'),
        BarColumn(bar_width=38),
        TaskProgressColumn(),
        TextColumn('{task.completed}/{task.total}'),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task('Parse', total=block_count)
        blocks,parsed,device,summary=parse_capture(text,progress,task)
    if not blocks:arg.error('No commands found. Expected ===== / show ... / ===== blocks')
    master=consolidate(parsed)
    payload={'schema_version':'1.1.1','source_file':str(args.input),'device':device,'command_summary':summary,'commands':parsed,'interfaces_master':master}
    payload['unparsed_raw_commands']=[b for b in blocks if b['status']!='PARSED']
    if args.raw_json:payload['raw_commands']=blocks
    if args.json:json_path.write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding='utf-8')
    if not args.no_excel:
        try:
            from exporters.excel_exporter import excel_export
            excel_export(excel_path,device,blocks,parsed,master,summary)
        except ImportError as exc:
            console.print('[red]Excel export requires openpyxl. Install with: py -m pip install openpyxl[/red]');raise SystemExit(2) from exc
    logging.info('Completed %s blocks, %s interface records in %.2fs',len(blocks),len(master),time.monotonic()-start)
    show_results(summary, device, master, paths, log_dir / 'parser.log', time.monotonic()-start)
    return 0
if __name__=='__main__':sys.exit(main())
