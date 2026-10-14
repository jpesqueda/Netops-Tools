#!/usr/bin/env python3
"""Catalyst Configuration Auditor v1.0.0 — offline/SSH extraction and roundtrip checks.

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

from core.connection import collect
from core.discovery import discover
from core.renderer import render
from core.reporting import save_diff, summary_report
from parsers.extractor import extract

__version__='1.0.0'
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
