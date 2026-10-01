#!/usr/bin/env python3
"""Cisco IOS-XE upgrade evidence and QUICK snapshot comparison.

Author: Peskicorp
Version: 1.0.1
Dependencies: netmiko, pyats, genie (see requirements.txt).
Section 1: Settings and CLI. Section 2: Capture and parsing.
Section 3: Normalization and comparison. Section 4: Reports and execution.
No upgrade or configuration changes are performed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from getpass import getpass
from html import escape
from pathlib import Path

VERSION = '1.0.1'
SCRIPT_DIR = Path(__file__).resolve().parent
# SECTION 1 — Settings and command-line interface
# Exact field names are excluded recursively; original evidence is preserved.
IGNORE_FIELDS = {
    'uptime', 'uptime_this_cp', 'system_restarted_at', 'last_modified_date',
    'last_modified_time', 'last_modified', 'date', 'time', 'hold_time',
    'holdtime', 'up_down', 'up_time', 'elapsed_time', 'last_read', 'last_write',
    'msg_received', 'msg_sent', 'msg_rcvd', 'msg_sent', 'table_version',
    'input_packets', 'output_packets', 'in_pkts', 'out_pkts', 'input_bytes',
    'output_bytes', 'in_octets', 'out_octets', 'input_rate', 'output_rate',
    'last_input', 'last_output', 'last_clear', 'age', 'age_sec',
    'available_system_uptime', 'uptime_in_curr_state', 'auto_abort_timer',
}
ERROR_MARKERS = ('% Invalid input', '% Incomplete command', '% Ambiguous command',
                 '% Authorization failed', '% Access denied', 'Permission denied')

def cli():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n  python Cisco_Checks.py --init\n  python Cisco_Checks.py --mode pre -u admin -o Upgrade_01\n  python Cisco_Checks.py --mode post -u admin -o Upgrade_01 --target-version 17.12.04\n  python Cisco_Checks.py --mode compare -o Upgrade_01')
    p.add_argument('--version', action='version', version=VERSION)
    p.add_argument('--init', action='store_true', help='Check external command files and create missing hosts/rules examples beside the script')
    p.add_argument('--mode', choices=['pre', 'post', 'compare'])
    p.add_argument('--hosts', default=str(SCRIPT_DIR / 'hosts.txt'))
    p.add_argument('--full-cmd', default=str(SCRIPT_DIR / 'full_cmd.txt'))
    p.add_argument('--quick-cmd', default=str(SCRIPT_DIR / 'quick_cmd.txt'))
    p.add_argument('-u', '--username')
    p.add_argument('-o', '--output', default='Cisco_Checks_Output', help='Same project directory for PRE and POST')
    p.add_argument('--workers', type=int, default=10)
    p.add_argument('--command-timeout', type=int, default=180)
    p.add_argument('--backup-timeout', type=int, default=600)
    p.add_argument('--target-version', help='Expected IOS-XE version; matched exactly')
    p.add_argument('--rules', default=str(SCRIPT_DIR / 'comparison_rules.json'))
    p.add_argument('--overwrite', action='store_true', help='Replace an existing phase snapshot')
    return p.parse_args()

def safe(value):
    readable = re.sub(r'[^A-Za-z0-9_.-]', '_', value).strip('._')[:85] or 'device'
    return readable + '_' + hashlib.sha256(value.encode()).hexdigest()[:8]

def read_list(path):
    return list(dict.fromkeys(s.strip() for s in Path(path).read_text(encoding='utf-8-sig').splitlines()
                             if s.strip() and not s.lstrip().startswith('#')))

def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, default=str), encoding='utf-8')
    temporary.replace(path)

def load_rules(path):
    return json.loads(Path(path).read_text()) if Path(path).exists() else {}

# SECTION 2 — Read-only SSH capture and structured parsing

def validate_commands(commands):
    for command in commands:
        if not re.match(r'^(show|dir)\s', command, re.I) or any(x in command for x in ['\n', '\r', ';']):
            raise ValueError(f'Only show/dir commands are allowed: {command!r}')
        if re.search(r'\|\s*(redirect|tee|append)\b', command, re.I):
            raise ValueError(f'Output redirection is not allowed: {command}')

def parse_output(device, command, raw):
    if not raw.strip():
        return {'status': 'EMPTY_OUTPUT', 'data': None, 'error': 'Empty output requires review'}
    if any(marker.lower() in raw.lower() for marker in ERROR_MARKERS):
        return {'status': 'CLI_ERROR', 'data': None, 'error': 'Device rejected the command'}
    try:
        data = device.parse(command, output=raw)
        if not isinstance(data, dict) or not data:
            raise ValueError('Parser returned no structured records')
        return {'status': 'PARSED', 'data': data, 'error': ''}
    except Exception as exc:
        return {'status': 'PARSE_ERROR', 'data': None, 'error': f'{type(exc).__name__}: {exc}'}

def phase_paths(root, phase):
    title = 'Pre' if phase == 'pre' else 'Post'
    base = root / f'{title}Checks'
    return base / f'Backups_{title}', base / f'{title}Checks_Full', base / f'{title}Checks_Quick'

def capture(host, args, full, quick, password, secret):
    from netmiko import ConnectHandler
    from genie.conf.base import Device
    backup, full_dir, quick_dir = phase_paths(Path(args.output), args.mode)
    key = safe(host)
    snapshot_path = quick_dir / key / 'snapshot.json'
    if snapshot_path.exists() and not args.overwrite:
        raise FileExistsError(f'{host}: existing snapshot; use --overwrite deliberately')
    snap = {'host': host, 'phase': args.mode, 'timestamp': datetime.now().astimezone().isoformat(),
            'version': VERSION, 'collection': 'FAILED', 'backup': 'NOT_ATTEMPTED', 'commands': {}, 'full_errors': []}
    connection = None
    try:
        connection = ConnectHandler(device_type='cisco_xe', host=host, username=args.username,
            password=password, secret=secret or '', conn_timeout=20, auth_timeout=30,
            banner_timeout=30, fast_cli=False)
        if secret:
            connection.enable()
        connection.send_command('terminal length 0', read_timeout=30)
        device = Device(name=key, os='iosxe')
        for command in dict.fromkeys(full + quick + ['show running-config']):
            filename = safe(command) + '.txt'
            try:
                raw = str(connection.send_command(command, read_timeout=args.backup_timeout if command == 'show running-config' else args.command_timeout))
                bad = any(m.lower() in raw.lower() for m in ERROR_MARKERS)
                entry = {'status': 'CLI_ERROR' if bad else 'CAPTURED', 'data': None, 'error': ''}
            except Exception as exc:
                raw = f'[CAPTURE ERROR] {type(exc).__name__}: {exc}'
                bad = True
                entry = {'status': 'CAPTURE_ERROR', 'data': None, 'error': str(exc)}
            if command in full:
                if bad:
                    snap['full_errors'].append(command)
                path = full_dir / key / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(raw, encoding='utf-8')
            if command == 'show running-config':
                if not bad:
                    backup.mkdir(parents=True, exist_ok=True)
                    (backup / f'{key}_{args.mode}.cfg').write_text(raw, encoding='utf-8')
                    snap['backup'] = 'SUCCESS'
                else:
                    snap['backup'] = 'FAILED'
            if command in quick:
                path = quick_dir / key / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(raw, encoding='utf-8')
                if not bad:
                    entry = parse_output(device, command, raw)
                entry['raw_file'] = str(path.relative_to(Path(args.output)))
                snap['commands'][command] = entry
                if entry['status'] != 'PARSED':
                    logging.warning('%s / %s: %s %s', host, command, entry['status'], entry['error'])
        snap['collection'] = 'SUCCESS' if not snap['full_errors'] and all(v['status'] == 'PARSED' for v in snap['commands'].values()) else 'PARTIAL'
    except Exception as exc:
        snap['error'] = f'{type(exc).__name__}: {exc}'
        logging.exception('Capture failed: %s', host)
    finally:
        if connection:
            try:
                connection.disconnect()
            except Exception:
                logging.warning('Disconnect failed: %s', host)
    write_json(snapshot_path, snap)
    return snap

# SECTION 3 — Explicit normalization and record comparison

def normalize(data, ignored, path=''):
    if isinstance(data, dict):
        # Genie directory records are keyed by entry index; re-key by filename.
        if data and all(isinstance(v, dict) and ('filename' in v or 'file_name' in v) for v in data.values()):
            data = {str(v.get('filename', v.get('file_name'))): v for v in data.values()}
        return {str(k): normalize(v, ignored, f'{path}/{k}') for k, v in sorted(data.items(), key=lambda kv: str(kv[0]))
                if str(k).lower() not in ignored}
    if isinstance(data, list):
        items = [normalize(v, ignored, path) for v in data]
        return sorted(items, key=lambda v: json.dumps(v, sort_keys=True, default=str))
    return data

def flatten(data, prefix=''):
    result = {}
    if isinstance(data, dict):
        for key, value in data.items():
            result.update(flatten(value, f'{prefix}/{key}' if prefix else str(key)))
    else:
        result[prefix] = data
    return result

def compare_snapshots(pre, post, rules, target):
    rows = []
    for command in dict.fromkeys(list(pre.get('commands', {})) + list(post.get('commands', {}))):
        a, b = pre.get('commands', {}).get(command), post.get('commands', {}).get(command)
        if not a or not b or a['status'] != 'PARSED' or b['status'] != 'PARSED':
            rows.append((command, 'Comparison coverage', a['status'] if a else 'MISSING', b['status'] if b else 'MISSING', 'N/A'))
            continue
        ignored = IGNORE_FIELDS | set(rules.get('ignore_fields', [])) | set(rules.get('commands', {}).get(command, {}).get('ignore_fields', []))
        old = flatten(normalize(a['data'], ignored))
        new = flatten(normalize(b['data'], ignored))
        changes = 0
        for field in sorted(set(old) | set(new)):
            before, after = old.get(field, '<MISSING>'), new.get(field, '<MISSING>')
            is_version = command == 'show version' and field.split('/')[-1] in {'version', 'version_short', 'software_version'}
            if is_version and target:
                state = 'EXPECTED' if str(after) == target else 'FAIL'
            elif before != after:
                state = 'CHANGE'
            else:
                continue
            changes += 1
            rows.append((command, field, before, after, state))
        if not changes:
            rows.append((command, 'Selected fields', 'Unchanged', 'Unchanged', 'GOOD'))
    return rows

# SECTION 4 — QUICK-only text/HTML reports and execution

def cell(value):
    return json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)

def text_report(host, rows):
    import textwrap
    widths = [36, 48, 48, 10]
    header = f'SWITCH: {host}\nPROFILE: QUICK\nGOOD means unchanged selected fields, not a complete health certification.\n'
    lines = [header, ' | '.join(v.ljust(w) for v, w in zip(['COMMAND / FIELD', 'PRE', 'POST', 'STATUS'], widths)), '-' * 151]
    last = None
    for command, field, pre, post, status in rows:
        if command != last:
            lines.extend(['', command])
            last = command
        columns = [textwrap.wrap(cell(v), width=w, replace_whitespace=True) or [''] for v, w in zip([field, pre, post, status], widths)]
        for n in range(max(map(len, columns))):
            lines.append(' | '.join((c[n] if n < len(c) else '').ljust(w) for c, w in zip(columns, widths)))
    return '\n'.join(lines) + '\n'

def reports(args, rules):
    root = Path(args.output)
    pre_dir = phase_paths(root, 'pre')[2]
    post_dir = phase_paths(root, 'post')[2]
    files = {p.parent.name for d in [pre_dir, post_dir] for p in d.glob('*/snapshot.json')}
    if not files:
        raise ValueError('No snapshots found; capture PRE and POST in the same output directory')
    sections, summary = [], []
    for key in sorted(files):
        paths = [d / key / 'snapshot.json' for d in [pre_dir, post_dir]]
        snaps = [json.loads(p.read_text()) if p.exists() else {} for p in paths]
        pre, post = snaps
        host = post.get('host', pre.get('host', key))
        rows = compare_snapshots(pre, post, rules, args.target_version) if all(snaps) else [('ALL QUICK COMMANDS', 'Snapshot', 'AVAILABLE' if pre else 'MISSING', 'AVAILABLE' if post else 'MISSING', 'N/A')]
        coverage = 'INCOMPLETE' if any(r[4] == 'N/A' for r in rows) else 'COMPLETE'
        diff = root / 'Diffs' / f'{key}.diff'
        diff.parent.mkdir(parents=True, exist_ok=True)
        diff.write_text(text_report(host, rows), encoding='utf-8')
        body = []
        for command in dict.fromkeys(r[0] for r in rows):
            entries = [r for r in rows if r[0] == command]
            body.append(f'<details open><summary>{escape(command)}</summary><table><thead><tr><th>FIELD</th><th>PRE</th><th>POST</th><th>STATUS</th></tr></thead><tbody>')
            for _, field, a, b, status in entries:
                body.append('<tr>' + ''.join(f'<td>{escape(cell(v))}</td>' for v in [field, a, b]) + f'<td class="{status}">{status}</td></tr>')
            body.append('</tbody></table></details>')
        sections.append(f'<section><h2>{escape(host)}</h2><p>Coverage: {coverage} · Backup PRE: {pre.get("backup", "MISSING")} · Backup POST: {post.get("backup", "MISSING")}</p>{"".join(body)}</section>')
        summary.append(f'{host}: Changes={sum(r[4] == "CHANGE" for r in rows)} | Coverage={coverage}')
    html = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cisco QUICK comparison</title><style>body{font:14px system-ui;background:#eef2f7;color:#172033;margin:24px}section{background:white;padding:20px;margin:20px 0;border-radius:12px;overflow:auto}table{border-collapse:collapse;width:100%;table-layout:fixed}td,th{padding:10px;border:1px solid #ddd;overflow-wrap:anywhere;text-align:left}td:nth-child(2){background:#fff1f2}td:nth-child(3){background:#ecfdf5}.GOOD{color:green}.CHANGE{color:#a16207}.FAIL{color:red}.EXPECTED{color:#2563eb}summary{padding:15px;cursor:pointer;font-weight:bold}</style><h1>Cisco PRE vs POST — QUICK</h1><p>Original outputs are retained. GOOD means selected fields are unchanged. Changes require review; dynamic health rules are not inferred.</p>' + ''.join(sections) + '</html>'
    html_path = root / 'Diff_HTML' / 'index.html'
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(html, encoding='utf-8')
    print('\n'.join(summary))
    print(f'HTML report: {html_path.resolve()}')

def main():
    args = cli()
    if args.init:
        for name, content in [('hosts.txt', '# One hostname or IP per line\n# Replace this example\nswitch1.example.com\n'), ('comparison_rules.json', json.dumps({'ignore_fields': [], 'commands': {}}, indent=2))]:
            if not (SCRIPT_DIR / name).exists():
                (SCRIPT_DIR / name).write_text(content, encoding='utf-8')
                print(f'Created {name}')
        for filename in ('full_cmd.txt', 'quick_cmd.txt'):
            if not (SCRIPT_DIR / filename).is_file():
                raise FileNotFoundError(f'Missing external command file: {SCRIPT_DIR / filename}')
            print(f'Command file: {SCRIPT_DIR / filename}')
        return 0
    args.mode = args.mode or input('Execution Type (pre/post/compare): ').strip().lower()
    if args.mode not in {'pre', 'post', 'compare'}:
        raise ValueError('Invalid execution type')
    rules = load_rules(args.rules)
    if args.mode == 'compare':
        reports(args, rules)
        return 0
    full, quick, hosts = read_list(args.full_cmd), read_list(args.quick_cmd), read_list(args.hosts)
    if not full or not quick or not hosts:
        raise ValueError('Hosts and command lists must not be empty')
    validate_commands(full + quick)
    if args.workers < 1:
        raise ValueError('Workers must be positive')
    # Refuse the entire run before credentials/connections if any PRE/POST exists.
    quick_dir = phase_paths(Path(args.output), args.mode)[2]
    if not args.overwrite and any((quick_dir / safe(h) / 'snapshot.json').exists() for h in hosts):
        raise FileExistsError('Existing phase snapshots found; use a new output directory or --overwrite')
    args.username = args.username or input('Username: ').strip()
    password = getpass('Password: ')
    secret = getpass('Enable secret (Enter to skip): ')
    Path(args.output).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=Path(args.output) / 'Cisco_Checks.log', level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')
    print(f'CISCO CHECKS {VERSION} — {args.mode.upper()} | FULL={len(full)} QUICK={len(quick)}')
    failed = False
    with ThreadPoolExecutor(max_workers=min(args.workers, len(hosts))) as pool:
        futures = {pool.submit(capture, h, args, full, quick, password, secret): h for h in hosts}
        for count, future in enumerate(as_completed(futures), 1):
            snap = future.result()
            failed |= snap['collection'] != 'SUCCESS' or snap['backup'] != 'SUCCESS'
            print(f'[{count}/{len(hosts)}] {snap["host"]}: Collection={snap["collection"]} | Backup={snap["backup"]}')
    if args.mode == 'post':
        print('Comparing QUICK snapshots: PRE vs POST...')
        reports(args, rules)
    return 2 if failed else 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('\nCancelled.')
        raise SystemExit(130)
    except Exception as exc:
        print(f'ERROR: {exc}')
        raise SystemExit(1)
