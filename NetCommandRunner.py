#!/usr/bin/env python3
"""NetCommandRunner v1.0.0 - parallel network command collector for Netmiko."""
from __future__ import annotations

import argparse
import csv
import getpass
import logging
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

VERSION = "1.0.0"
DEFAULT_WORKERS = 20
WRITE_COMMANDS = {"wr", "write mem", "write memory", "copy run start", "copy running-config startup-config"}
ERROR_PATTERNS = [
    re.compile(p, re.I) for p in (
        r"^%\s*(?:Invalid input|Incomplete command|Ambiguous command|Error|Failed)",
        r"^Error:",
        r"startup-config file open failed",
        r"not enough space",
    )
]
_LOG = logging.getLogger("NetCommandRunner")

@dataclass
class CommandResult:
    command: str
    status: str
    output: str
    error: str = ""
    duration: float = 0.0

@dataclass
class DeviceResult:
    host: str
    status: str = "FAILED"
    results: list[CommandResult] = field(default_factory=list)
    error: str = ""
    duration: float = 0.0
    filename: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run network CLI commands over SSH and save output per device.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=("Examples:\n"
                "  python NetCommandRunner.py -ho SW01 -cmd commands.txt -u admin\n"
                "  python NetCommandRunner.py -hf hosts.txt -cf commands.txt --prefix pre --suffix checks --timestamp\n"
                "  python NetCommandRunner.py -hf hosts.txt -cmd commands.txt -w 20 -o Audit --overwrite\n"
                "  python NetCommandRunner.py -hf hosts.txt -cmd commands.txt --dry-run"),
    )
    device = parser.add_argument_group("Device selection")
    group = device.add_mutually_exclusive_group(required=True)
    group.add_argument("-ho", "--host", help="Single hostname or IP")
    group.add_argument("-hf", "--host-file", type=Path, help="File of hostnames/IPs, one per line")
    commands = parser.add_argument_group("Commands")
    commands.add_argument("-cf", "-cmd", "--command-file", type=Path, required=True, help="Commands file; blank lines and # comments ignored")
    commands.add_argument("--mode", choices=("exec", "config"), default="exec", help="EXEC commands or configuration commands")
    auth = parser.add_argument_group("Authentication")
    auth.add_argument("-u", "--user", help="SSH username; prompted if omitted")
    auth.add_argument("-p", "--password", help="SSH password; securely prompted if omitted")
    auth.add_argument("--secret", help="Enable secret; securely prompted when needed if omitted")
    execution = parser.add_argument_group("Execution")
    execution.add_argument("-dt", "--device-type", default="cisco_ios", help="Netmiko device_type (Cisco IOS-XE: cisco_ios)")
    execution.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help="Concurrent SSH sessions")
    execution.add_argument("--timeout", type=int, default=30, help="Read timeout in seconds per command")
    execution.add_argument("--conn-timeout", type=int, default=15, help="SSH connection timeout")
    execution.add_argument("--retries", type=int, default=2, help="Retries on transient connection errors, excluding authentication failures")
    execution.add_argument("--dry-run", action="store_true", help="Preview resolved hosts, commands and filenames without SSH")
    execution.add_argument("-y", "--yes", action="store_true", help="Skip config-mode confirmation")
    output = parser.add_argument_group("Output")
    output.add_argument("-o", "--output", type=Path, default=Path("Outputs"), help="Root directory for Results/, Logs/ and summary.csv")
    output.add_argument("--prefix", help="Prefix for device output filenames")
    output.add_argument("--suffix", help="Suffix for device output filenames")
    output.add_argument("--timestamp", action="store_true", help="Append common run timestamp to device filenames")
    output.add_argument("--overwrite", action="store_true", help="Overwrite device outputs and summary.csv if they exist")
    parser.add_argument("-v", "--version", action="version", version=f"NetCommandRunner {VERSION}")
    args = parser.parse_args()
    if args.workers < 1 or args.timeout < 1 or args.conn_timeout < 1 or args.retries < 0:
        parser.error("workers, timeout and conn-timeout must be positive, retries >= 0")
    return args


def read_lines(path: Path, label: str) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise ValueError(f"Cannot read {label} {path}: {exc}") from exc
    result = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not result:
        raise ValueError(f"{label} is empty: {path}")
    return result


def safe_fragment(value: str) -> str:
    # Prevent traversal and invalid Windows filenames.
    sanitized = re.sub(r'[^A-Za-z0-9._-]+', '_', value.strip()).strip(' ._')
    if not sanitized or sanitized in ('.', '..'):
        raise ValueError(f"Invalid filename component: {value!r}")
    return sanitized


def filename_for(host: str, args: argparse.Namespace, stamp: str) -> str:
    parts = []
    if args.prefix:
        parts.append(safe_fragment(args.prefix))
    parts.append(safe_fragment(host))
    if args.suffix:
        parts.append(safe_fragment(args.suffix))
    if args.timestamp:
        parts.append(stamp)
    return '_'.join(parts) + '.txt'


def is_write_command(command: str) -> bool:
    return ' '.join(command.lower().split()) in WRITE_COMMANDS


def is_error_output(output: str, write: bool) -> bool:
    if any(pattern.search(line.strip()) for line in output.splitlines() for pattern in ERROR_PATTERNS):
        return True
    if write:
        # For Cisco IOS/IOS-XE WR the [OK] completion marker is required.
        return re.search(r"\[OK\]", output, flags=re.I) is None
    return False


def run_command(connection, command: str, timeout: int) -> str:
    if is_write_command(command):
        # Timing mode handles prompts/async CLI output better than pattern-based matching.
        output = connection.send_command_timing(command, read_timeout=timeout, strip_prompt=False, strip_command=False)
        # Some platforms use an interactive destination prompt for copy run start.
        if re.search(r"Destination filename.*\?", output, re.I):
            output += connection.send_command_timing("\n", read_timeout=timeout, strip_prompt=False, strip_command=False)
        return output
    return connection.send_command(command, read_timeout=timeout, strip_prompt=False, strip_command=False)


def execute_device(host: str, commands: list[str], args: argparse.Namespace, filename: str) -> DeviceResult:
    start = time.monotonic()
    result = DeviceResult(host=host, filename=filename)
    params = {
        "device_type": args.device_type, "host": host, "username": args.user,
        "password": args.password, "conn_timeout": args.conn_timeout,
        "auth_timeout": args.conn_timeout, "banner_timeout": args.conn_timeout,
        "timeout": args.conn_timeout,
        "secret": args.secret or args.password,
    }
    conn = None
    try:
        for attempt in range(args.retries + 1):
            try:
                conn = ConnectHandler(**params)
                break
            except NetmikoAuthenticationException as exc:
                result.status, result.error = "AUTH FAILED", str(exc).splitlines()[0]
                _LOG.error("%s | Authentication failed", host)
                return result
            except (NetmikoTimeoutException, OSError, EOFError) as exc:
                if attempt >= args.retries:
                    result.status, result.error = "CONNECTION FAILED", str(exc).splitlines()[0]
                    _LOG.error("%s | Connection failed after %s attempts: %s", host, attempt + 1, result.error)
                    return result
                delay = min(2 ** attempt, 10)
                _LOG.warning("%s | Connection retry %s after %s: %s", host, attempt + 1, type(exc).__name__, str(exc).splitlines()[0])
                time.sleep(delay)
        assert conn is not None
        _LOG.info("%s | SSH connected", host)
        # Use privileged EXEC for 'wr' and other commands requiring enable.
        if args.device_type.startswith('cisco') and not conn.check_enable_mode():
            try:
                conn.enable()
            except Exception as exc:
                result.status, result.error = "ENABLE FAILED", str(exc).splitlines()[0]
                _LOG.error("%s | Enable mode failed: %s", host, result.error)
                return result
        if args.mode == 'config':
            output = conn.send_config_set(commands, read_timeout=args.timeout, error_pattern=r"% (?:Invalid|Error|Failed)")
            bad = is_error_output(output, False)
            result.results.append(CommandResult(command='<config batch>', status='FAILED' if bad else 'PASS', output=output,
                                                error='Device reported configuration error' if bad else ''))
        else:
            for command in commands:
                cmdstart = time.monotonic()
                try:
                    output = run_command(conn, command, args.timeout)
                    bad = is_error_output(output, is_write_command(command))
                    status = 'FAILED' if bad else 'PASS'
                    error = 'Device reported error or missing [OK] for write memory' if bad else ''
                    result.results.append(CommandResult(command, status, output, error, time.monotonic() - cmdstart))
                    _LOG.log(logging.ERROR if bad else logging.INFO, "%s | %s | %s", host, command, status)
                except Exception as exc:
                    error = f"{type(exc).__name__}: {str(exc).splitlines()[0]}"
                    result.results.append(CommandResult(command, 'FAILED', '', error, time.monotonic() - cmdstart))
                    _LOG.error("%s | %s | %s", host, command, error)
                    # After command timeout, the channel may be unsynchronized: stop this device.
                    break
        passed = sum(r.status == 'PASS' for r in result.results)
        result.status = 'PASS' if passed == len(commands if args.mode == 'exec' else [1]) else ('PARTIAL' if passed else 'FAILED')
    except Exception as exc:
        result.status, result.error = 'FAILED', f"{type(exc).__name__}: {str(exc).splitlines()[0]}"
        _LOG.exception("%s | Unhandled device failure", host)
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:
                pass
        result.duration = time.monotonic() - start
    return result


def save_device(path: Path, result: DeviceResult, run_started: str, overwrite: bool) -> None:
    mode = 'w' if overwrite else 'x'
    with path.open(mode, encoding='utf-8') as fh:
        fh.write(f"NET COMMAND RUNNER v{VERSION}\nHost: {result.host}\nRun started: {run_started}\nStatus: {result.status}\n\n")
        for entry in result.results:
            fh.write('=' * 75 + f"\nCOMMAND: {entry.command}\nSTATUS: {entry.status}\n" + '-' * 75 + '\n')
            fh.write(entry.output.rstrip() + '\n')
            if entry.error:
                fh.write(f"ERROR: {entry.error}\n")
            fh.write('\n')
        if result.error:
            fh.write(f"DEVICE ERROR: {result.error}\n")


def main() -> int:
    args = parse_args()
    now = datetime.now()
    stamp = now.strftime('%Y%m%d_%H%M%S')
    run_started = now.strftime('%Y-%m-%d %H:%M:%S')
    try:
        hosts = [args.host] if args.host else read_lines(args.host_file, 'host file')
        hosts = list(dict.fromkeys(hosts))
        commands = read_lines(args.command_file, 'command file')
        filenames = {host: filename_for(host, args, stamp) for host in hosts}
        if len(set(name.casefold() for name in filenames.values())) != len(filenames):
            raise ValueError('Output filenames collide; choose unique hostnames/prefixes')
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print('=' * 72 + f"\n{'NET COMMAND RUNNER':^72}\n{'Version ' + VERSION:^72}\n" + '=' * 72)
    print(f"Devices: {len(hosts)} | Commands: {len(commands)} | Mode: {args.mode} | Workers: {args.workers}")
    if args.dry_run:
        print('\nDRY RUN - No SSH connections or files will be created.\n')
        for host in hosts:
            print(f"{host} -> {filenames[host]}")
        print('\nCommands:\n' + '\n'.join(f"  {command}" for command in commands))
        return 0
    if args.mode == 'config' and not args.yes:
        response = input(f"WARNING: Configure {len(hosts)} devices? Type YES to continue: ").strip()
        if response != 'YES':
            print('Cancelled.')
            return 1
    if not args.user:
        args.user = input('SSH Username: ').strip()
    if not args.password:
        args.password = getpass.getpass('SSH Password: ')
    if not args.user or not args.password:
        print('ERROR: SSH username and password are required.', file=sys.stderr)
        return 2

    root = args.output
    result_dir, log_dir = root / 'Results', root / 'Logs'
    result_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    summary_path = root / 'summary.csv'
    if not args.overwrite:
        collisions = [str(result_dir / filename) for filename in filenames.values() if (result_dir / filename).exists()]
        if summary_path.exists():
            collisions.append(str(summary_path))
        if collisions:
            print('ERROR: Output already exists. Use --overwrite, --timestamp or a different -o directory:', file=sys.stderr)
            for path in collisions[:10]:
                print('  ' + path, file=sys.stderr)
            return 2
    log_file = log_dir / f"NetCommandRunner_{stamp}.log"
    if log_file.exists():
        log_file = log_dir / f"NetCommandRunner_{stamp}_{time.time_ns() % 1000000:06d}.log"
    logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-7s | %(threadName)s | %(message)s',
                        handlers=[logging.FileHandler(log_file, encoding='utf-8')], force=True)
    _LOG.info('NetCommandRunner v%s | Started | Devices=%s | Mode=%s', VERSION, len(hosts), args.mode)
    completed: list[DeviceResult] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(execute_device, host, commands, args, filenames[host]): host for host in hosts}
        for future in as_completed(futures):
            host = futures[future]
            try:
                item = future.result()
            except Exception as exc:
                item = DeviceResult(host=host, filename=filenames[host], status='FAILED', error=str(exc))
                _LOG.exception('%s | Unexpected worker exception', host)
            completed.append(item)
            try:
                save_device(result_dir / item.filename, item, run_started, args.overwrite)
            except OSError as exc:
                item.status = 'OUTPUT FAILED'
                item.error = f"Cannot save device output: {exc}"
                _LOG.error('%s | %s', host, item.error)
            print(f"{item.host:<30} {item.status:<18} {len(item.results):>3} command result(s) | {item.duration:.1f}s")
    order = {host: idx for idx, host in enumerate(hosts)}
    completed.sort(key=lambda r: order[r.host])
    try:
        with summary_path.open('w' if args.overwrite else 'x', newline='', encoding='utf-8-sig') as stream:
            writer = csv.writer(stream)
            writer.writerow(['Host', 'Status', 'Commands', 'Successful', 'Failed', 'Execution_Time_s', 'Output_File', 'Error'])
            for entry in completed:
                passed = sum(cmd.status == 'PASS' for cmd in entry.results)
                failed = len(commands) - passed if args.mode == 'exec' else int(passed != 1)
                command_error = next((cmd.error for cmd in entry.results if cmd.error), '')
                writer.writerow([entry.host, entry.status, len(commands) if args.mode == 'exec' else 1,
                                 passed, failed, f'{entry.duration:.2f}', entry.filename, entry.error or command_error])
    except OSError as exc:
        _LOG.error('Unable to save summary: %s', exc)
        print(f'ERROR: Unable to save summary: {exc}', file=sys.stderr)
        return 2
    passed = sum(r.status == 'PASS' for r in completed)
    print(f"\nCompleted: {passed}/{len(completed)} PASS | Results: {result_dir} | Summary: {summary_path} | Log: {log_file}")
    _LOG.info('Completed: %s/%s PASS', passed, len(completed))
    return 0 if passed == len(completed) else 1

if __name__ == '__main__':
    sys.exit(main())
