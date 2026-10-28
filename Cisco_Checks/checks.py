#!/usr/bin/env python3
"""Cisco IOS-XE PRE/POST command collection tool.

Version: 2.1.0
Python: 3.10+
Dependencies: netmiko, rich

This release intentionally does not generate diffs or parse JSON.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from getpass import getpass
from pathlib import Path
from typing import Literal

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TaskProgressColumn

VERSION = "2.1.0"
DEVICE_TYPE = "cisco_xe"
DEFAULT_WORKERS = 20
DEFAULT_COMMAND_FILE = "cmd.txt"
CONNECTION_TIMEOUT = 20
AUTH_TIMEOUT = 30
BANNER_TIMEOUT = 30
COMMAND_READ_TIMEOUT = 120
BANNER = "CISCO PRE / POST CHECKS"
FILE_HEADER = "=" * 70
COMMAND_SEPARATOR = "#" * 70
console = Console()


# ---------------------------------------------------------------------------
# DATA MODEL
# ---------------------------------------------------------------------------
@dataclass
class DeviceResult:
    target: str
    hostname: str = ""
    status: Literal["Success", "Failed"] = "Failed"
    reason: str = ""
    file_path: Path | None = None
    command_failures: list[str] = field(default_factory=list)
    backup_path: Path | None = None
    backup_error: str = ""


# ---------------------------------------------------------------------------
# CLI AND INTERACTIVE PROMPTS
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Cisco_Pre_Post_Checks.py",
        add_help=False,  # -h is intentionally reserved for --host
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Cisco IOS-XE PRE/POST command collection via SSH.\n"
            "Missing arguments are requested interactively.\n"
            "PRE/POST collection only: no diffs or JSON comparisons."
        ),
        epilog=(
            "EXAMPLES:\n"
            "  Interactive:\n"
            "    python Cisco_Pre_Post_Checks.py\n\n"
            "  PRE check on one switch:\n"
            "    python Cisco_Pre_Post_Checks.py --pre -h SW01 -u admin\n\n"
            "  POST check using hosts.txt:\n"
            "    python Cisco_Pre_Post_Checks.py --post -hf hosts.txt -u admin\n\n"
            "  Custom commands and output folder:\n"
            "    python Cisco_Pre_Post_Checks.py --pre -hf hosts.txt -cf cmd.txt -o Upgrade_Cat9k -u admin\n\n"
            "  Collect running-config backup during PRE:\n"
            "    python Cisco_Pre_Post_Checks.py --pre -hf hosts.txt -u admin -b\n\n"
            "  Collect running-config backup during POST:\n"
            "    python Cisco_Pre_Post_Checks.py --post -h SW01 -u admin --backup\n\n"
            "  Explicit credentials and concurrency:\n"
            "    python Cisco_Pre_Post_Checks.py --post -h SW01 -cf cmd.txt -u admin -p secret -w 20\n\n"
            "  HELP: --help (note: -h means --host, not help)\n"
            "  DEFAULT OUTPUT: DD-MMM-YYYY/Pre_Checks or Post_Checks\n"
            "  LOGS: DD-MMM-YYYY/Logs/"
        ),
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--pre", action="store_true", help="Collect PRE-CHECK outputs")
    modes.add_argument("--post", action="store_true", help="Collect POST-CHECK outputs")
    hosts = parser.add_mutually_exclusive_group()
    hosts.add_argument("-h", "--host", metavar="HOST", help="Single device hostname or IP")
    hosts.add_argument("-hf", "--host_file", metavar="FILE", help="File with one host per line")
    parser.add_argument("-cf", "--cmd", metavar="FILE", help="Commands file (prompt; default: cmd.txt)")
    parser.add_argument("-u", "--username", metavar="USER", help="SSH username")
    parser.add_argument("-p", "--password", metavar="PASS", help="SSH password (prefer secure prompt)")
    parser.add_argument("-o", "--output", metavar="FOLDER", help="Output root (default: DD-MMM-YYYY)")
    parser.add_argument("-b", "--backup", action="store_true",
                        help="Save show running-config to PRE/POST Backups/ (requires privilege)")
    parser.add_argument("-w", "--workers", metavar="N", type=int, default=DEFAULT_WORKERS,
                        help=f"Concurrent sessions (default: {DEFAULT_WORKERS})")
    parser.add_argument("--help", action="help", help="Display help and examples")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    return args


def ask_required(label: str, default: str | None = None) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        value = input(f"{label}{suffix}: ").strip().strip('"').strip("'")
        if value:
            return value
        if default:
            return default
        console.print("[red]A value is required.[/red]")


def ask_mode() -> str:
    while True:
        mode = ask_required("Execution Type (pre/post)").lower()
        if mode in {"pre", "post"}:
            return mode
        console.print("[red]Enter pre or post.[/red]")


def read_items(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def unique_hosts(hosts: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        key = host.casefold()
        if key not in seen:
            result.append(host)
            seen.add(key)
    return result


def resolve_hosts(args: argparse.Namespace) -> list[str]:
    if args.host:
        return [args.host]
    if args.host_file:
        return unique_hosts(read_items(Path(args.host_file).expanduser()))
    while True:
        choice = ask_required("Host or Host File (host/file)")
        choice_key = choice.lower()
        if choice_key in {"host", "h"}:
            return [ask_required("Host")]
        if choice_key in {"file", "f", "host_file", "hf"}:
            file_path = Path(ask_required("Host File")).expanduser()
            if not file_path.is_file():
                console.print(f"[red]Host file not found: {file_path}[/red]")
                continue
            hosts = unique_hosts(read_items(file_path))
            if hosts:
                return hosts
            console.print("[red]Host file has no valid hosts.[/red]")
            continue
        # Convenience: a hostname or existing file path may be entered directly.
        if choice:
            candidate = Path(choice).expanduser()
            if candidate.is_file():
                hosts = unique_hosts(read_items(candidate))
                if hosts:
                    return hosts
                console.print("[red]Host file has no valid hosts.[/red]")
                continue
            if any(sep in choice for sep in ("/", "\\")) or choice.endswith(".txt"):
                console.print(f"[red]Host file not found: {choice}[/red]")
                continue
            return [choice]


def safe_filename(host: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", host).strip("._") or "unknown_device"


def extract_hostname(prompt: str, fallback: str) -> str:
    value = prompt.strip().rstrip("#>").strip()
    return value.split("(", 1)[0].strip() or fallback


def classify_error(exc: Exception) -> str:
    error = str(exc).lower()
    if any(x in error for x in ("getaddrinfo", "name or service not known", "dns failure",
                                    "nodename nor servname", "not resolvable")):
        return "DNS Failure"
    if isinstance(exc, NetmikoAuthenticationException):
        return "Authentication Failure"
    if isinstance(exc, NetmikoTimeoutException):
        return "SSH/Connection Timeout"
    if isinstance(exc, OSError):
        return "Network/OS Error"
    return f"{type(exc).__name__}: {str(exc).splitlines()[0][:180]}"


def validate_output_filenames(hosts: list[str]) -> None:
    seen: dict[str, str] = {}
    for host in hosts:
        file_key = safe_filename(host).casefold()
        if file_key in seen:
            raise ValueError(f"Output filename collision between {seen[file_key]!r} and {host!r}")
        seen[file_key] = host


def confirm_overwrite(directory: Path, mode: str) -> bool:
    # Include backups nested under the selected mode folder when checking for prior results.
    existing = [p for p in directory.rglob("*") if p.is_file()] if directory.is_dir() else []
    if not existing:
        return True
    console.print(f"\n[yellow][WARNING] Existing {mode.upper()}-CHECK results detected.[/yellow]")
    console.print(f"    Directory : {directory}")
    console.print(f"    Files     : {len(existing)}")
    while True:
        answer = input(f"    Overwrite existing {mode.upper()}-CHECK results? (Y/N): ").strip().lower()
        if answer in {"y", "yes", "s", "si", "sí"}:
            return True
        if answer in {"n", "no"}:
            return False
        console.print("[red]Please enter Y or N.[/red]")


# ---------------------------------------------------------------------------
# LOGGING AND OUTPUT FORMATTING
# ---------------------------------------------------------------------------
def create_logger(log_dir: Path, mode: str) -> tuple[logging.Logger, Path]:
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    log_path = log_dir / f"{mode.upper()}_{timestamp}.log"
    logger = logging.getLogger(f"cisco_checks.{timestamp}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger, log_path


def output_header(target: str, hostname: str, mode: str) -> str:
    return (f"{FILE_HEADER}\nCISCO IOS-XE {mode.upper()}-CHECK\n{FILE_HEADER}\n"
            f"RUN_TIMESTAMP: {datetime.now().astimezone().isoformat(timespec='seconds')}\n"
            f"TARGET: {target}\nHOSTNAME: {hostname}\nEXECUTION_TYPE: {mode.upper()}\n"
            f"{FILE_HEADER}\n\n")


def command_block(command: str, output: str) -> str:
    return f"{COMMAND_SEPARATOR}\nCOMMAND: {command}\n{COMMAND_SEPARATOR}\n\n{output.rstrip()}\n\n"


# ---------------------------------------------------------------------------
# SSH COLLECTION WORKER
# ---------------------------------------------------------------------------
def collect_device(target: str, username: str, password: str,
                   commands: list[str], mode: str, output_dir: Path,
                   backup: bool = False) -> DeviceResult:
    result = DeviceResult(target=target)
    conn = None
    try:
        conn = ConnectHandler(
            device_type=DEVICE_TYPE,
            host=target,
            username=username,
            password=password,
            conn_timeout=CONNECTION_TIMEOUT,
            auth_timeout=AUTH_TIMEOUT,
            banner_timeout=BANNER_TIMEOUT,
            fast_cli=False,
        )
        result.hostname = extract_hostname(conn.find_prompt(), target)
        sections: list[str] = []
        for command in commands:
            try:
                output = conn.send_command(command, read_timeout=COMMAND_READ_TIMEOUT,
                                           strip_prompt=True, strip_command=True)
                # CLI error output does not necessarily raise a Netmiko exception.
                if re.search(r"(?im)^\s*(?:% (?:Invalid input|Incomplete command|Ambiguous command|Error)|"
                             r"%Error)\b", str(output)):
                    result.command_failures.append(f"{command}: Device CLI error")
            except Exception as exc:
                result.command_failures.append(f"{command}: {type(exc).__name__}")
                output = f"[COMMAND ERROR] {type(exc).__name__}: {exc}"
            sections.append(command_block(command, str(output)))
        if backup:
            backup_dir = output_dir / "Backups"
            backup_path = backup_dir / f"{safe_filename(target)}_{mode.upper()}_Running_Config.txt"
            try:
                running_config = conn.send_command(
                    "show running-config", read_timeout=COMMAND_READ_TIMEOUT,
                    strip_prompt=True, strip_command=True,
                )
                if not running_config.strip() or re.search(
                    r"(?im)^\s*%\s*(?:Invalid input|Incomplete command|Ambiguous command|Error|Authorization failed|Access denied)",
                    running_config,
                ):
                    raise ValueError("Device did not return a valid running configuration")
                backup_dir.mkdir(parents=True, exist_ok=True)
                backup_content = (
                    f"{FILE_HEADER}\nCISCO IOS-XE RUNNING-CONFIG BACKUP\n{FILE_HEADER}\n"
                    f"TARGET: {target}\nHOSTNAME: {result.hostname}\n"
                    f"EXECUTION_TYPE: {mode.upper()}\n"
                    f"TIMESTAMP: {datetime.now().astimezone().isoformat(timespec='seconds')}\n"
                    f"{FILE_HEADER}\n\n{running_config.rstrip()}\n"
                )
                backup_tmp = backup_dir / f".{safe_filename(target)}_{os.getpid()}_{time.monotonic_ns()}.tmp"
                try:
                    backup_tmp.write_text(backup_content, encoding="utf-8", errors="replace")
                    os.replace(backup_tmp, backup_path)
                finally:
                    backup_tmp.unlink(missing_ok=True)
                result.backup_path = backup_path
            except Exception as exc:
                result.backup_error = f"{type(exc).__name__}: {str(exc).splitlines()[0][:180]}"
        path = output_dir / f"{safe_filename(target)}_{mode.upper()}.txt"
        content = output_header(target, result.hostname, mode) + "".join(sections)
        # Atomic replacement: never leave a partially written result file.
        tmp = output_dir / f".{safe_filename(target)}_{mode.upper()}_{os.getpid()}_{time.monotonic_ns()}.tmp"
        try:
            tmp.write_text(content, encoding="utf-8", errors="replace")
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)
        result.file_path = path
        if result.backup_error:
            result.reason = "Running-config backup failed"
        elif result.command_failures:
            result.reason = f"{len(result.command_failures)} command(s) failed"
        else:
            result.status = "Success"
            result.reason = "Completed"
    except Exception as exc:
        result.reason = classify_error(exc)
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:
                pass
    return result


# ---------------------------------------------------------------------------
# MAIN EXECUTION
# ---------------------------------------------------------------------------
def main() -> int:
    args = parse_args()
    console.print(FILE_HEADER)
    console.print(f"{BANNER:^{len(FILE_HEADER)}}")
    console.print(FILE_HEADER)
    console.print()

    mode = "pre" if args.pre else "post" if args.post else None
    hosts = resolve_hosts(args)
    if not hosts:
        raise ValueError("No valid hosts were provided")
    validate_output_filenames(hosts)

    cmd_arg = args.cmd or ask_required("Commands File", DEFAULT_COMMAND_FILE)
    cmd_path = Path(cmd_arg).expanduser()
    if not cmd_path.is_file():
        raise FileNotFoundError(f"Commands file not found: {cmd_path}")
    commands = read_items(cmd_path)
    if not commands:
        raise ValueError(f"Commands file is empty: {cmd_path}")
    username = args.username or ask_required("Username")
    password = args.password if args.password is not None else getpass("Password: ")
    if not password:
        raise ValueError("Password cannot be blank")
    if mode is None:
        mode = ask_mode()
    root = Path(args.output).expanduser() if args.output else Path(datetime.now().strftime("%d-%b-%Y").upper())
    output_dir = root / ("Pre_Checks" if mode == "pre" else "Post_Checks")

    console.print("\n[+] Validating input...")
    console.print(f"    Hosts          : {len(hosts)} devices")
    console.print(f"    Commands       : {len(commands)} commands")
    console.print(f"    Execution Type : {mode.upper()}")
    console.print(f"    Output Folder  : {root}")

    if not confirm_overwrite(output_dir, mode):
        console.print("\n[+] Execution cancelled. Existing results were preserved.")
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)
    logger, log_path = create_logger(root / "Logs", mode)
    logger.info(FILE_HEADER)
    logger.info("CISCO PRE / POST CHECKS")
    logger.info("Execution Type : %s", mode.upper())
    logger.info("Start Time     : %s", datetime.now().isoformat(timespec="seconds"))
    logger.info("Username       : %s", username)
    logger.info("Devices        : %d", len(hosts))
    logger.info("Commands File  : %s", cmd_path)
    logger.info("Workers        : %d", args.workers)
    logger.info("Backup Enabled : %s", "Yes" if args.backup else "No")
    logger.info(FILE_HEADER)

    start = time.monotonic()
    results: list[DeviceResult] = []
    console.print("\n[+] Connecting to Cisco IOS-XE devices...\n")
    try:
        with Progress(
            TextColumn("Cisco IOS-XE checks"), BarColumn(bar_width=40),
            TaskProgressColumn(), TextColumn("{task.completed}/{task.total}"),
            console=console, transient=False,
        ) as progress:
            task = progress.add_task("checks", total=len(hosts))
            with ThreadPoolExecutor(max_workers=min(args.workers, len(hosts))) as pool:
                futures = {pool.submit(collect_device, host, username, password,
                                       commands, mode, output_dir, args.backup): host for host in hosts}
                for index, future in enumerate(as_completed(futures), start=1):
                    host = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = DeviceResult(target=host, reason=f"Worker Error: {type(exc).__name__}")
                    results.append(result)
                    logger.info("[%d/%d] %s: %s (%s)", index, len(hosts),
                                host, result.status, result.reason)
                    for failure in result.command_failures:
                        logger.info("    COMMAND FAILURE: %s", failure)
                    if result.backup_path:
                        logger.info("    BACKUP SAVED: %s", result.backup_path)
                    if result.backup_error:
                        logger.info("    BACKUP FAILURE: %s", result.backup_error)
                    progress.advance(task)
    finally:
        password = ""

    elapsed = int(time.monotonic() - start)
    passed = sum(r.status == "Success" for r in results)
    failed = len(results) - passed
    duration = f"{elapsed // 3600:02}:{(elapsed % 3600) // 60:02}:{elapsed % 60:02}"
    logger.info(FILE_HEADER)
    logger.info("Devices Processed : %d", len(results))
    logger.info("Successful        : %d", passed)
    logger.info("Failed            : %d", failed)
    logger.info("Execution Time    : %s", duration)
    logger.info(FILE_HEADER)
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)

    console.print(f"\n{FILE_HEADER}")
    console.print("Execution Completed")
    console.print(FILE_HEADER)
    console.print(f"\nDevices Processed : {len(results)}")
    console.print(f"Successful        : [green]{passed}[/green]")
    console.print(f"Failed            : [{'red' if failed else 'green'}]{failed}[/]")
    console.print(f"Execution Time    : {duration}")
    console.print(f"\nResults : {output_dir}/")
    if args.backup:
        console.print(f"Backups : {output_dir / 'Backups'}/")
    console.print(f"Logs    : {log_path.parent}/")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Execution interrupted.[/yellow]")
        sys.exit(130)
    except (OSError, ValueError) as exc:
        console.print(f"\n[red]ERROR: {exc}[/red]")
        sys.exit(2)
