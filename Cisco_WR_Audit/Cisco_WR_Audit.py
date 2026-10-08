#!/usr/bin/env python3
"""Cisco Catalyst 9000 IOS-XE write-memory audit.

Requirements:
    pip install netmiko rich

Inputs:
    hosts.txt: one hostname or IP per line; blank lines and # comments ignored.

Behavior:
    - Connects over SSH using Netmiko.
    - Detects user EXEC vs privileged EXEC and enters enable if necessary.
    - Reads IOS-XE version, runs `write memory`, and checks startup-config readability.
    - Runs batches of up to 20 switches concurrently, with a 30-second delay
      BETWEEN batches (defaults; configurable).
    - Writes a detailed CSV (including Failure Reason and raw WR output) while
      printing only Hostname / Version / WR Status.

NOTE: Reading startup-config confirms access/readability, but is not a byte-for-byte
comparison with running-config. PASS also requires a positive [OK] from write memory.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from rich.console import Console
from rich.table import Table

console = Console()

# ------------------------------- Parsing ---------------------------------
VERSION_PATTERNS = (
    re.compile(r"Cisco IOS XE Software, Version\s+([^,\s]+)", re.I),
    re.compile(r"Cisco IOS Software.*?Version\s+([^,\s]+)", re.I | re.S),
)
ERROR_PATTERN = re.compile(
    r"(?:%\s*Error|\bfile open failed\b|\bnot enough space\b|"
    r"\bno space left\b|\bpermission denied\b|\bfailed\b|"
    r"\bI/O error\b|\bunable to\b|\breadonly\b|\bread-only\b)",
    re.I,
)
SUCCESS_PATTERN = re.compile(r"\[OK\]", re.I)
CSV_HEADERS = ["Hostname", "Version", "Status of WR", "Failure Reason", "Initial Mode",
               "Final Mode", "WR Output", "Startup Config Check", "Error"]


def classify_failure(status: str, error: str, wr_output: str = "") -> str:
    """Classify failures without replacing the complete original Cisco response."""
    if status == "PASS":
        return "NONE"
    if status == "ENABLE ERROR":
        return "ENABLE ERROR"
    if status == "AUTH ERROR":
        return "AUTH ERROR"
    if status == "SSH ERROR":
        return "SSH ERROR"
    combined = f"{wr_output} {error}"
    if re.search(r"not enough space|no space left|insufficient (?:disk )?space", combined, re.I):
        return "NO SPACE"
    if re.search(r"nvram|startup-config file open failed|file open failed|I/O error", combined, re.I):
        return "NVRAM / FILE ERROR"
    if re.search(r"permission denied|read.only", combined, re.I):
        return "PERMISSION ERROR"
    if re.search(r"startup-config|no version line", combined, re.I):
        return "STARTUP VERIFY ERROR"
    if status == "UNVERIFIED":
        return "WR UNVERIFIED"
    return "OTHER ERROR"



@dataclass
class Result:
    hostname: str
    version: str = "N/A"
    status: str = "ERROR"
    failure_reason: str = "OTHER ERROR"
    initial_mode: str = "UNKNOWN"
    final_mode: str = "UNKNOWN"
    wr_output: str = ""
    startup_check: str = "NOT RUN"
    error: str = ""

    def csv_row(self) -> dict[str, str]:
        self.failure_reason = classify_failure(self.status, self.error, self.wr_output)
        vals = asdict(self)
        return dict(zip(CSV_HEADERS, vals.values()))


def single_line(value: str) -> str:
    """Compact full device replies into a CSV-friendly single line."""
    return " | ".join(s.strip() for s in value.splitlines() if s.strip())


def find_version(output: str) -> str:
    for regex in VERSION_PATTERNS:
        match = regex.search(output)
        if match:
            return match.group(1)
    return "UNKNOWN"


def load_hosts(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"Hosts file not found: {path}")
    hosts: list[str] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        host = raw.split("#", 1)[0].strip()
        if host and host.lower() not in seen:
            hosts.append(host)
            seen.add(host.lower())
    if not hosts:
        raise ValueError("No valid devices found in hosts file")
    return hosts


# ----------------------------- Device audit -------------------------------
def audit(host: str, username: str, password: str, secret: str,
          conn_timeout: int, cmd_timeout: int) -> Result:
    result = Result(hostname=host)
    conn = None
    try:
        conn = ConnectHandler(
            device_type="cisco_ios", host=host, username=username,
            password=password, secret=secret,
            conn_timeout=conn_timeout, auth_timeout=conn_timeout,
            banner_timeout=conn_timeout, timeout=cmd_timeout,
            fast_cli=False,
        )

        # Determine privilege state BEFORE running a save command.
        already_enabled = conn.check_enable_mode()
        result.initial_mode = "PRIVILEGED" if already_enabled else "USER EXEC"
        if not already_enabled:
            if not secret:
                result.status = "ENABLE ERROR"
                result.error = "Enable password required but not provided"
                return result
            try:
                conn.enable()
            except Exception as exc:
                result.status = "ENABLE ERROR"
                result.error = f"Unable to enter enable mode: {exc}"
                return result
        if not conn.check_enable_mode():
            result.status = "ENABLE ERROR"
            result.error = "Device did not enter privileged EXEC mode"
            return result
        result.final_mode = "PRIVILEGED"

        # Get the actual software release.
        version_output = conn.send_command("show version", read_timeout=cmd_timeout)
        result.version = find_version(version_output)

        # Preserve original device output (including file open / space errors).
        raw = conn.send_command_timing(
            "write memory", read_timeout=cmd_timeout,
            strip_prompt=False, strip_command=False,
        )
        # Avoid executing a confirmation without explicit device-specific support.
        result.wr_output = single_line(raw)

        # Failure must win over [OK] if mixed messages appear.
        match = ERROR_PATTERN.search(raw)
        if match:
            result.status = "FAIL"
            result.error = result.wr_output
            return result
        if not SUCCESS_PATTERN.search(raw):
            result.status = "UNVERIFIED"
            result.error = "No [OK] confirmation from write memory; check WR Output"
            return result

        # Sanity check: startup-config can be read after successful save.
        startup = conn.send_command(
            "show startup-config | include ^version", read_timeout=cmd_timeout
        )
        if ERROR_PATTERN.search(startup) or re.search(r"%\s*(Invalid input|Ambiguous command)", startup, re.I):
            result.status = "FAIL"
            result.startup_check = "ERROR"
            result.error = single_line(startup)
        elif not re.search(r"(?m)^version\s+\S+", startup):
            result.status = "UNVERIFIED"
            result.startup_check = "NOT CONFIRMED"
            result.error = f"No version line found in startup-config: {single_line(startup)}"
        else:
            result.status = "PASS"
            result.startup_check = "READABLE"
        return result

    except NetmikoAuthenticationException as exc:
        result.status = "AUTH ERROR"
        result.error = str(exc)
    except NetmikoTimeoutException as exc:
        result.status = "SSH ERROR"
        result.error = str(exc)
    except (TimeoutError, OSError, ValueError) as exc:
        result.status = "ERROR"
        result.error = f"{type(exc).__name__}: {exc}"
    except Exception as exc:
        result.status = "ERROR"
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:
                pass
    return result


# -------------------------- CLI / batch scheduler -------------------------
def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Catalyst 9K IOS-XE WR audit with batch throttling")
    p.add_argument("--hosts", default="hosts.txt", help="One hostname/IP per line")
    p.add_argument("--output", default="Cisco_WR_Audit.csv", help="Output CSV path")
    p.add_argument("--username", help="SSH username (prompted if omitted)")
    p.add_argument("--batch-size", type=int, default=20, help="Concurrent hosts per batch (default 20)")
    p.add_argument("--batch-delay", type=float, default=30, help="Seconds between batches (default 30)")
    p.add_argument("--conn-timeout", type=int, default=15)
    p.add_argument("--cmd-timeout", type=int, default=45)
    return p


def main() -> int:
    args = parser().parse_args()
    if args.batch_size < 1 or args.batch_delay < 0 or args.conn_timeout < 1 or args.cmd_timeout < 1:
        parser().error("Invalid batch/timeout setting")
    try:
        hosts = load_hosts(Path(args.hosts))
    except (OSError, ValueError) as exc:
        console.print(f"[red]ERROR: {exc}[/red]")
        return 2

    username = args.username or input("SSH Username: ").strip()
    if not username:
        console.print("[red]ERROR: Username is required[/red]")
        return 2
    password = getpass.getpass("SSH Password: ")
    secret = getpass.getpass("Enable Password (press Enter if same as SSH / not needed): ") or password

    console.print("\n[bold]CISCO WR AUDIT[/bold]")
    console.print(f"Devices: {len(hosts)} | Batch size: {args.batch_size} | Pause: {args.batch_delay:g}s")
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[Result] = []

    # One batch completes fully before the next begins. No sleep after the last batch.
    total_batches = (len(hosts) + args.batch_size - 1) // args.batch_size
    for offset in range(0, len(hosts), args.batch_size):
        batch_no = offset // args.batch_size + 1
        batch = hosts[offset:offset + args.batch_size]
        console.print(f"[cyan]Batch {batch_no}/{total_batches}: {len(batch)} device(s)[/cyan]")
        batch_results: dict[str, Result] = {}
        with ThreadPoolExecutor(max_workers=args.batch_size) as pool:
            future_map = {
                pool.submit(audit, h, username, password, secret, args.conn_timeout, args.cmd_timeout): h
                for h in batch
            }
            for future in as_completed(future_map):
                host = future_map[future]
                try:
                    batch_results[host] = future.result()
                except Exception as exc:
                    batch_results[host] = Result(hostname=host, status="ERROR", error=str(exc))
        rows.extend(batch_results[h] for h in batch)
        # Save partial progress after EACH batch, including device error text.
        with output_path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_HEADERS)
            writer.writeheader()
            writer.writerows(r.csv_row() for r in rows)
        if batch_no < total_batches:
            console.print(f"[dim]Batch complete. Pausing {args.batch_delay:g}s before next batch...[/dim]")
            time.sleep(args.batch_delay)

    table = Table(title="Cisco WR Audit")
    table.add_column("Hostname")
    table.add_column("Version")
    table.add_column("Status of WR")
    for r in rows:
        color = "green" if r.status == "PASS" else "red"
        table.add_row(r.hostname, r.version, f"[{color}]{r.status}[/{color}]")
    console.print(table)
    console.print(f"\nCSV saved: [bold]{output_path.resolve()}[/bold]")
    console.print(f"PASS: {sum(r.status == 'PASS' for r in rows)} | Non-PASS: {sum(r.status != 'PASS' for r in rows)}")
    return 0 if all(r.status == "PASS" for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
