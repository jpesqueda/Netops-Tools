#!/usr/bin/env python3
"""Cisco Catalyst 9000 IOS-XE write-memory audit.

Version: 1.2.0

Requirements:
    pip install netmiko rich

Inputs:
    -ho/--host: one hostname/IP; -hf/--host-file: path with one device per line.
    If neither option is passed, select the source interactively.

Behavior:
    - Connects over SSH using Netmiko.
    - Uses SSH session privileges as-is; does not enter or check enable mode.
    - Reads IOS-XE version, runs `write memory`, captures prompt/confirmation, and checks startup-config readability.
    - Runs batches of up to 20 switches concurrently, with a 30-second delay
      BETWEEN batches (defaults; configurable).
    - Writes a detailed CSV (including Failure Reason and raw WR output) while
      printing only Hostname / Model / Version / WR Status.

NOTE: Reading startup-config confirms readability, not that the running-config was
saved. PASS requires explicit successful write-memory output.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from rich.console import Console
from rich.table import Table

__version__ = "1.2.0"

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
SUCCESS_PATTERN = re.compile(r"\[\s*OK\s*\]|\b(?:copy complete|configuration saved successfully)\b", re.I)
CSV_HEADERS = ["Hostname", "Model", "Version", "Status of WR", "Failure Reason",
               "WR Output", "Startup Config Check", "Error"]


def classify_failure(status: str, error: str, wr_output: str = "") -> str:
    """Classify failures without replacing the complete original Cisco response."""
    if status == "PASS":
        return "NONE"
    if status == "AUTH ERROR":
        return "AUTH ERROR"
    if status == "SSH ERROR":
        return "SSH ERROR"
    if status == "PRIVILEGE ERROR":
        return "PRIVILEGE ERROR"
    if status == "WR TIMEOUT":
        return "WR TIMEOUT"
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
    model: str = "N/A"
    version: str = "N/A"
    status: str = "ERROR"
    failure_reason: str = "OTHER ERROR"
    wr_output: str = ""
    startup_check: str = "NOT RUN"
    error: str = ""

    def csv_row(self) -> dict[str, str]:
        self.failure_reason = classify_failure(self.status, self.error, self.wr_output)
        return {"Hostname": self.hostname, "Model": self.model, "Version": self.version,
                "Status of WR": self.status, "Failure Reason": self.failure_reason,
                "WR Output": self.wr_output, "Startup Config Check": self.startup_check,
                "Error": self.error}


def single_line(value: str) -> str:
    """Compact full device replies into a CSV-friendly single line."""
    return " | ".join(s.strip() for s in value.splitlines() if s.strip())


def find_version(output: str) -> str:
    for regex in VERSION_PATTERNS:
        match = regex.search(output)
        if match:
            return match.group(1)
    return "UNKNOWN"


def find_model(output: str) -> str:
    """Identify Catalyst 9K model from show version (including stack members)."""
    # Common IOS-XE output: Model Number : C9300-48P
    matches = re.findall(r"(?im)^\s*Model Number\s*:\s*(C9\d{3}[\w-]*)", output)
    if matches:
        return ", ".join(dict.fromkeys(m.upper() for m in matches))

    # Hardware description: cisco C9300-48P (X86) processor...
    match = re.search(r"(?im)^\s*cisco\s+(C9\d{3}[\w-]*)\s+\(", output)
    if match:
        return match.group(1).upper()

    # Switch stack table: Switch Ports Model SW Version...
    models = re.findall(r"(?im)^\s*\*?\s*\d+\s+\d+\s+(C9\d{3}[\w-]*)\s+", output)
    if models:
        return ", ".join(dict.fromkeys(m.upper() for m in models))
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
def audit(host: str, username: str, password: str,
          conn_timeout: int, cmd_timeout: int, wr_timeout: int) -> Result:
    result = Result(hostname=host)
    conn = None
    try:
        conn = ConnectHandler(
            device_type="cisco_ios", host=host, username=username,
            password=password,
            use_keys=False, allow_agent=False,
            ssh_strict=False, system_host_keys=False,
            conn_timeout=conn_timeout, auth_timeout=conn_timeout,
            banner_timeout=conn_timeout, timeout=cmd_timeout,
            fast_cli=False,
        )

        # Get the actual software release.
        version_output = conn.send_command("show version", read_timeout=cmd_timeout)
        result.version = find_version(version_output)
        result.model = find_model(version_output)

        # Execute WR ONCE. Keep the full response even when Cisco outputs only
        # "Building configuration...". Waiting for the prompt proves that the
        # command returned; it does NOT itself prove that the write succeeded.
        #
        # A read timeout means unknown device outcome; never blindly retry.
        try:
            prompt = conn.find_prompt().strip()
            # Explicit terminal prompt, including user EXEC or privileged EXEC.
            # With the newline anchor a hostname mentioned in the output cannot
            # cause a false early match.
            expect_prompt = rf"(?m)^{re.escape(prompt)}\s*$"
            raw = conn.send_command(
                "write memory",
                expect_string=expect_prompt,
                read_timeout=wr_timeout,
                strip_prompt=False,
                strip_command=False,
                cmd_verify=False,
            )
            result.wr_output = single_line(raw)
        except Exception as exc:
            if isinstance(exc, (TimeoutError, NetmikoTimeoutException)) or type(exc).__name__ == "ReadTimeout":
                result.status = "WR TIMEOUT"
                result.error = (
                    f"WR did not return to prompt within {wr_timeout}s; "
                    f"write result UNKNOWN; do not retry automatically. "
                    f"{type(exc).__name__}: {exc}"
                )
                return result
            raise

        # Never interpret a real Cisco error as success.
        if re.search(r"(?i)%\s*(invalid input|authorization failed|access denied|privilege)", raw):
            result.status = "PRIVILEGE ERROR"
            result.error = result.wr_output
            return result
        if ERROR_PATTERN.search(raw):
            result.status = "FAIL"
            result.error = result.wr_output
            return result
        # Check startup readability even if IOS-XE omits [OK] in WR output.
        # This check must not promote a missing WR confirmation to PASS.
        try:
            startup = conn.send_command(
                "show startup-config | include ^version", read_timeout=cmd_timeout
            )
            if ERROR_PATTERN.search(startup) or re.search(
                r"%\s*(Invalid input|Ambiguous command|Authorization failed)", startup, re.I
            ):
                result.startup_check = "ERROR"
                result.error = f"Startup read check: {single_line(startup)}"
            elif re.search(r"(?m)^version\s+\S+", startup):
                result.startup_check = "READABLE"
            else:
                result.startup_check = "INCONCLUSIVE"
        except Exception as exc:
            result.startup_check = "ERROR"
            result.error = f"Startup read check failed: {type(exc).__name__}: {exc}"

        if SUCCESS_PATTERN.search(raw):
            result.status = "PASS"
        else:
            result.status = "UNVERIFIED"
            details = "No explicit [OK] returned by WR; command returned to prompt."
            if result.startup_check == "READABLE":
                details += " Startup config is readable, but a successful save is not proven."
            result.error = f"{details} {result.error}".strip()
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
    p = argparse.ArgumentParser(
        description="Catalyst 9K IOS-XE WR audit with batch throttling",
        epilog=("Examples:\n"
                "  python Cisco_WR_Audit.py -ho SW01 -u admin\n"
                "  python Cisco_WR_Audit.py -hf devices.txt -u admin -o results.csv\n"
                "  python Cisco_WR_Audit.py  (interactive prompts)"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sources = p.add_mutually_exclusive_group()
    sources.add_argument("-ho", "--host", help="Single hostname/IP to audit")
    sources.add_argument("-hf", "--host-file", help="Text file with one hostname/IP per line")
    p.add_argument("-u", "--username", help="SSH username (prompted if omitted)")
    p.add_argument("-p", "--password", help="SSH password (securely prompted if omitted)")
    p.add_argument("-o", "--output", default="Cisco_WR_Audit.csv", help="Output CSV path (default: Cisco_WR_Audit.csv)")
    p.add_argument("--batch-size", type=int, default=20, help="Concurrent hosts per batch (default: 20)")
    p.add_argument("--batch-delay", type=float, default=30, help="Seconds between batches (default: 30)")
    p.add_argument("--conn-timeout", type=int, default=15, help="SSH connection timeout (default: 15s)")
    p.add_argument("--cmd-timeout", type=int, default=45, help="Show command timeout (default: 45s)")
    p.add_argument("--wr-timeout", type=int, default=120, help="Write memory timeout (default: 120s)")
    return p


def interactive_hosts() -> list[str]:
    """Ask for a single device or file only when CLI supplied neither."""
    while True:
        source = input("Host or host file? [ho/hf]: ").strip().lower()
        if source in ("ho", "host", "1"):
            host = input("Hostname/IP: ").strip()
            if host:
                return [host]
            console.print("[red]ERROR: Hostname/IP is required[/red]")
        elif source in ("hf", "host-file", "2"):
            path = input("Host file path: ").strip().strip('"')
            if not path:
                console.print("[red]ERROR: File path is required[/red]")
                continue
            try:
                return load_hosts(Path(path))
            except (OSError, ValueError) as exc:
                console.print(f"[red]ERROR: {exc}[/red]")
        else:
            console.print("[yellow]Enter ho for a device or hf for a file.[/yellow]")


def main() -> int:
    args = parser().parse_args()
    if args.batch_size < 1 or args.batch_delay < 0 or args.conn_timeout < 1 or args.cmd_timeout < 1 or args.wr_timeout < 1:
        parser().error("Invalid batch/timeout setting")
    try:
        if args.host:
            hosts = [args.host.strip()]
            if not hosts[0]:
                raise ValueError("Hostname/IP is required")
        elif args.host_file:
            hosts = load_hosts(Path(args.host_file))
        else:
            hosts = interactive_hosts()
    except (OSError, ValueError, EOFError, KeyboardInterrupt) as exc:
        console.print(f"[red]ERROR: {exc}[/red]")
        return 2

    try:
        username = args.username if args.username is not None else input("SSH Username: ").strip()
        if not username.strip():
            console.print("[red]ERROR: Username is required[/red]")
            return 2
        password = args.password if args.password is not None else getpass.getpass("SSH Password: ")
    except (EOFError, KeyboardInterrupt):
        console.print("[red]ERROR: Credential input cancelled[/red]")
        return 2

    console.print(f"\n[bold]CISCO WR AUDIT v{__version__}[/bold]")
    console.print(f"Devices: {len(hosts)} | Batch size: {args.batch_size} | Pause: {args.batch_delay:g}s | WR read timeout: {args.wr_timeout}s")
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
                pool.submit(audit, h, username, password, args.conn_timeout, args.cmd_timeout, args.wr_timeout): h
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
    table.add_column("Model")
    table.add_column("Version")
    table.add_column("Status of WR")
    for r in rows:
        color = "green" if r.status == "PASS" else "red"
        table.add_row(r.hostname, r.model, r.version, f"[{color}]{r.status}[/{color}]")
    console.print(table)
    console.print(f"\nCSV saved: [bold]{output_path.resolve()}[/bold]")
    console.print(f"PASS: {sum(r.status == 'PASS' for r in rows)} | Non-PASS: {sum(r.status != 'PASS' for r in rows)}")
    return 0 if all(r.status == "PASS" for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
