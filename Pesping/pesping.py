#!/usr/bin/env python3

"""PESPING - Concurrent IPv4 scanner and ICMP upgrade monitor.

Version: 1.1.0
Python: 3.10+
Platforms: Windows, Linux, and macOS (system ping command required)

Overview:
    Perform a single ICMP scan or continuously monitor hosts during network
    maintenance. Targets may be supplied as one host, a host file, an inclusive
    IPv4 range, or an IPv4 CIDR subnet. Network probes execute concurrently.

Dependencies:
    Python standard library; optional `colorama` for terminal colors.
    Install the optional dependency with: pip install colorama

Example commands (documentation-only addresses from RFC 5737):
    python pesping.py -ho 192.0.2.10
    python pesping.py -hf hosts.txt --monitor --only-changes
    python pesping.py -r 192.0.2.100-192.0.2.200
    python pesping.py -r 192.0.2.100-200 --show up
    python pesping.py -s 192.0.2.0/24 --show down
    python pesping.py -s 198.51.100.0/26 --monitor --workers 20

Example hosts.txt:
    # Name,IP address (all fictional)
    switch01.example.test,192.0.2.10
    switch02.example.test,192.0.2.11

Operational notes:
    * ICMP success means the target answered ping, not that applications or
      routing protocols have recovered.
    * ICMP failure does not prove that a device is offline; firewalls may
      block or rate-limit echo requests.
    * --max-hosts prevents accidental oversized scans by default.
    * --show filters single-scan output, not continuous monitoring events.
    * Monitoring timestamps and downtime are local process observations.
    * Run scans only on systems and networks you are authorized to test.

Security and privacy:
    All examples use reserved documentation IPv4 ranges (RFC 5737) and
    fictional .test domain names. No production IPs or user credentials
    are embedded in this file. Logs and CSVs contain actual target data
    supplied at runtime; handle generated outputs accordingly.
"""

import argparse
import concurrent.futures
import csv
import datetime as dt
import ipaddress
import math
import os
import platform
import subprocess
import sys
import time
from dataclasses import dataclass

__version__ = "1.1.0"

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    GREEN, RED, CYAN, YELLOW, RESET = Fore.GREEN, Fore.RED, Fore.CYAN, Fore.YELLOW, Style.RESET_ALL
except ImportError:
    GREEN = RED = CYAN = YELLOW = RESET = ""


@dataclass
# Persistent monitoring state for each host.
class DeviceState:
    """Per-target state used for debounced UP/DOWN detection and downtime."""
    state: str = "UNKNOWN"
    fail_streak: int = 0
    success_streak: int = 0
    first_failure: float | None = None
    first_recovery: float | None = None
    down_since: float | None = None
    outages: int = 0
    total_downtime: float = 0.0


# ============================================================================
# TIME FORMATTING AND EXPORT HELPERS
# ============================================================================
def timestamp():
    """Return the current local time formatted for a console event."""
    return dt.datetime.now().strftime("%H:%M:%S")


def full_timestamp():
    """Return the current local date and time for exported event records."""
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def format_duration(seconds):
    """Format a nonnegative elapsed duration as HH:MM:SS."""
    h, rem = divmod(max(0, int(seconds)), 3600)
    m, s = divmod(rem, 60)
    return f"{h:02}:{m:02}:{s:02}"


def write_log(filename, message):
    """Append a timestamped event to the optional plain-text log file."""
    if filename:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"[{full_timestamp()}] {message}\n")


def write_csv_event(filename, event, host, status, downtime=0, outages=0):
    """Append one lifecycle event to CSV, writing column headers as needed."""
    if not filename:
        return

    new_file = not os.path.exists(filename) or os.path.getsize(filename) == 0
    fields = ["timestamp", "event", "host", "address", "status", "outages", "downtime_seconds", "downtime"]

    with open(filename, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        if new_file:
            writer.writeheader()
        writer.writerow({
            "timestamp": full_timestamp(),
            "event": event,
            "host": host["name"],
            "address": host["address"],
            "status": status,
            "outages": outages,
            "downtime_seconds": round(downtime, 2),
            "downtime": format_duration(downtime),
        })


# ============================================================================
# TARGET FILE AND IP EXPANSION
# ============================================================================
def load_hosts(filename):
    """Load named or unnamed targets, skipping comments and duplicate addresses."""
    hosts, seen = [], set()

    try:
        with open(filename, encoding="utf-8") as f:
            for number, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue

                if "," in line:
                    name, address = [x.strip() for x in line.split(",", 1)]
                else:
                    name = address = line

                if not name or not address:
                    print(f"{YELLOW}WARNING:{RESET} Invalid line {number}: {line}")
                    continue
                if address in seen:
                    continue

                seen.add(address)
                hosts.append({"name": name, "address": address})

    except FileNotFoundError:
        sys.exit(f"ERROR: Host file '{filename}' was not found.")
    except OSError as exc:
        sys.exit(f"ERROR: Unable to read '{filename}': {exc}")

    if not hosts:
        sys.exit("ERROR: No valid hosts were found.")

    return hosts



def parse_range(spec):
    """Expand inclusive IPv4 ranges.

    Full endpoints may span subnet boundaries. A numeric-only end uses the
    first three octets of the start address; descending ranges are rejected.
    Returns integer addresses suitable for lazy iteration.
    """
    parts = spec.split("-")
    if len(parts) != 2 or not all(parts):
        raise ValueError("Range must be START-IP-END-IP or START-IP-LAST-OCTET")
    start_text, end_text = (part.strip() for part in parts)
    try:
        start = ipaddress.IPv4Address(start_text)
        if "." in end_text:
            end = ipaddress.IPv4Address(end_text)
        else:
            if not end_text.isdecimal() or not 0 <= int(end_text) <= 255:
                raise ValueError("Abbreviated range end must be an octet from 0 to 255")
            end = ipaddress.IPv4Address(".".join(start_text.split(".")[:3]) + "." + str(int(end_text)))
    except ipaddress.AddressValueError as exc:
        raise ValueError(str(exc)) from exc
    if int(end) < int(start):
        raise ValueError("Range end must be greater than or equal to its start")
    return int(start), int(end)


def load_targets(args, parser):
    """Resolve CLI target selection into host dictionaries.

    CIDR scans use network.hosts(), excluding network/broadcast on typical
    subnets but retaining addresses on /31 and /32. IPv4 range boundaries
    are inclusive. Enforce max-hosts before expansion where possible.
    """
    if args.host_file:
        hosts = load_hosts(args.host_file)
    elif args.host:
        hosts = [{"name": args.host, "address": args.host}]
    else:
        try:
            if args.subnet:
                network = ipaddress.IPv4Network(args.subnet, strict=False)
                count = network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
                if count > args.max_hosts:
                    parser.error(f"Subnet has {count:,} target IPs; --max-hosts is {args.max_hosts:,}. Increase --max-hosts intentionally to proceed.")
                addresses = (str(ip) for ip in network.hosts())
            else:
                start, end = parse_range(args.range)
                count = end - start + 1
                if count > args.max_hosts:
                    parser.error(f"Range has {count:,} target IPs; --max-hosts is {args.max_hosts:,}.")
                addresses = (str(ipaddress.IPv4Address(i)) for i in range(start, end + 1))
            hosts = [{"name": address, "address": address} for address in addresses]
        except (ValueError, ipaddress.NetmaskValueError) as exc:
            parser.error(str(exc))
    if len(hosts) > args.max_hosts:
        parser.error(f"Host file has {len(hosts):,} targets; increase --max-hosts (currently {args.max_hosts:,}).")
    return hosts


# ============================================================================
# CROSS-PLATFORM ICMP PROBING
# ============================================================================
def ping_host(host, timeout=1):
    """Send one ICMP echo request using the host operating system ping command."""
    address = host["address"]
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), address]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), address]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, math.ceil(timeout))), address]

    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 1
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def ping_all(hosts, timeout, workers):
    """Probe targets concurrently and map each address to its response status."""
    results = {}
    max_workers = min(workers, max(1, len(hosts)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(ping_host, host, timeout): host for host in hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                results[host["address"]] = future.result()
            except Exception:
                results[host["address"]] = False

    return results


# ============================================================================
# STATE TRANSITIONS AND EVENT REPORTING
# ============================================================================
def emit_event(event, host, state, log_file=None, csv_file=None, downtime=0):
    """Print a state transition and optionally persist it to text/CSV logs."""
    name, address = host["name"], host["address"]

    if event in ("UP", "INITIAL_UP"):
        print(
            f"[{timestamp()}] {GREEN}UP{RESET}     {name:<30}"
            + (f" downtime {YELLOW}{format_duration(downtime)}{RESET}" if event == "UP" else "")
        )
        status = "UP"
    else:
        print(f"[{timestamp()}] {RED}DOWN{RESET}   {name}")
        status = "DOWN"

    log_msg = f"{event} {name} ({address})"
    if event == "UP":
        log_msg += f" downtime {format_duration(downtime)}"

    write_log(log_file, log_msg)
    write_csv_event(csv_file, event, host, status, downtime, state.outages)


def process_result(host, alive, state, fail_threshold, recovery_threshold, log_file, csv_file):
    """Update hysteresis counters and state; return True on confirmed DOWN."""
    now = time.time()

    if alive:
        state.fail_streak = 0
        state.first_failure = None

        if state.state in ("UNKNOWN", "DOWN"):
            if state.success_streak == 0:
                state.first_recovery = now
            state.success_streak += 1

            if state.success_streak >= recovery_threshold:
                recovery_time = state.first_recovery or now

                if state.state == "DOWN":
                    downtime = recovery_time - (state.down_since or recovery_time)
                    state.total_downtime += downtime
                    state.state = "UP"
                    state.success_streak = 0
                    state.first_recovery = None
                    state.down_since = None
                    emit_event("UP", host, state, log_file, csv_file, downtime)
                else:
                    state.state = "UP"
                    state.success_streak = 0
                    state.first_recovery = None
                    emit_event("INITIAL_UP", host, state, log_file, csv_file)

        else:
            state.success_streak = 0
            state.first_recovery = None

        return False

    state.success_streak = 0
    state.first_recovery = None

    if state.state in ("UNKNOWN", "UP"):
        if state.fail_streak == 0:
            state.first_failure = now
        state.fail_streak += 1

        if state.fail_streak >= fail_threshold:
            was_up = state.state == "UP"
            state.state = "DOWN"
            state.down_since = state.first_failure or now
            state.fail_streak = 0
            state.first_failure = None
            state.outages += 1
            emit_event("DOWN" if was_up else "INITIAL_DOWN", host, state, log_file, csv_file)
            return True

    else:
        state.fail_streak = 0
        state.first_failure = None

    return False


# ============================================================================
# MONITORING STATUS AND SUMMARY
# ============================================================================
def get_counts(states):
    """Count UP, DOWN, and UNKNOWN host states for the current monitoring cycle."""
    values = [s.state for s in states.values()]
    return values.count("UP"), values.count("DOWN"), values.count("UNKNOWN")


def all_up(states):
    """Return True only when every tracked target has reached UP state."""
    return all(s.state == "UP" for s in states.values())


def show_summary(hosts, states, start_time):
    """Print final host states, outage counts, downtime, and elapsed time."""
    now = time.time()
    print("\n" + "=" * 92)
    print("UPGRADE MONITOR SUMMARY")
    print("=" * 92)
    print(f"{'DEVICE':<30}{'STATUS':<12}{'OUTAGES':<12}{'TOTAL DOWNTIME':<18}ADDRESS")
    print("-" * 92)

    longest_host, longest_time = None, -1
    for host in hosts:
        state = states[host["address"]]
        total = state.total_downtime
        if state.state == "DOWN" and state.down_since:
            total += now - state.down_since

        if total > longest_time:
            longest_host, longest_time = host["name"], total

        color = GREEN if state.state == "UP" else RED if state.state == "DOWN" else YELLOW
        print(
            f"{host['name']:<30}{color}{state.state:<12}{RESET}"
            f"{state.outages:<12}{format_duration(total):<18}{host['address']}"
        )

    up, down, unknown = get_counts(states)
    print("-" * 92)
    print(f"Devices         : {len(hosts)}")
    print(f"UP              : {GREEN}{up}{RESET}")
    print(f"DOWN            : {RED}{down}{RESET}")
    if unknown:
        print(f"UNKNOWN         : {YELLOW}{unknown}{RESET}")
    print(f"Monitoring time : {format_duration(now - start_time)}")
    if longest_host:
        print(f"Longest outage  : {longest_host} - {format_duration(longest_time)}")
    print("=" * 92)


# ============================================================================
# CONTINUOUS MONITORING LOOP
# ============================================================================
def monitor_hosts(args, hosts):
    """Monitor targets until interrupted or an enabled exit condition is met."""
    start_time = time.time()
    states = {host["address"]: DeviceState() for host in hosts}
    seen_down = False

    print("\n" + "=" * 78)
    print(f"{CYAN}PESPING Upgrade Monitor{RESET}")
    print("=" * 78)
    print(f"[{timestamp()}] Monitoring {len(hosts)} devices...")
    print(f"Interval            : {args.interval}s")
    print(f"Timeout             : {args.timeout}s")
    print(f"Fail threshold      : {args.fail_threshold}")
    print(f"Recovery threshold  : {args.recovery_threshold}")
    if args.log:
        print(f"Log                 : {args.log}")
    if args.csv:
        print(f"CSV                 : {args.csv}")
    if args.only_changes:
        print("Display             : changes only")
    print("\nPress Ctrl+C to stop.")
    print("=" * 78 + "\n")

    write_log(
        args.log,
        f"MONITOR START devices={len(hosts)} interval={args.interval} timeout={args.timeout} "
        f"fail_threshold={args.fail_threshold} recovery_threshold={args.recovery_threshold}",
    )

    try:
        while True:
            cycle_start = time.time()
            results = ping_all(hosts, args.timeout, args.workers)

            for host in hosts:
                state = states[host["address"]]
                if process_result(
                    host, results.get(host["address"], False), state,
                    args.fail_threshold, args.recovery_threshold, args.log, args.csv
                ):
                    seen_down = True

            up, down, unknown = get_counts(states)

            if not args.only_changes:
                print(
                    f"[{timestamp()}] {GREEN}UP {up}{RESET} | "
                    f"{RED}DOWN {down}{RESET} | {YELLOW}PENDING {unknown}{RESET}"
                )

            if all_up(states):
                if args.stop_when_all_up and seen_down:
                    print(f"\n{GREEN}ALL DEVICES RECOVERED{RESET}")
                    write_log(args.log, "ALL DEVICES RECOVERED")
                    break
                if args.wait_for_up and not args.stop_when_all_up:
                    print(f"\n{GREEN}ALL DEVICES ARE UP{RESET}")
                    write_log(args.log, "ALL DEVICES ARE UP")
                    break

            time.sleep(max(0, args.interval - (time.time() - cycle_start)))

    except KeyboardInterrupt:
        print(f"\n{YELLOW}Monitoring stopped by user.{RESET}")
        write_log(args.log, "MONITOR STOPPED BY USER")
    finally:
        show_summary(hosts, states, start_time)
        write_log(args.log, "MONITOR END")


# ============================================================================
# ONE-TIME SCAN MODE
# ============================================================================
def single_scan(args, hosts):
    """Run one concurrent probe cycle, filter output, and print scan totals."""
    start = time.monotonic()
    results = ping_all(hosts, args.timeout, args.workers)
    print()

    for host in hosts:
        alive = results.get(host["address"], False)
        if args.show == "up" and not alive or args.show == "down" and alive:
            continue
        if alive:
            print(f"{GREEN}UP{RESET}     {host['name']:<30} {host['address']}")
        else:
            print(f"{RED}DOWN{RESET}   {host['name']:<30} {host['address']}")

    up = sum(bool(results.get(host["address"], False)) for host in hosts)
    down = len(hosts) - up
    print("\n" + "=" * 78)
    print("PING SCAN SUMMARY")
    print("=" * 78)
    print(f"Total IPs       : {len(hosts)}")
    print(f"Reachable       : {GREEN}{up}{RESET}")
    print(f"Unreachable     : {RED}{down}{RESET}")
    print(f"Scan time       : {format_duration(time.monotonic() - start)}")
    print("=" * 78)


# ============================================================================
# COMMAND-LINE INTERFACE
# ============================================================================
def parse_args(argv=None):
    """Parse CLI options and reject invalid thresholds and worker limits."""
    parser = argparse.ArgumentParser(
        description=f"PESPING v{__version__} - Concurrent ICMP monitor and IPv4 scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python pesping.py -ho 192.0.2.10\n"
            "  python pesping.py -hf hosts.txt --monitor --only-changes\n"
            "  python pesping.py -r 192.0.2.100-192.0.2.200\n"
            "  python pesping.py -r 192.0.2.100-200 --show up\n"
            "  python pesping.py -s 192.0.2.0/24 --show down\n"
            "  python pesping.py -s 192.0.2.0/22 --monitor --workers 20\n"
        ),
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-hf", "--host_file", dest="host_file", metavar="FILE", help="File containing hosts or IPs")
    source.add_argument("-ho", "--host", help="Single hostname or IP")
    source.add_argument("-r", "--range", metavar="START-END", help="IPv4 range; full or abbreviated last octet")
    source.add_argument("-s", "--subnet", metavar="CIDR", help="IPv4 subnet, e.g. 192.0.2.0/24")
    parser.add_argument("--monitor", action="store_true", help="Enable continuous monitoring")
    parser.add_argument("--interval", type=float, default=2, help="Seconds between cycles")
    parser.add_argument("--timeout", type=float, default=1, help="ICMP timeout in seconds")
    parser.add_argument("--fail-threshold", type=int, default=3, help="Failures required to declare DOWN")
    parser.add_argument("--recovery-threshold", type=int, default=2, help="Replies required to declare UP")
    parser.add_argument("--log", metavar="FILE", help="Save events to log file")
    parser.add_argument("--csv", metavar="FILE", help="Save events to CSV")
    parser.add_argument("--show", choices=("all", "up", "down"), default="all", help="Filter results for a single scan")
    parser.add_argument("--only-changes", action="store_true", help="Show only state changes in monitor mode")
    parser.add_argument("--wait-for-up", action="store_true", help="Exit when all devices are UP")
    parser.add_argument("--stop-when-all-up", action="store_true", help="Exit after DOWN event and full recovery")
    parser.add_argument("--workers", type=int, default=50, help="Maximum simultaneous ping workers")
    parser.add_argument("--max-hosts", type=int, default=4096, help="Maximum target IPs (safety limit)")
    args = parser.parse_args(argv)
    if args.interval <= 0:
        parser.error("--interval must be greater than 0")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if args.fail_threshold < 1:
        parser.error("--fail-threshold must be >= 1")
    if args.recovery_threshold < 1:
        parser.error("--recovery-threshold must be >= 1")
    if args.workers < 1:
        parser.error("--workers must be >= 1")
    if args.max_hosts < 1:
        parser.error("--max-hosts must be >= 1")
    if args.wait_for_up or args.stop_when_all_up:
        args.monitor = True
    return args, parser


# ============================================================================
# PROGRAM ENTRY POINT
# ============================================================================
def main():
    """Select the input targets and dispatch to scan or monitoring mode."""
    args, parser = parse_args()
    hosts = load_targets(args, parser)
    if args.monitor:
        monitor_hosts(args, hosts)
    else:
        single_scan(args, hosts)


if __name__ == "__main__":
    main()
