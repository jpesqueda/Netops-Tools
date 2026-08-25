#!/usr/bin/env python3

import argparse
import concurrent.futures
import csv
import datetime as dt
import math
import os
import platform
import subprocess
import sys
import time
from dataclasses import dataclass

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    GREEN, RED, CYAN, YELLOW, RESET = Fore.GREEN, Fore.RED, Fore.CYAN, Fore.YELLOW, Style.RESET_ALL
except ImportError:
    GREEN = RED = CYAN = YELLOW = RESET = ""


@dataclass
class DeviceState:
    state: str = "UNKNOWN"
    fail_streak: int = 0
    success_streak: int = 0
    first_failure: float | None = None
    first_recovery: float | None = None
    down_since: float | None = None
    outages: int = 0
    total_downtime: float = 0.0


def timestamp():
    return dt.datetime.now().strftime("%H:%M:%S")


def full_timestamp():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def format_duration(seconds):
    h, rem = divmod(max(0, int(seconds)), 3600)
    m, s = divmod(rem, 60)
    return f"{h:02}:{m:02}:{s:02}"


def write_log(filename, message):
    if filename:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"[{full_timestamp()}] {message}\n")


def write_csv_event(filename, event, host, status, downtime=0, outages=0):
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


def load_hosts(filename):
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


def ping_host(host, timeout=1):
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


def emit_event(event, host, state, log_file=None, csv_file=None, downtime=0):
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


def get_counts(states):
    values = [s.state for s in states.values()]
    return values.count("UP"), values.count("DOWN"), values.count("UNKNOWN")


def all_up(states):
    return all(s.state == "UP" for s in states.values())


def show_summary(hosts, states, start_time):
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


def monitor_hosts(args, hosts):
    start_time = time.time()
    states = {host["address"]: DeviceState() for host in hosts}
    seen_down = False

    print("\n" + "=" * 78)
    print(f"{CYAN}PyFping Upgrade Monitor{RESET}")
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


def single_scan(args, hosts):
    results = ping_all(hosts, args.timeout, args.workers)
    print()

    for host in hosts:
        if results.get(host["address"], False):
            print(f"{GREEN}UP{RESET}     {host['name']:<30} {host['address']}")
        else:
            print(f"{RED}DOWN{RESET}   {host['name']:<30} {host['address']}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="PyFping - Concurrent ICMP monitor for network upgrades",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("-f", "--file", required=True, help="File containing hosts")
    parser.add_argument("--monitor", action="store_true", help="Enable continuous monitoring")
    parser.add_argument("--interval", type=float, default=2, help="Seconds between cycles")
    parser.add_argument("--timeout", type=float, default=1, help="ICMP timeout in seconds")
    parser.add_argument("--fail-threshold", type=int, default=3, help="Failures required to declare DOWN")
    parser.add_argument("--recovery-threshold", type=int, default=2, help="Replies required to declare UP")
    parser.add_argument("--log", metavar="FILE", help="Save events to log file")
    parser.add_argument("--csv", metavar="FILE", help="Save events to CSV")
    parser.add_argument("--only-changes", action="store_true", help="Show only state changes")
    parser.add_argument("--wait-for-up", action="store_true", help="Exit when all devices are UP")
    parser.add_argument("--stop-when-all-up", action="store_true", help="Exit after DOWN event and full recovery")
    parser.add_argument("--workers", type=int, default=50, help="Maximum simultaneous ping workers")

    args = parser.parse_args()

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

    if args.wait_for_up or args.stop_when_all_up:
        args.monitor = True

    return args


def main():
    args = parse_args()
    hosts = load_hosts(args.file)

    if args.monitor:
        monitor_hosts(args, hosts)
    else:
        single_scan(args, hosts)


if __name__ == "__main__":
    main()
