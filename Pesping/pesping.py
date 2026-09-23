#!/usr/bin/env python3
"""pesping: concurrent ICMP monitor for maintenance windows and upgrade validation."""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import csv
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import math
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    print("Missing dependency: colorama. Install it with: pip install colorama", file=sys.stderr)
    sys.exit(2)


STATUS_UP = "UP"
STATUS_DOWN = "DOWN"
STATUS_PENDING = "PENDING"
STATUS_UNKNOWN = "UNKNOWN"
CSV_FIELDS = [
    "timestamp",
    "event",
    "host",
    "address",
    "status",
    "outages",
    "downtime_seconds",
    "downtime",
]
TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:%-]{0,254}$")
IP_RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}|\d{1,3}(?:\.\d{1,3}){3})$")
MAX_GENERATED_HOSTS = 65_536


@dataclass(frozen=True)
class Device:
    host: str
    address: str

    @property
    def key(self) -> str:
        return self.address.lower()


@dataclass
class DeviceState:
    state: str = STATUS_UNKNOWN
    fail_streak: int = 0
    success_streak: int = 0
    first_failure: float | None = None
    first_recovery: float | None = None
    down_since: float | None = None
    outages: int = 0
    total_downtime: float = 0.0
    longest_outage: float = 0.0


@dataclass(frozen=True)
class PingResult:
    device: Device
    success: bool
    timestamp: float
    error: str | None = None


@dataclass(frozen=True)
class MonitorEvent:
    event: str
    device: Device
    timestamp: float
    downtime_seconds: float = 0.0


@dataclass(frozen=True)
class MonitorConfig:
    interval: float
    timeout: float
    fail_threshold: int
    recovery_threshold: int
    workers: int
    only_changes: bool
    wait_for_up: bool
    stop_when_all_up: bool


@dataclass
class EventSink:
    log_path: Path | None = None
    csv_path: Path | None = None
    log_failed: bool = False
    csv_failed: bool = False


def format_datetime(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def format_clock(timestamp: float | None = None) -> str:
    return datetime.fromtimestamp(timestamp or time.time()).strftime("%H:%M:%S")


def format_duration(seconds: float) -> str:
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def format_value(value: float) -> str:
    return f"{value:g}"


def format_csv_seconds(seconds: float) -> str:
    return "0" if seconds <= 0 else f"{seconds:.1f}"


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}"


def color_status(status: str, width: int = 0) -> str:
    label = f"{status:<{width}}" if width else status
    colors = {
        STATUS_UP: Fore.GREEN,
        STATUS_DOWN: Fore.RED,
        STATUS_PENDING: Fore.YELLOW,
        STATUS_UNKNOWN: Fore.YELLOW,
    }
    return color_text(label, colors.get(status, Fore.WHITE))


def warn(message: str) -> None:
    print(color_text(f"WARNING: {message}", Fore.YELLOW), file=sys.stderr)


def normalize_path(value: str | None) -> Path | None:
    return Path(value).expanduser() if value else None


def is_valid_target(value: str) -> bool:
    if not value or len(value) > 255 or value.startswith("-"):
        return False
    if any(char.isspace() for char in value):
        return False
    return bool(TARGET_RE.fullmatch(value))


def parse_host_line(line: str, line_number: int) -> tuple[Device | None, str | None]:
    try:
        fields = next(csv.reader([line], skipinitialspace=True))
    except csv.Error as exc:
        return None, f"line {line_number}: CSV parse error: {exc}"

    fields = [field.strip() for field in fields]
    if len(fields) == 1:
        host = address = fields[0]
    elif len(fields) == 2:
        host, address = fields
    else:
        return None, f"line {line_number}: expected HOST or HOST,ADDRESS"

    if not is_valid_target(host) or not is_valid_target(address):
        return None, f"line {line_number}: invalid host entry '{line}'"
    return Device(host=host, address=address), None


def duplicate_keys(device: Device) -> set[str]:
    return {f"host:{device.host.lower()}", f"addr:{device.address.lower()}"}


def load_hosts(file_path: str) -> tuple[list[Device], list[str]]:
    path = Path(file_path).expanduser()
    if not path.exists():
        raise ValueError(f"host file does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"host path is not a file: {path}")

    devices: list[Device] = []
    warnings: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        lines = path.read_text().splitlines()
    except OSError as exc:
        raise ValueError(f"could not read host file {path}: {exc}") from exc

    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        device, error = parse_host_line(line, line_number)
        if error:
            invalid.append(error)
            continue

        keys = duplicate_keys(device)
        if seen.intersection(keys):
            warnings.append(f"line {line_number}: duplicate host ignored: {device.host} ({device.address})")
            continue

        seen.update(keys)
        devices.append(device)

    if invalid:
        raise ValueError("invalid host file entries:\n  - " + "\n  - ".join(invalid))
    if not devices:
        raise ValueError(f"host file is empty or contains no usable hosts: {path}")
    return devices, warnings


def device_from_host(host: str) -> Device:
    target = host.strip()
    if not is_valid_target(target):
        raise ValueError(f"invalid host value: {host}")
    return Device(host=target, address=target)


def devices_from_network(value: str) -> list[Device]:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid subnet '{value}': use CIDR format like 192.168.10.0/24") from exc

    if network.num_addresses > MAX_GENERATED_HOSTS:
        raise ValueError(
            f"subnet {network} is too large ({network.num_addresses} addresses); "
            f"maximum allowed is {MAX_GENERATED_HOSTS}"
        )

    devices = [Device(host=str(ip), address=str(ip)) for ip in network.hosts()]
    if not devices:
        raise ValueError(f"subnet {network} does not contain usable hosts")
    return devices


def devices_from_range(value: str) -> list[Device]:
    match = IP_RANGE_RE.fullmatch(value)
    if not match:
        raise ValueError("invalid range format; use 192.168.10.1-50 or 192.168.10.1-192.168.10.50")

    try:
        start_ip = ipaddress.IPv4Address(match.group(1))
        end_value = match.group(2)
        if "." in end_value:
            end_ip = ipaddress.IPv4Address(end_value)
        else:
            octets = match.group(1).split(".")
            end_ip = ipaddress.IPv4Address(".".join([*octets[:3], end_value]))
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"invalid IPv4 range '{value}'") from exc

    start_int = int(start_ip)
    end_int = int(end_ip)
    if end_int < start_int:
        raise ValueError(f"invalid IPv4 range '{value}': end address is lower than start address")

    count = end_int - start_int + 1
    if count > MAX_GENERATED_HOSTS:
        raise ValueError(
            f"range {value} is too large ({count} addresses); maximum allowed is {MAX_GENERATED_HOSTS}"
        )

    return [
        Device(host=str(ipaddress.IPv4Address(address)), address=str(ipaddress.IPv4Address(address)))
        for address in range(start_int, end_int + 1)
    ]


def load_subnet(value: str) -> tuple[list[Device], list[str]]:
    target = value.strip()
    if not target or target.startswith("-"):
        raise ValueError(f"invalid subnet or range value: {value}")
    if "-" in target and "/" not in target:
        return devices_from_range(target), []
    return devices_from_network(target), []


def build_ping_command(host: str, timeout: float) -> list[str]:
    system = platform.system()
    timeout_ms = str(max(1, int(math.ceil(timeout * 1000))))
    timeout_seconds = str(max(1, int(math.ceil(timeout))))

    if system == "Windows":
        return ["ping", "-n", "1", "-w", timeout_ms, host]
    if system == "Darwin":
        return ["ping", "-c", "1", "-W", timeout_ms, host]
    return ["ping", "-c", "1", "-W", timeout_seconds, host]


def ping_host(device: Device, timeout: float) -> PingResult:
    started = time.time()
    try:
        completed = subprocess.run(
            build_ping_command(device.address, timeout),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(timeout + 1.0, 2.0),
            check=False,
        )
        return PingResult(device=device, success=completed.returncode == 0, timestamp=time.time())
    except subprocess.TimeoutExpired:
        return PingResult(device=device, success=False, timestamp=time.time(), error="ping command timed out")
    except FileNotFoundError:
        return PingResult(device=device, success=False, timestamp=started, error="ping command not found")
    except OSError as exc:
        return PingResult(device=device, success=False, timestamp=time.time(), error=str(exc))


def ping_all(devices: list[Device], timeout: float, workers: int) -> list[PingResult]:
    max_workers = min(max(1, workers), len(devices))
    results: list[PingResult | None] = [None] * len(devices)

    with futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(ping_host, device, timeout): index
            for index, device in enumerate(devices)
        }
        for future in futures.as_completed(future_map):
            index = future_map[future]
            try:
                results[index] = future.result()
            except Exception as exc:
                device = devices[index]
                results[index] = PingResult(
                    device=device, success=False, timestamp=time.time(), error=str(exc)
                )

    return [result for result in results if result is not None]


def process_result(result: PingResult, state: DeviceState, config: MonitorConfig) -> MonitorEvent | None:
    now = result.timestamp
    if result.success:
        state.fail_streak = 0
        state.first_failure = None

        if state.state == STATUS_DOWN:
            if state.success_streak == 0:
                state.first_recovery = now
            state.success_streak += 1
            if state.success_streak < config.recovery_threshold:
                return None

            downtime = max(0.0, now - (state.down_since if state.down_since is not None else now))
            state.total_downtime += downtime
            state.longest_outage = max(state.longest_outage, downtime)
            state.state = STATUS_UP
            state.success_streak = 0
            state.first_recovery = None
            state.down_since = None
            return MonitorEvent(
                event=STATUS_UP, device=result.device, timestamp=now, downtime_seconds=downtime
            )

        if state.state in {STATUS_UNKNOWN, STATUS_PENDING}:
            if state.success_streak == 0:
                state.first_recovery = now
            state.success_streak += 1
            needed = config.recovery_threshold if config.wait_for_up else 1
            if state.success_streak < needed:
                state.state = STATUS_PENDING
                return None

            state.state = STATUS_UP
            state.success_streak = 0
            state.first_recovery = None
            return MonitorEvent(STATUS_UP, result.device, now, 0.0) if config.wait_for_up else None

        state.success_streak = 0
        return None

    state.success_streak = 0
    state.first_recovery = None
    if state.state == STATUS_DOWN:
        return None

    if state.fail_streak == 0:
        state.first_failure = now
    state.fail_streak += 1
    if state.state == STATUS_UNKNOWN:
        state.state = STATUS_PENDING

    if state.fail_streak < config.fail_threshold:
        return None

    state.state = STATUS_DOWN
    state.down_since = state.first_failure if state.first_failure is not None else now
    state.outages += 1
    state.fail_streak = 0
    state.first_failure = None
    return MonitorEvent(event=STATUS_DOWN, device=result.device, timestamp=now)


def prepare_output_files(sink: EventSink) -> None:
    for path in (sink.log_path, sink.csv_path):
        if not path:
            continue
        try:
            if path.parent != Path("."):
                path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8"):
                pass
        except OSError as exc:
            raise RuntimeError(f"could not prepare output file {path}: {exc}") from exc

    if sink.csv_path:
        try:
            if not sink.csv_path.exists() or sink.csv_path.stat().st_size == 0:
                with sink.csv_path.open("a", newline="", encoding="utf-8") as csv_file:
                    csv.DictWriter(csv_file, fieldnames=CSV_FIELDS).writeheader()
        except OSError as exc:
            raise RuntimeError(f"could not prepare CSV file {sink.csv_path}: {exc}") from exc


def write_log(sink: EventSink, timestamp: float, message: str) -> None:
    if not sink.log_path or sink.log_failed:
        return
    try:
        with sink.log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(f"[{format_datetime(timestamp)}] {message}\n")
    except OSError as exc:
        sink.log_failed = True
        warn(f"could not write log file {sink.log_path}: {exc}")


def write_csv_event(sink: EventSink, event: MonitorEvent, state: DeviceState) -> None:
    if not sink.csv_path or sink.csv_failed:
        return
    try:
        needs_header = not sink.csv_path.exists() or sink.csv_path.stat().st_size == 0
        with sink.csv_path.open("a", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
            if needs_header:
                writer.writeheader()
            writer.writerow(
                {
                    "timestamp": format_datetime(event.timestamp),
                    "event": event.event,
                    "host": event.device.host,
                    "address": event.device.address,
                    "status": event.event,
                    "outages": state.outages,
                    "downtime_seconds": format_csv_seconds(event.downtime_seconds),
                    "downtime": format_duration(event.downtime_seconds),
                }
            )
    except OSError as exc:
        sink.csv_failed = True
        warn(f"could not write CSV file {sink.csv_path}: {exc}")


def emit_event(event: MonitorEvent, state: DeviceState, sink: EventSink) -> None:
    extra = (
        f"   downtime {format_duration(event.downtime_seconds)}"
        if event.event == STATUS_UP and event.downtime_seconds > 0
        else ""
    )
    print(
        f"[{format_clock(event.timestamp)}] "
        f"{color_status(event.event, 6)} {event.device.host:<28}{extra}"
    )

    if event.event == STATUS_DOWN:
        write_log(sink, event.timestamp, f"DOWN {event.device.host} ({event.device.address})")
    elif event.event == STATUS_UP:
        downtime = (
            f" downtime {format_duration(event.downtime_seconds)}"
            if event.downtime_seconds > 0
            else ""
        )
        write_log(sink, event.timestamp, f"UP {event.device.host} ({event.device.address}){downtime}")
    write_csv_event(sink, event, state)


def current_status(state: DeviceState) -> str:
    return state.state if state.state in {STATUS_UP, STATUS_DOWN} else STATUS_PENDING


def count_states(states: dict[str, DeviceState]) -> dict[str, int]:
    counts = {STATUS_UP: 0, STATUS_DOWN: 0, STATUS_PENDING: 0}
    for state in states.values():
        counts[current_status(state)] += 1
    return counts


def all_devices_up(states: dict[str, DeviceState]) -> bool:
    return all(state.state == STATUS_UP for state in states.values())


def effective_total_downtime(state: DeviceState, now: float) -> float:
    if state.state == STATUS_DOWN and state.down_since is not None:
        return state.total_downtime + max(0.0, now - state.down_since)
    return state.total_downtime


def effective_longest_outage(state: DeviceState, now: float) -> float:
    current = max(0.0, now - state.down_since) if state.state == STATUS_DOWN and state.down_since else 0.0
    return max(state.longest_outage, current)


def show_cycle_summary(states: dict[str, DeviceState]) -> None:
    counts = count_states(states)
    print(
        f"[{format_clock()}] {color_status(STATUS_UP)} {counts[STATUS_UP]} | "
        f"{color_status(STATUS_DOWN)} {counts[STATUS_DOWN]} | "
        f"{color_status(STATUS_PENDING)} {counts[STATUS_PENDING]}"
    )


def show_monitor_banner(devices: list[Device], config: MonitorConfig) -> None:
    line = "=" * 78
    print(color_text(line, Fore.CYAN))
    print(color_text("pesping Upgrade Monitor", Fore.CYAN))
    print(color_text(line, Fore.CYAN))
    print()
    print(color_text(f"[{format_clock()}] Monitoring {len(devices)} devices...", Fore.CYAN))
    print()
    print(f"Interval            : {format_value(config.interval)}s")
    print(f"Timeout             : {format_value(config.timeout)}s")
    print(f"Fail threshold      : {config.fail_threshold}")
    print(f"Recovery threshold  : {config.recovery_threshold}")
    if config.wait_for_up:
        print("Auto stop           : wait for all devices UP")
    elif config.stop_when_all_up:
        print("Auto stop           : stop after confirmed DOWN and full recovery")
    print()
    print("Press Ctrl+C to stop.")
    print()
    print(color_text(line, Fore.CYAN))


def show_summary(devices: list[Device], states: dict[str, DeviceState], started: float, ended: float) -> None:
    line = "=" * 90
    dash = "-" * 90
    counts = count_states(states)
    longest_device: Device | None = None
    longest_seconds = 0.0

    for device in devices:
        seconds = effective_longest_outage(states[device.key], ended)
        if seconds > longest_seconds:
            longest_device = device
            longest_seconds = seconds

    print()
    print(color_text(line, Fore.CYAN))
    print(color_text("UPGRADE MONITOR SUMMARY", Fore.CYAN))
    print(color_text(line, Fore.CYAN))
    print()
    print(f"{'DEVICE':<30} {'STATUS':<10} {'OUTAGES':<10} {'TOTAL DOWNTIME':<18} ADDRESS")
    print(dash)

    for device in devices:
        state = states[device.key]
        total = effective_total_downtime(state, ended)
        print(
            f"{device.host:<30} {color_status(current_status(state), 10)} "
            f"{state.outages:<10} {format_duration(total):<18} {device.address}"
        )

    print()
    print(dash)
    longest = f"{longest_device.host} - {format_duration(longest_seconds)}" if longest_device else "N/A"
    print()
    print(f"Devices         : {len(devices)}")
    print(f"UP              : {counts[STATUS_UP]}")
    print(f"DOWN            : {counts[STATUS_DOWN]}")
    print(f"PENDING         : {counts[STATUS_PENDING]}")
    print(f"Monitoring time : {format_duration(ended - started)}")
    print(f"Longest outage  : {longest}")
    print()
    print(color_text(line, Fore.CYAN))


def device_label(device: Device) -> str:
    return f"{device.host} ({device.address})" if device.host != device.address else device.address


def single_scan(devices: list[Device], timeout: float, workers: int) -> int:
    results = ping_all(devices, timeout, workers)
    reported_errors: set[str] = set()

    for result in results:
        if result.error and result.error not in reported_errors:
            warn(result.error)
            reported_errors.add(result.error)
        status = STATUS_UP if result.success else STATUS_DOWN
        print(f"{color_status(status, 6)} {device_label(result.device)}")

    return 0 if all(result.success for result in results) else 1


def monitor_hosts(devices: list[Device], config: MonitorConfig, sink: EventSink) -> int:
    states = {device.key: DeviceState() for device in devices}
    started = time.time()
    interrupted = False
    saw_confirmed_down = False
    reported_errors: set[str] = set()

    show_monitor_banner(devices, config)
    write_log(
        sink,
        started,
        (
            f"MONITOR START devices={len(devices)} interval={format_value(config.interval)} "
            f"timeout={format_value(config.timeout)}"
        ),
    )

    try:
        while True:
            cycle_started = time.time()
            for result in ping_all(devices, config.timeout, config.workers):
                if result.error and result.error not in reported_errors:
                    warn(result.error)
                    reported_errors.add(result.error)

                state = states[result.device.key]
                event = process_result(result, state, config)
                if not event:
                    continue

                if event.event == STATUS_DOWN:
                    saw_confirmed_down = True
                emit_event(event, state, sink)

            if not config.only_changes:
                show_cycle_summary(states)

            if config.wait_for_up and all_devices_up(states):
                print(color_text("ALL DEVICES ARE UP", Fore.CYAN))
                write_log(sink, time.time(), "ALL DEVICES ARE UP")
                break

            if config.stop_when_all_up and saw_confirmed_down and all_devices_up(states):
                print(color_text("ALL DEVICES RECOVERED", Fore.CYAN))
                write_log(sink, time.time(), "ALL DEVICES RECOVERED")
                break

            sleep_for = config.interval - (time.time() - cycle_started)
            if sleep_for > 0:
                time.sleep(sleep_for)
    except KeyboardInterrupt:
        interrupted = True
        print()
        print(color_text("Interrupted by user.", Fore.CYAN))
    finally:
        ended = time.time()
        write_log(sink, ended, "MONITOR END")
        show_summary(devices, states, started, ended)

    return 130 if interrupted else 0


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if args.interval <= 0:
        parser.error("--interval must be greater than 0")
    if args.fail_threshold < 1:
        parser.error("--fail-threshold must be at least 1")
    if args.recovery_threshold < 1:
        parser.error("--recovery-threshold must be at least 1")
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.wait_for_up and args.stop_when_all_up:
        parser.error("--wait-for-up and --stop-when-all-up cannot be used together")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pesping.py",
        description="Concurrent ping utility for network operations and upgrade monitoring.",
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-ho", "--host", help="single host or IP address to ping")
    target.add_argument("-f", "--file", help="file with HOST or HOST,ADDRESS entries")
    target.add_argument(
        "-s",
        "--subnet",
        metavar="SUBNET_OR_RANGE",
        help="CIDR subnet or IPv4 range, e.g. 192.168.10.0/24 or 192.168.10.1-50",
    )
    parser.add_argument("--monitor", action="store_true", help="run continuous monitoring")
    parser.add_argument("--interval", type=float, default=2, help="seconds between monitoring cycles")
    parser.add_argument("--timeout", type=float, default=1, help="per-ping timeout in seconds")
    parser.add_argument("--fail-threshold", type=int, default=3, help="consecutive failures before DOWN")
    parser.add_argument("--recovery-threshold", type=int, default=2, help="consecutive successes before UP")
    parser.add_argument("--workers", type=int, default=50, help="maximum concurrent ping workers")
    parser.add_argument(
        "--only-changes", action="store_true", help="print only state changes in monitor mode"
    )
    parser.add_argument("--log", help="write monitor events to a plain text log file")
    parser.add_argument("--csv", help="write monitor events to a CSV file")
    parser.add_argument("--wait-for-up", action="store_true", help="exit when every device is confirmed UP")
    parser.add_argument(
        "--stop-when-all-up",
        action="store_true",
        help="after at least one confirmed DOWN, exit when every device is UP",
    )

    args = parser.parse_args(argv)
    validate_args(parser, args)
    return args


def load_devices(args: argparse.Namespace) -> tuple[list[Device], list[str]]:
    if args.host:
        return [device_from_host(args.host)], []
    if args.subnet:
        return load_subnet(args.subnet)
    return load_hosts(args.file)


def main(argv: list[str] | None = None) -> int:
    colorama_init(autoreset=True)
    args = parse_args(argv)

    try:
        devices, warnings = load_devices(args)
    except ValueError as exc:
        print(color_text(f"ERROR: {exc}", Fore.RED), file=sys.stderr)
        return 2

    for message in warnings:
        warn(message)

    should_monitor = args.monitor or args.wait_for_up or args.stop_when_all_up
    if not should_monitor:
        return single_scan(devices, args.timeout, args.workers)

    sink = EventSink(log_path=normalize_path(args.log), csv_path=normalize_path(args.csv))
    try:
        prepare_output_files(sink)
    except RuntimeError as exc:
        print(color_text(f"ERROR: {exc}", Fore.RED), file=sys.stderr)
        return 2

    config = MonitorConfig(
        interval=args.interval,
        timeout=args.timeout,
        fail_threshold=args.fail_threshold,
        recovery_threshold=args.recovery_threshold,
        workers=args.workers,
        only_changes=args.only_changes,
        wait_for_up=args.wait_for_up,
        stop_when_all_up=args.stop_when_all_up,
    )
    return monitor_hosts(devices, config, sink)


if __name__ == "__main__":
    sys.exit(main())
