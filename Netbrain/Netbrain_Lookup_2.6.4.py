#!/usr/bin/env python3
"""
Netbrain_Lookup
===============

Description:
    Searches NetBrain endpoint information using IPv4 or MAC addresses.
    Automatically detects target types, supports single and file lookups,
    displays a concise terminal table, and exports complete results to CSV.

Author:
    Peskicorp

Version:
    2.6.4 Release Candidate 4

Requirements:
    Python 3.10+
    rich

Installation:
    pip install rich

Security / Sanitization:
    This source file contains no production server names, usernames, passwords,
    tenant/domain names, IP addresses, MAC addresses, serial numbers, or site names.
    Version 2.6.4 RC4 lookup strategy:
        IPv4       : direct One-IP ``ip`` filter
        MAC        : direct One-IP ``mac`` filter using dotted-lower format
                     (example: aaaa.aaaa.aaaa)
        MAC miss   : optional verification by ``switch_name`` partitions
        Global scan: never used automatically for MAC targets

    Release Candidate 4 result semantics:
        FOUND                  : exact endpoint evidence was returned
        VERIFIED_NOT_FOUND     : direct MAC miss + complete secondary verification
        DIRECT_MAC_NOT_FOUND   : direct MAC miss; secondary verification was partial
        ERROR                  : the primary lookup itself could not be completed safely

    Logging behavior:
        Non-fatal warnings, partition failures, pagination limits, and detailed
        API errors are written to a .log file instead of cluttering terminal output.
        By default, -o Report.csv automatically creates Report.log.

    Documentation examples use reserved/generic values only:
        NetBrain URL : https://netbrain.example.local
        IPv4 pattern : 192.168.1.X
        MAC address  : aa:aa:aa:aa:aa:aa
        Username     : USERNAME
        Password     : PASSWORD

    Important: The SOURCE CODE is sanitized. Runtime terminal output, CSV files,
    and --raw-json files will contain the real IP/MAC/device information returned
    by your NetBrain environment unless you sanitize those generated artifacts.

Code Sections:
    01 - Imports and dependencies
    02 - Global configuration and API paths
    03 - Exceptions
    04 - NetBrain API client
         Authentication: requesting token
         Session: deleting token
         Connectivity validation
         Generic REST requests
    05 - Main workflow
    06 - Command-line arguments
    07 - Tenant and domain selection
    08 - Target loading, validation, and normalization
    09 - Endpoint lookup orchestration
    10 - One-IP Table lookup, diagnostics, and pagination
         Direct MAC lookup: Cisco dotted-lower format
         MAC fallback: switch_name partition verification
    11 - Result parsing and correlation
    12 - CSV and terminal output
    13 - Program entry point and error handling
"""

# ============================================================================
# SECTION 01 - IMPORTS AND DEPENDENCIES
# ============================================================================

from __future__ import annotations

import argparse
import csv
import getpass
import ipaddress
import json
import platform
import re
import socket
from datetime import datetime
import ssl
import sys
import time
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

try:
    from rich import box
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
except ImportError:
    box = Console = Table = Text = BarColumn = Progress = TaskProgressColumn = TextColumn = None


# ============================================================================
# SECTION 02 - GLOBAL CONFIGURATION AND NETBRAIN API PATHS
# ============================================================================

SESSION = "/ServicesAPI/API/V1/Session"
DEFAULT_OUTPUT = "Netbrain_Lookup_Report.csv"
ONEIP_DEEP_OFFSET_LIMIT = 20000
DEFAULT_MAC_QUERY_STYLE = "dotted-lower"
DEFAULT_RETRIES = 3
DEFAULT_RETRY_BACKOFF = 1.0
VERSION = "Netbrain_Lookup 2.6.4 RC4"
console = Console(markup=False) if Console else None
DEFAULT_ENDPOINTS = [
    "/ServicesAPI/API/V1/CMDB/Devices/ConnectedSwitchPorts",
    "/ServicesAPI/API/V1/CMDB/Devices/EndSystemConnectedSwitchPorts",
    "/ServicesAPI/API/V1/CMDB/Devices/EndSystem/ConnectedSwitchPorts",
    "/ServicesAPI/API/V1/CMDB/Topology/ConnectedSwitchPort",
    "/ServicesAPI/API/V1/Topology/ConnectedSwitchPort",
]
SEARCH_ENDPOINTS = [
    "/ServicesAPI/API/V1/Search/Results",
    "/ServicesAPI/API/V1/Search/Result",
    "/ServicesAPI/API/V1/CMDB/Search",
    "/ServicesAPI/API/V1/Search",
    "/ServicesAPI/API/V1/CMDB/Search/Results",
    "/ServicesAPI/API/V1/CMDB/Search/Result",
]
MAC_RE = re.compile(
    r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|"
    r"\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b|"
    r"\b[0-9a-f]{12}\b"
)
INTERFACE_RE = re.compile(
    r"(?i)(?:TwentyFiveGigE|HundredGigE|FortyGigabitEthernet|TenGigabitEthernet|GigabitEthernet|"
    r"FastEthernet|Ethernet|Port-Channel|Bundle-Ether|TenGigE|GigE|xe-\d+|ge-\d+|fe-\d+|"
    r"Gi|Te|Fa|Eth|Et|Po|Hu|Fo|Twe)[\w/.:~-]*$"
)

COLS = [
    "target",
    "target_type",
    "status",
    "lookup_method",
    "verification",
    "endpoint_ip",
    "endpoint_mac",
    "endpoint_name",
    "switch_name",
    "switch_ip",
    "switch_port",
    "port_description",
    "vlan",
    "vrf",
    "site",
    "location",
    "device_type",
    "vendor",
    "model",
    "serial",
    "source_api",
    "notes",
]
ALIASES = {
    "endpoint_ip": "ip ipaddress ip_address endpointip hostip clientip".split(),
    "endpoint_mac": "mac macaddress mac_address endpointmac hostmac clientmac".split(),
    "endpoint_name": "endpoint endsystem host client clientname dns alias".split(),
    "switch_name": "switch switchname connecteddevice devicename device_name hostname name sourcedevice".split(),
    "switch_ip": "switchip deviceip mgmtip managementip management_ip managementaddress".split(),
    "switch_port": "switchport connectedSwitchPort connected_switch_port switchportname port portname interface interfacename intfname localinterface".split(),
    "port_description": "portdescription interfacedescription ifdescription intfdescription descr".split(),
    "vlan": "vlan vlanid accessvlan nativevlan".split(),
    "vrf": "vrf vrfname".split(),
    "site": "site sitepath".split(),
    "location": "location loc rack room".split(),
    "device_type": "devicetype type subtypename".split(),
    "vendor": "vendor manufacturer".split(),
    "model": "model platform".split(),
    "serial": "serial sn serialnumber".split(),
}
IGNORE_KEYS = {"statuscode", "statusdescription", "status", "message", "error", "errors"}

# Runtime diagnostic log. Initialized from the CSV output name in main().
LOG_PATH: Path | None = None
RUN_START_MONOTONIC: float | None = None

def init_runtime_log(path: Path) -> None:
    """Create a fresh diagnostic log for this execution."""
    global LOG_PATH
    LOG_PATH = path
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write("Netbrain_Lookup v2.6.4 RC4 - Runtime Diagnostic Log\n")
        handle.write(f"Started: {datetime.now().isoformat(timespec='seconds')}\n")
        handle.write("=" * 78 + "\n")

def log_event(level: str, message: str) -> None:
    """Append one timestamped diagnostic entry without printing it to the terminal."""
    if LOG_PATH is None:
        return
    try:
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            stamp = datetime.now().isoformat(timespec="seconds")
            handle.write(f"{stamp} [{level.upper()}] {message}\n")
    except OSError:
        # Logging must never break the lookup workflow.
        pass

def log_raw_diagnostics(data: Any) -> None:
    """Extract known warning/error fields from collected raw diagnostics."""
    diagnostic_keys = {
        "api_error": "ERROR",
        "lookup_error": "ERROR",
        "scan_warning": "WARNING",
        "pagination_warning": "WARNING",
        "capability_warning": "WARNING",
    }
    seen: set[tuple[str, str]] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in diagnostic_keys and item:
                    text = str(item)
                    pair = (diagnostic_keys[key], text)
                    if pair not in seen:
                        seen.add(pair)
                        log_event(*pair)
                elif isinstance(item, (dict, list)):
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(data)


# ============================================================================
# SECTION 03 - CUSTOM EXCEPTIONS
# ============================================================================

class NetBrainError(RuntimeError):
    pass


class NetBrainUnreachable(NetBrainError):
    pass


class AuthenticationError(NetBrainError):
    pass


class NetBrainAPIError(NetBrainError):
    def __init__(self, message: str, http_status: int | None = None) -> None:
        super().__init__(message)
        self.http_status = http_status


# ============================================================================
# SECTION 04 - NETBRAIN API CLIENT
# ============================================================================

class NetBrain:
    def __init__(self, url: str, user: str, password: str, args: argparse.Namespace) -> None:
        self.url = url.rstrip("/")
        self.user = user
        # Kept only for the lifetime of this NetBrain object so a single token
        # re-authentication can be performed during long-running jobs. It is
        # never written to logs and is cleared on logout.
        self._password = password
        self.auth_id = args.auth_id
        self.timeout = args.timeout
        self.verify_tls = not args.insecure
        self.verbose = args.verbose
        self.retries = max(0, int(getattr(args, "retries", DEFAULT_RETRIES)))
        self.retry_backoff = max(0.0, float(getattr(args, "retry_backoff", DEFAULT_RETRY_BACKOFF)))
        self.headers = {"Content-Type": "application/json", "Accept": "application/json"}
        self.last_error: Exception | None = None
        self.reauth_used = False
        self.current_domain: dict[str, str] | None = None

        # One-IP MAC behavior discovered during diagnostics. The production
        # environment validated for this release uses Cisco dotted-lower notation.
        self.mac_query_style = args.mac_style
        self.oneip_mac_filter_supported: bool | None = None
        self.oneip_mac_preferred_style: str | None = (
            None if args.mac_style == "auto" else args.mac_style
        )

    # -------------------------------------------------------------------------
    # AUTHENTICATION - REQUESTING TOKEN
    # -------------------------------------------------------------------------
    def login(self, *, reauthenticate: bool = False) -> None:
        """Authenticate and store a NetBrain token.

        The password is kept only in memory for the active client so one automatic
        session renewal can be attempted if an authenticated request receives 401.
        It is cleared during logout and is never logged.
        """
        body = {"username": self.user, "password": self._password}
        if self.auth_id:
            body["authentication_id"] = self.auth_id
        try:
            response = self.call("POST", SESSION, body=body, auth=False)
            token = response.get("token") if isinstance(response, dict) else None
        except NetBrainAPIError as exc:
            if exc.http_status in {400, 401, 403}:
                log_event("ERROR", f"Authentication request rejected with HTTP {exc.http_status}.")
                raise AuthenticationError("NetBrain authentication failed.") from exc
            raise
        finally:
            # Clear the temporary request payload; the in-memory credential is
            # retained only until logout to support one controlled re-authentication.
            body["password"] = ""

        if not token:
            log_event("ERROR", "Authentication response did not contain a token.")
            raise AuthenticationError("NetBrain authentication failed.")

        self.headers.update({"Token": token, "token": token})
        if reauthenticate:
            log_event("INFO", "NetBrain session token renewed successfully.")
            # A new session may reset the working domain. Restore it when known.
            if self.current_domain:
                self.call(
                    "PUT",
                    "/ServicesAPI/API/V1/Session/CurrentDomain",
                    body=self.current_domain,
                    auth=True,
                )
                log_event("INFO", "Working tenant/domain restored after token renewal.")

    # -------------------------------------------------------------------------
    # SESSION - DELETING TOKEN / LOGOUT
    # -------------------------------------------------------------------------
    def logout(self) -> None:
        try:
            if "Token" in self.headers:
                self.try_call("DELETE", SESSION)
        finally:
            self.headers.pop("Token", None)
            self.headers.pop("token", None)
            self._password = ""

    # -------------------------------------------------------------------------
    # CONNECTIVITY - VALIDATING NETBRAIN REACHABILITY
    # -------------------------------------------------------------------------
    def validate_connection(self) -> None:
        last_error = None
        for path in (SESSION, "/"):
            url = urljoin(self.url + "/", path.lstrip("/"))
            ctx = None if self.verify_tls else ssl._create_unverified_context()
            req = Request(url, headers={"Accept": "application/json"}, method="GET")
            try:
                with urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    log_event("INFO", f"Connectivity probe returned HTTP {resp.status}.")
                    say("    Status : Reachable", style="green")
                    return
            except HTTPError as exc:
                # Any HTTP response proves that the web/API server is reachable.
                log_event("INFO", f"Connectivity probe returned HTTP {exc.code}.")
                say("    Status : Reachable", style="green")
                return
            except (URLError, TimeoutError, socket.timeout) as exc:
                last_error = exc
                if self.verbose:
                    debug(f"Connectivity probe failed: {type(exc).__name__}")
        raise NetBrainUnreachable("Unable to reach NetBrain server.") from last_error

    @staticmethod
    def _response_detail(text: str) -> str:
        """Extract a concise API error description without exposing secrets."""
        detail = ""
        if text.strip():
            try:
                payload = json.loads(text)
                if isinstance(payload, dict):
                    detail = next(
                        (
                            str(value)
                            for key, value in payload.items()
                            if str(key).casefold() in {"statusdescription", "message", "error", "detail"}
                            and value
                        ),
                        "",
                    )
            except json.JSONDecodeError:
                pass
            detail = detail or " ".join(text.split())
        return detail[:500]

    def _retry_delay(self, retry_number: int, retry_after: str | None = None) -> float:
        """Return retry delay using Retry-After when usable, else exponential backoff."""
        if retry_after:
            try:
                return max(0.0, min(float(retry_after), 60.0))
            except (TypeError, ValueError):
                pass
        return min(self.retry_backoff * (2 ** max(0, retry_number - 1)), 30.0)

    @staticmethod
    def _is_timeout_exception(exc: BaseException) -> bool:
        reason = getattr(exc, "reason", None)
        return (
            isinstance(exc, (TimeoutError, socket.timeout))
            or isinstance(reason, (TimeoutError, socket.timeout))
            or "timed out" in str(exc).casefold()
        )

    # -------------------------------------------------------------------------
    # REST CLIENT - RETRY/BACKOFF + ONE-TIME TOKEN REAUTHENTICATION
    # -------------------------------------------------------------------------
    def call(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        auth: bool = True,
    ) -> Any:
        if auth and "Token" not in self.headers:
            raise NetBrainError("No active NetBrain session.")

        url = path if path.startswith(("http://", "https://")) else urljoin(self.url + "/", path.lstrip("/"))
        if params:
            url += ("&" if "?" in url else "?") + urlencode(params, doseq=True)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        ctx = None if self.verify_tls else ssl._create_unverified_context()

        retry_number = 0
        while True:
            req = Request(url, data=data, headers=self.headers.copy(), method=method.upper())
            if self.verbose:
                debug(f"Connecting to NetBrain API: {method.upper()} {path}")

            code: int | None = None
            text = ""
            response_headers = None
            try:
                with urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    code = resp.status
                    response_headers = resp.headers
                    text = resp.read().decode("utf-8", errors="replace")
            except HTTPError as exc:
                code = exc.code
                response_headers = exc.headers
                text = exc.read().decode("utf-8", errors="replace")
            except (URLError, TimeoutError, socket.timeout) as exc:
                if self._is_timeout_exception(exc) and retry_number < self.retries:
                    retry_number += 1
                    delay = self._retry_delay(retry_number)
                    log_event(
                        "WARNING",
                        f"Request timeout for {method.upper()} {path}; retry {retry_number}/{self.retries} "
                        f"in {delay:.1f}s.",
                    )
                    time.sleep(delay)
                    continue
                if self._is_timeout_exception(exc):
                    raise NetBrainAPIError(
                        f"NetBrain API request timed out after {retry_number + 1} attempt(s): {method.upper()} {path}"
                    ) from exc
                raise NetBrainUnreachable("Unable to reach NetBrain server.") from exc

            if self.verbose:
                debug(f"HTTP status: {code}")

            # Session expired/rejected: renew the token only once per execution,
            # then retry the original authenticated request.
            if code == 401 and auth:
                if not self.reauth_used:
                    self.reauth_used = True
                    log_event(
                        "WARNING",
                        f"Authenticated request received HTTP 401 at {path}; attempting one token renewal.",
                    )
                    try:
                        self.login(reauthenticate=True)
                    except AuthenticationError:
                        raise
                    except Exception as exc:
                        raise AuthenticationError("NetBrain session re-authentication failed.") from exc
                    continue
                raise AuthenticationError("NetBrain session token was rejected after automatic re-authentication.")

            # Retry only transient HTTP failures. 4xx errors other than 429 are
            # treated as deterministic and are not retried.
            if code is not None and (code == 429 or 500 <= code <= 599):
                if retry_number < self.retries:
                    retry_number += 1
                    retry_after = response_headers.get("Retry-After") if response_headers else None
                    delay = self._retry_delay(retry_number, retry_after)
                    log_event(
                        "WARNING",
                        f"Transient HTTP {code} for {method.upper()} {path}; retry {retry_number}/{self.retries} "
                        f"in {delay:.1f}s.",
                    )
                    time.sleep(delay)
                    continue

            if code != 200:
                detail = self._response_detail(text)
                suffix = f": {detail}" if detail else ""
                raise NetBrainAPIError(f"NetBrain API request failed: HTTP {code} at {path}{suffix}", code)

            try:
                return json.loads(text) if text.strip() else {}
            except json.JSONDecodeError as exc:
                raise NetBrainAPIError(f"NetBrain API returned invalid JSON: {path}") from exc

    # -------------------------------------------------------------------------
    # SAFE API WRAPPER - CAPTURING NON-FATAL REQUEST ERRORS
    # -------------------------------------------------------------------------
    def try_call(self, method: str, path: str, **kwargs: Any) -> Any | None:
        self.last_error = None
        try:
            return self.call(method, path, **kwargs)
        except (AuthenticationError, NetBrainUnreachable):
            # Authentication/session and reachability failures are fatal. Never
            # hide them as a harmless "not found" result.
            raise
        except Exception as exc:
            self.last_error = exc
            if self.verbose:
                debug(f"Request unavailable: {method.upper()} {path}: {exc}")
            return None


# ============================================================================
# SECTION 05 - MAIN WORKFLOW
# ============================================================================

def resolve_output_paths(output_arg: str | None, log_arg: str | None, *, prompt: bool) -> tuple[Path, Path]:
    """Resolve the CSV and diagnostic-log paths.

    ``-o/--output`` accepts either:
      * a CSV filename/path, for example ``-o Report.csv``; or
      * a directory, for example ``-o reports``. In directory mode the default
        report filename is created inside that directory.
    """
    value = (output_arg or "").strip()
    if not value and prompt:
        value = input(f"Output CSV or folder [{DEFAULT_OUTPUT}]: ").strip()
    value = value or DEFAULT_OUTPUT

    candidate = Path(value).expanduser()
    if candidate.suffix.casefold() == ".csv":
        output = candidate
    else:
        output = candidate / DEFAULT_OUTPUT

    log_path = Path(log_arg).expanduser() if log_arg else output.with_suffix(".log")
    return output, log_path


def existing_output_conflicts(
    output: Path,
    log_path: Path,
    raw_json: str | None,
) -> list[Path]:
    """Return generated artifact paths that already exist."""
    paths = [output, log_path]
    if raw_json:
        paths.append(Path(raw_json).expanduser())
    return [path for path in paths if path.exists()]


def log_runtime_metadata(
    args: argparse.Namespace,
    output: Path,
    log_path: Path,
    *,
    input_mode: str,
) -> None:
    """Write execution metadata without credentials, tokens, or target values."""
    log_event("INFO", f"Tool version: {VERSION}")
    log_event("INFO", f"Python version: {platform.python_version()}")
    log_event("INFO", f"Platform: {platform.system()} {platform.release()}")
    log_event("INFO", f"Script file: {Path(__file__).resolve()}")
    log_event("INFO", f"Input mode: {input_mode}")
    log_event("INFO", f"NetBrain URL: {args.url}")
    log_event("INFO", f"TLS certificate verification: {'DISABLED' if args.insecure else 'ENABLED'}")
    log_event("INFO", f"HTTP timeout: {args.timeout}s")
    log_event("INFO", f"Transient retries: {args.retries}; backoff base: {args.retry_backoff:.1f}s")
    log_event("INFO", f"MAC query style: {args.mac_style}")
    log_event("INFO", f"Switch fallback: {'DISABLED' if args.no_switch_fallback else 'ENABLED'}")
    log_event("INFO", f"CSV output: {output.resolve()}")
    log_event("INFO", f"Diagnostic log: {log_path.resolve()}")
    if args.raw_json:
        log_event("INFO", f"Raw JSON output: {Path(args.raw_json).expanduser().resolve()}")


def log_execution_time() -> None:
    """Write elapsed execution time to the diagnostic log when timing is active."""
    if RUN_START_MONOTONIC is None:
        return
    elapsed = max(0.0, time.perf_counter() - RUN_START_MONOTONIC)
    minutes, seconds = divmod(elapsed, 60)
    hours, minutes = divmod(minutes, 60)
    log_event("INFO", f"Execution time: {int(hours):02d}:{int(minutes):02d}:{seconds:05.2f}")


def prompt_target_source(args: argparse.Namespace) -> None:
    """Prompt for a single target or hosts file when neither CLI option was supplied."""
    if args.oneip_info or args.host is not None or args.hosts_file is not None:
        return

    while True:
        choice = input("Search input [1=single host, 2=hosts file]: ").strip().casefold()
        if choice in {"1", "host", "single", "h"}:
            args.host = input("Host (IPv4 or MAC): ").strip()
            if args.host:
                return
        elif choice in {"2", "file", "hosts", "f"}:
            args.hosts_file = input("Hosts file path: ").strip()
            if args.hosts_file:
                return
        else:
            print("Please enter 1 for a single host or 2 for a hosts file.")


def create_lookup_progress() -> Progress | None:
    """Create the single terminal progress bar used by the normal lookup workflow."""
    if not (console and Progress and TextColumn and BarColumn and TaskProgressColumn):
        return None
    return Progress(
        TextColumn("    Progress      :"),
        BarColumn(bar_width=36),
        TaskProgressColumn(),
        console=console,
        transient=False,
    )


def log_execution_summary(
    rows: list[dict[str, str]],
    args: argparse.Namespace,
    fallback_stats: dict[str, int],
) -> None:
    """Write detailed lookup-method and secondary-verification statistics to the log."""
    direct_ip = sum(row.get("lookup_method") == "DIRECT_IP" and row.get("status") == "found" for row in rows)
    direct_mac = sum(row.get("lookup_method") == "DIRECT_MAC" and row.get("status") == "found" for row in rows)
    switch_partition = sum(row.get("lookup_method") == "SWITCH_PARTITION" and row.get("status") == "found" for row in rows)
    ip_correlation = sum(row.get("lookup_method") == "IP_CORRELATION" and row.get("status") == "found" for row in rows)
    connected_port = sum(row.get("lookup_method") == "CONNECTED_SWITCH_PORT" and row.get("status") == "found" for row in rows)
    device_lookup = sum(row.get("lookup_method") == "DEVICE_LOOKUP" and row.get("status") == "found" for row in rows)
    global_scan = sum(row.get("lookup_method") == "GLOBAL_IP_SCAN" and row.get("status") == "found" for row in rows)

    log_event(
        "INFO",
        "Search methods summary: "
        f"DIRECT_IP={direct_ip}, DIRECT_MAC={direct_mac}, SWITCH_PARTITION={switch_partition}, "
        f"IP_CORRELATION={ip_correlation}, CONNECTED_SWITCH_PORT={connected_port}, "
        f"DEVICE_LOOKUP={device_lookup}, GLOBAL_IP_SCAN={global_scan}.",
    )
    log_event(
        "INFO",
        f"MAC query format={args.mac_style}; direct misses submitted for secondary verification="
        f"{fallback_stats.get('requested', 0)}.",
    )
    if fallback_stats.get("requested", 0):
        coverage = "COMPLETE" if fallback_stats.get("verification_complete") else "PARTIAL"
        log_event(
            "INFO",
            "Secondary verification summary: "
            f"candidate_partitions={fallback_stats.get('switches', 0)}, "
            f"attempted={fallback_stats.get('scanned', 0)}, "
            f"complete={fallback_stats.get('partitions_complete', 0)}, "
            f"incomplete={fallback_stats.get('partitions_incomplete', 0)}, "
            f"fallback_resolved={fallback_stats.get('resolved', 0)}, "
            f"fully_verified_misses={fallback_stats.get('verified_not_found', 0)}, "
            f"partial_direct_misses={fallback_stats.get('partial_not_found', 0)}, "
            f"partition_failures={fallback_stats.get('failed_switches', 0)}, "
            f"pagination_limits={fallback_stats.get('pagination_limited', 0)}, "
            f"inventory_errors={fallback_stats.get('inventory_errors', 0)}, coverage={coverage}.",
        )

def main() -> int:
    args = parse_args()

    # Interactive fallback for omitted normal-run parameters. The mutually
    # exclusive CLI group still prevents -ho and -hf from being supplied together.
    prompt_target_source(args)

    if not args.oneip_info and args.host is None and args.hosts_file is None:
        return report_error("A host or hosts file is required.", 2)

    # Ask for runtime connection information when it was not supplied on the CLI.
    args.url = (args.url or input("NetBrain URL: ")).strip().rstrip("/")
    if not args.url:
        return report_error("NetBrain URL is required.", 2)
    args.username = args.username or input("NetBrain Username: ").strip()
    if not args.username:
        return report_error("NetBrain username is required.", 2)

    # Normalize retry controls before logging/using them.
    args.timeout = max(1, int(args.timeout))
    args.retries = max(0, int(args.retries))
    args.retry_backoff = max(0.0, float(args.retry_backoff))

    output, log_path = resolve_output_paths(args.output, args.log, prompt=not args.oneip_info)

    # CSV, log, and raw JSON outputs must always be distinct files.
    artifact_paths = [output.resolve(), log_path.resolve()]
    if args.raw_json:
        artifact_paths.append(Path(args.raw_json).expanduser().resolve())
    if len(set(artifact_paths)) != len(artifact_paths):
        return report_error("CSV, diagnostic log, and raw JSON output paths must be different.", 2)

    # Protect existing reports/logs unless the operator explicitly allows overwrite.
    conflicts = existing_output_conflicts(output, log_path, args.raw_json)
    if conflicts and not args.overwrite:
        conflict_list = ", ".join(str(path) for path in conflicts)
        return report_error(
            f"Output file already exists: {conflict_list}. Use --overwrite or choose another -o path.",
            2,
        )

    init_runtime_log(log_path)
    args.log_path = str(log_path)
    global RUN_START_MONOTONIC
    RUN_START_MONOTONIC = time.perf_counter()

    input_mode = "ONEIP_DIAGNOSTICS" if args.oneip_info else ("SINGLE_HOST" if args.host is not None else "HOST_FILE")
    log_runtime_metadata(args, output, log_path, input_mode=input_mode)
    if args.insecure:
        log_event(
            "WARNING",
            "TLS certificate verification is disabled (--insecure). HTTPS encryption remains enabled, "
            "but certificate authenticity is not verified.",
        )

    if args.password is None:
        args.password = getpass.getpass("NetBrain Password: ")

    show_banner()

    # ---------------------------------------------------------------------
    # DIAGNOSTIC MODE - ONE-IP TABLE CAPABILITIES
    # ---------------------------------------------------------------------
    if args.oneip_info:
        nb = NetBrain(args.url, args.username, args.password, args)
        args.password = None
        try:
            say("[+] Validating NetBrain connectivity...", style="green")
            say(f"    URL    : {args.url}", style="green")
            nb.validate_connection()
            say("[+] Connecting to NetBrain API...", style="green")
            nb.login()
            say("    Login  : Successful", style="green")
            say("    Token  : Received", style="green")
            select_domain(nb, args.tenant, args.domain)
            result_code = run_oneip_diagnostics(nb, args.oneip_count)
            log_execution_time()
            return result_code
        finally:
            nb.logout()

    if args.host is not None:
        target = make_target(args.host.strip())
        if target["type"] == "INVALID":
            return report_error(f"Invalid endpoint: {target['value']}", 2)
        targets = [target]
    else:
        hosts_file = Path(args.hosts_file)
        try:
            targets = load_targets(hosts_file)
        except (OSError, UnicodeError):
            return report_error(f"Hosts file not found: {hosts_file}", 2)
    if not targets:
        return report_error("Hosts file contains no targets.", 2)

    rows: list[dict[str, str]] = []
    raw: list[dict[str, Any]] = []
    fallback_stats: dict[str, int] = {
        "requested": 0, "switches": 0, "scanned": 0, "resolved": 0,
        "remaining": 0, "verified_not_found": 0, "partial_not_found": 0,
        "failed_switches": 0, "inventory_errors": 0,
        "pagination_limited": 0, "verification_complete": 0,
        "partitions_complete": 0, "partitions_incomplete": 0,
    }
    valid_targets = [target for target in targets if target["type"] != "INVALID"]
    ip_count = sum(target["type"] == "IP" for target in valid_targets)
    mac_count = sum(target["type"] == "MAC" for target in valid_targets)
    for target in targets:
        debug_target(target["value"], target, args.verbose)

    nb = NetBrain(args.url, args.username, args.password, args)
    args.password = None
    progress = None
    progress_task = None
    try:
        say("[+] Validating NetBrain connectivity...", style="green")
        say(f"    URL    : {args.url}", style="green")
        nb.validate_connection()
        say("[+] Connecting to NetBrain API...", style="green")
        nb.login()
        say("    Login  : Successful", style="green")
        say("    Token  : Received", style="green")
        select_domain(nb, args.tenant, args.domain)

        say(f"[+] Searching {len(valid_targets)} endpoint(s)...", style="green")
        say(f"    IP lookup     : {ip_count} IP{'s' if ip_count != 1 else ''}", style="green")
        say(f"    MAC lookup    : {mac_count} MAC address{'es' if mac_count != 1 else ''}", style="green")

        # One concise progress bar covers both phases. Direct lookups account for
        # the first 90%; secondary MAC verification (when needed) completes 90-100%.
        progress = create_lookup_progress()
        if progress:
            progress.start()
            progress_task = progress.add_task("lookup", total=100.0)

        direct_limit = 90.0 if (mac_count and not args.no_switch_fallback) else 100.0
        processed = 0

        for target in targets:
            if target["type"] == "INVALID":
                rows.append(invalid_row(target))
                continue
            if args.verbose:
                debug(f"Searching endpoint: {target['value']}")
            target_rows, target_raw = lookup(
                nb,
                target,
                args.endpoint_path or DEFAULT_ENDPOINTS,
                scan_oneip=args.oneip_scan and not args.no_oneip_scan,
                oneip_count=args.oneip_count,
            )
            rows.extend(target_rows)
            raw.append({"target": target["value"], "responses": target_raw})
            processed += 1
            if progress and progress_task is not None and valid_targets:
                progress.update(progress_task, completed=(processed / len(valid_targets)) * direct_limit)
            if args.verbose:
                debug("Endpoint lookup completed")

        correlate_mac_targets(rows)

        if not args.no_switch_fallback:
            def _progress_switch(scanned: int, total: int) -> None:
                if progress and progress_task is not None:
                    ratio = (scanned / total) if total else 1.0
                    progress.update(progress_task, completed=direct_limit + ((100.0 - direct_limit) * ratio))

            fallback_raw, fallback_stats = resolve_mac_misses_by_switch_partitions(
                nb,
                rows,
                page_size=args.oneip_count,
                progress_callback=_progress_switch,
            )
            if fallback_raw:
                raw.append({"switch_partition_fallback": fallback_raw})

        if progress and progress_task is not None:
            progress.update(progress_task, completed=100.0)
    finally:
        if progress:
            progress.stop()
        nb.logout()

    # Persist detailed warnings/errors to the runtime log, not to terminal output.
    log_raw_diagnostics(raw)
    for row in rows:
        if row.get("status") == "error":
            log_event(
                "ERROR",
                f"Target {row.get('target', 'N/A')} lookup failed: {row.get('notes') or 'No detail available'}",
            )

    log_execution_summary(rows, args, fallback_stats)

    rows = [{column: row.get(column) or "N/A" for column in COLS} for row in rows]
    write_csv(output, rows)
    if args.raw_json:
        raw_path = Path(args.raw_json)
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
        log_event("WARNING", "Raw JSON output can contain live network data; sanitize it before sharing.")

    display_results(rows)
    has_errors = any(row["status"] == "error" for row in rows)
    display_search_summary(rows, output, log_path)

    log_execution_time()
    say("[+] Lookup completed successfully.", style="green")
    return 5 if has_errors else 0


# ============================================================================
# SECTION 06 - COMMAND-LINE ARGUMENTS
# ============================================================================

def parse_args() -> argparse.Namespace:
    examples = """USAGE
  python Netbrain_Lookup.py [connection options] -ho TARGET [output options]
  python Netbrain_Lookup.py [connection options] -hf FILE   [output options]
  python Netbrain_Lookup.py [connection options]            # prompts for missing values

EXAMPLES
  # Single IPv4 target
  python Netbrain_Lookup.py --url https://netbrain.example.local -ho 192.168.1.10 -u USERNAME

  # Single MAC target
  python Netbrain_Lookup.py --url https://netbrain.example.local -ho aa:aa:aa:aa:aa:aa -u USERNAME

  # Multiple targets from a text file
  python Netbrain_Lookup.py --url https://netbrain.example.local -hf hosts.txt -u USERNAME

  # Explicit CSV report name (Report.log is created automatically)
  python Netbrain_Lookup.py --url https://netbrain.example.local -hf hosts.txt -u USERNAME -o Report.csv

  # Output directory (creates reports/Netbrain_Lookup_Report.csv and .log)
  python Netbrain_Lookup.py --url https://netbrain.example.local -hf hosts.txt -u USERNAME -o reports

  # Explicitly overwrite an existing report/log
  python Netbrain_Lookup.py --url https://netbrain.example.local -hf hosts.txt -u USERNAME -o Report.csv --overwrite

  # Explicit password (not recommended because it may remain in shell history)
  python Netbrain_Lookup.py --url https://netbrain.example.local -ho 192.168.1.20 -u USERNAME -p PASSWORD

  # Generic tenant/domain example
  python Netbrain_Lookup.py --url https://netbrain.example.local -hf hosts.txt -u USERNAME --tenant LAB-TENANT --domain LAB-DOMAIN

  # TLS validation disabled for a lab/self-signed certificate
  python Netbrain_Lookup.py --url https://netbrain.example.local -hf hosts.txt -u USERNAME --insecure

INPUT RULES
  -ho/--host and -hf/--host_file are mutually exclusive and cannot be used together.
  If neither is provided, Netbrain_Lookup prompts you to select a single host or a hosts file.
  If URL, username, password, or output are omitted, the tool prompts for them at runtime.

GENERIC TEST DATA
  URL : https://netbrain.example.local
  IPv4: 192.168.1.10
  MAC : aa:aa:aa:aa:aa:aa
  User: USERNAME
"""
    p = argparse.ArgumentParser(
        description=(
            "Netbrain_Lookup searches NetBrain endpoint information by IPv4 or MAC address.\n"
            "Normal terminal output is intentionally concise; detailed diagnostics, warnings,\n"
            "partition/pagination information, and API errors are written to the .log file."
        ),
        epilog=examples,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"{VERSION}\nAuthor: Peskicorp")

    connection = p.add_argument_group("CONNECTION")
    connection.add_argument("--url", help="NetBrain base URL; prompted if omitted (example: https://netbrain.example.local)")

    inputs = p.add_argument_group("INPUT OPTIONS")
    target_input = inputs.add_mutually_exclusive_group(required=False)
    target_input.add_argument(
        "-ho", "--host",
        dest="host",
        help="Single IPv4 or MAC target; target type is detected automatically",
    )
    target_input.add_argument(
        "-hf", "--host_file", "--hosts-file", "--host-file",
        dest="hosts_file",
        help="Text file containing multiple IPv4/MAC targets",
    )

    auth = p.add_argument_group("AUTHENTICATION")
    auth.add_argument("-u", "--user", "--username", dest="username", help="NetBrain username; prompted if omitted")
    auth.add_argument(
        "-p", "--password", "--pasword",
        dest="password",
        help="NetBrain password; securely prompted if omitted. CLI use may expose it in shell history/process listings.",
    )
    auth.add_argument("--auth-id", help="authentication_id when required by the NetBrain environment")

    ssl_options = p.add_argument_group("SSL OPTIONS")
    ssl_options.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification; warning is written to the .log file")

    output = p.add_argument_group("OUTPUT OPTIONS")
    output.add_argument(
        "-o", "--output",
        default=None,
        help=(
            "CSV filename/path OR output directory; prompted if omitted. "
            "Examples: -o Report.csv, -o reports, -o reports/Report.csv. "
            f"Directory mode uses {DEFAULT_OUTPUT}. The .log uses the same basename."
        ),
    )
    output.add_argument("--log", help="Optional explicit diagnostic log path; otherwise derived from the CSV filename")
    output.add_argument("--raw-json", help="Optional raw API response JSON path; may contain live network data")
    output.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow existing CSV/log/raw-json output files to be replaced; default is to protect existing files",
    )

    advanced = p.add_argument_group("ADVANCED NETBRAIN OPTIONS")
    advanced.add_argument("--tenant", help="Tenant name or ID")
    advanced.add_argument("--domain", help="Domain name or ID")
    advanced.add_argument(
        "--oneip-info",
        action="store_true",
        help="Run sanitized One-IP API diagnostics instead of a normal endpoint lookup",
    )
    advanced.add_argument("--endpoint-path", action="append", help="Additional switch-port endpoint to try")
    advanced.add_argument(
        "--mac-style",
        choices=[
            "dotted-lower", "dotted-upper", "colon-lower", "colon-upper",
            "hyphen-lower", "hyphen-upper", "compact-lower", "compact-upper", "auto",
        ],
        default=DEFAULT_MAC_QUERY_STYLE,
        help="MAC notation sent to NetBrain One-IP queries (default: dotted-lower / aaaa.aaaa.aaaa)",
    )
    advanced.add_argument("--no-switch-fallback", action="store_true", help="Disable switch_name secondary verification for direct MAC misses")
    advanced.add_argument("--oneip-scan", action="store_true", help="Optional global One-IP scan after an exact IP miss; not used automatically for MAC targets")
    advanced.add_argument("--no-oneip-scan", action="store_true", help="Explicitly keep full One-IP scanning disabled")
    advanced.add_argument("--oneip-count", type=int, default=1000, help="Rows per One-IP API page (default/max used by this tool: 1000)")
    advanced.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds (default: 30)")
    advanced.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=f"Retries for HTTP 429, HTTP 5xx, and request timeouts (default: {DEFAULT_RETRIES})",
    )
    advanced.add_argument(
        "--retry-backoff",
        type=float,
        default=DEFAULT_RETRY_BACKOFF,
        help=f"Base seconds for exponential retry backoff (default: {DEFAULT_RETRY_BACKOFF:g}; sequence 1, 2, 4...)",
    )
    advanced.add_argument("-v", "--verbose", action="store_true", help="Write additional request/target diagnostics to the .log file")
    return p.parse_args()


# ============================================================================
# SECTION 07 - TENANT AND DOMAIN SELECTION
# ============================================================================

def select_domain(nb: NetBrain, tenant_arg: str | None, domain_arg: str | None) -> None:
    tenants = (nb.try_call("GET", "/ServicesAPI/API/V1/CMDB/Tenants") or {}).get("tenants", [])
    tenant = choose(tenants, tenant_arg, "tenantName", "tenantId", "tenant")
    if not tenant:
        return

    domains = (
        nb.try_call("GET", "/ServicesAPI/API/V1/CMDB/Domains", params={"tenantId": tenant["tenantId"]}) or {}
    ).get("domains", [])
    domain = choose(domains, domain_arg, "domainName", "domainId", "domain")
    if not domain:
        return

    domain_payload = {"tenantId": tenant["tenantId"], "domainId": domain["domainId"]}
    nb.call(
        "PUT",
        "/ServicesAPI/API/V1/Session/CurrentDomain",
        body=domain_payload,
    )
    nb.current_domain = domain_payload.copy()
    say(f"    Domain : {tenant.get('tenantName')} / {domain.get('domainName')}", style="green")


def choose(items: list[dict[str, Any]], wanted: str | None, name: str, item_id: str, label: str) -> dict[str, Any] | None:
    if not items:
        log_event("WARNING", f"Could not list {label}; continuing without selecting it.")
        return None
    if wanted:
        for item in items:
            valid = (str(item.get(name, "")).casefold(), str(item.get(item_id, "")).casefold())
            if wanted.casefold() in valid:
                return item
        raise NetBrainError(f"No encontre {label}: {wanted}")
    if len(items) == 1:
        return items[0]

    say(f"\nAvailable {label}s:")
    for i, item in enumerate(items, 1):
        say(f"  {i}. {item.get(name)} [{item.get(item_id)}]")
    answer = input(f"Select {label} by number/name/ID (Enter to skip): ").strip()
    if not answer:
        return None
    if answer.isdigit() and 1 <= int(answer) <= len(items):
        return items[int(answer) - 1]
    return choose(items, answer, name, item_id, label)


# ============================================================================
# SECTION 08 - TARGET LOADING, VALIDATION, AND NORMALIZATION
# ============================================================================

def load_targets(file_path: str | Path) -> list[dict[str, str]]:
    """Load IP/MAC targets and retain invalid entries for the final report."""
    targets: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for line in Path(file_path).read_text(encoding="utf-8-sig").splitlines():
        content = re.split(r"#|//", line, maxsplit=1)[0]
        for token in re.split(r"[\s,;]+", content.strip()):
            token = token.strip("[](){}<>")
            if token:
                target = make_target(token)
                add_target(targets, seen, target["type"], target["value"], target["original"])
    return targets


def add_target(
    targets: list[dict[str, str]], seen: set[tuple[str, str]], kind: str, value: str, original: str
) -> None:
    key = (kind, value)
    if key not in seen:
        seen.add(key)
        targets.append({"type": kind, "value": value, "original": original})


def validate_ipv4(target: str) -> bool:
    """Return whether target is a valid IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(target.strip()), ipaddress.IPv4Address)
    except ValueError:
        return False


def detect_target_type(target: str) -> str:
    """Classify a target as IP, MAC, or INVALID."""
    candidate = target.strip()
    if validate_ipv4(candidate):
        return "IP"
    try:
        ipaddress.ip_address(candidate)
        return "IP"
    except ValueError:
        return "MAC" if MAC_RE.fullmatch(candidate) else "INVALID"


def normalize_mac(mac: str) -> str:
    """Normalize a valid MAC address to lowercase colon notation."""
    digits = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(digits) != 12 or not re.fullmatch(r"[0-9a-f]{12}", digits):
        raise ValueError(f"Invalid MAC address: {mac}")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def _mac_digits(mac: str) -> str:
    """Return the 12 hexadecimal digits of a MAC address."""
    return re.sub(r"[^0-9a-fA-F]", "", mac)


def format_mac(mac: str, style: str) -> str:
    """Render a MAC address in a named representation without changing its value."""
    digits = _mac_digits(mac)
    if len(digits) != 12:
        return mac

    upper = style.endswith("-upper")
    rendered_digits = digits.upper() if upper else digits.lower()
    base_style = style.rsplit("-", 1)[0]

    if base_style == "dotted":
        return f"{rendered_digits[:4]}.{rendered_digits[4:8]}.{rendered_digits[8:]}"
    if base_style == "colon":
        return ":".join(rendered_digits[i : i + 2] for i in range(0, 12, 2))
    if base_style == "hyphen":
        return "-".join(rendered_digits[i : i + 2] for i in range(0, 12, 2))
    if base_style == "compact":
        return rendered_digits
    return mac


def mac_style(mac: str) -> str:
    """Describe only the representation of a MAC; never return the MAC itself."""
    value = mac.strip()
    case = "upper" if any(c.isalpha() for c in value) and value.upper() == value else "lower"
    if re.fullmatch(r"[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}", value):
        return f"dotted-{case}"
    if re.fullmatch(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", value):
        return f"colon-{case}"
    if re.fullmatch(r"[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}", value):
        return f"hyphen-{case}"
    if re.fullmatch(r"[0-9A-Fa-f]{12}", value):
        return f"compact-{case}"
    return "unknown"


def mac_query_variants(mac: str, preferred_style: str | None = None) -> list[tuple[str, str]]:
    """Return labeled MAC representations, optionally prioritizing a known-good style."""
    styles = [
        "dotted-upper", "dotted-lower",
        "colon-upper", "colon-lower",
        "hyphen-upper", "hyphen-lower",
        "compact-upper", "compact-lower",
    ]
    if preferred_style in styles:
        styles.remove(preferred_style)
        styles.insert(0, preferred_style)

    variants: list[tuple[str, str]] = []
    seen: set[str] = set()
    for style in styles:
        value = format_mac(mac, style)
        if value not in seen:
            seen.add(value)
            variants.append((style, value))
    return variants


def mac_query_values(mac: str) -> list[str]:
    """Backward-compatible list of common MAC representations."""
    return [value for _, value in mac_query_variants(mac)]



def make_target(raw: str) -> dict[str, str]:
    kind = detect_target_type(raw)
    value = raw.strip()
    if kind == "MAC":
        value = normalize_mac(value)
    elif kind == "IP":
        value = str(ipaddress.ip_address(value))
    return {"type": kind, "value": value, "original": raw.strip()}


def invalid_row(target: dict[str, str]) -> dict[str, str]:
    row = empty_row(target, "error")
    row["lookup_method"] = "INVALID"
    row["notes"] = "Invalid target"
    return row


def debug_target(original: str, target: dict[str, str], verbose: bool) -> None:
    if not verbose:
        return
    debug(f"Original target: {target.get('original', original)}")
    debug(f"Target detected as {target['type']}")
    if target["type"] == "MAC":
        debug(f"Normalized MAC: {target['value']}")


# ============================================================================
# SECTION 09 - ENDPOINT LOOKUP ORCHESTRATION
# ============================================================================

def lookup(
    nb: NetBrain,
    target: dict[str, str],
    endpoints: list[str],
    *,
    scan_oneip: bool = False,
    oneip_count: int = 1000,
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    raw: list[dict[str, Any]] = []

    direct_rows, direct_raw = connected_switch_port_lookup(nb, target)
    raw.extend(direct_raw)
    oneip_rows, oneip_raw = oneip_lookup(nb, target, scan=scan_oneip, count=oneip_count)
    raw.extend(oneip_raw)
    if direct_rows or oneip_rows:
        row = merge_rows(*(oneip_rows + direct_rows))
        if row["switch_name"] and not row["switch_ip"]:
            path = "/ServicesAPI/API/V1/CMDB/Devices"
            result = nb.try_call("GET", path, params={"hostname": row["switch_name"], "fullattr": 1})
            if result:
                raw.append({"path": path, "params": {"hostname": row["switch_name"], "fullattr": 1}, "response": result})
                devices = records_from(result)
                device = next(
                    (
                        item
                        for item in devices
                        if clean(pick(
                            {clean(k): stringify(v) for k, v in flatten(item).items()},
                            ["hostname", "name"],
                        )) == clean(row["switch_name"])
                    ),
                    None,
                )
                if device:
                    device_flat = {clean(k): stringify(v) for k, v in flatten(device).items()}
                    row["switch_ip"] = pick(device_flat, ["mgmtip", "managementip", "managementaddress", "deviceip"])
                    for field, aliases in (("site", ["site", "sitepath"]), ("location", ["loc", "location"])):
                        row[field] = row[field] or pick(device_flat, aliases)
        return [row], raw

    keys = ["ip", "ipAddress", "endSystemIp", "endpointIp"] if target["type"] == "IP" else [
        "mac",
        "macAddress",
        "endSystemMac",
        "endpointMac",
    ]

    # Some NetBrain deployments expose the default connected-port and generic
    # search paths as IP-only; probing those paths for MAC targets can create
    # unnecessary 404 responses.
    if target["type"] == "IP" or endpoints != DEFAULT_ENDPOINTS:
        for path in endpoints:
            for key in keys:
                payload = {key: target["value"]}
                for method, kwargs in (("GET", {"params": payload}), ("POST", {"body": payload})):
                    result = nb.try_call(method, path, **kwargs)
                    if not result:
                        continue
                    raw.append({"method": method, "path": path, "key": key, "response": result})
                    records = records_from(result)
                    if records:
                        rows = useful_rows(target, records, path)
                        if rows:
                            return rows, raw

    if target["type"] == "IP":
        device = nb.try_call("GET", "/ServicesAPI/API/V1/CMDB/Devices", params={"ip": target["value"], "fullattr": 1})
        records = records_from(device) if device else []
        if records:
            row = row_from(target, records[0], "device-found-no-switchport", "/ServicesAPI/API/V1/CMDB/Devices")
            row["notes"] = "La IP aparece como dispositivo NetBrain, no como endpoint final."
            return [row], raw + [{"path": "/ServicesAPI/API/V1/CMDB/Devices", "response": device}]

    if target["type"] == "IP":
        for path in SEARCH_ENDPOINTS:
            for key in ("keyword", "searchText", "searchString", "q", "query", "text"):
                payload = {key: target["value"], "limit": 20, "skip": 0}
                for method, kwargs in (("GET", {"params": payload}), ("POST", {"body": payload})):
                    result = nb.try_call(method, path, **kwargs)
                    records = filter_target_records(records_from(result), target) if result else []
                    if result:
                        raw.append({"method": method, "path": path, "key": key, "response": result})
                    if records:
                        rows = useful_rows(target, records, path)
                        if rows:
                            return rows, raw

    errors = list(
        dict.fromkeys(
            item.get("api_error") or item.get("lookup_error")
            for item in raw
            if item.get("api_error") or item.get("lookup_error")
        )
    )
    warnings = list(
        dict.fromkeys(item.get("scan_warning") for item in raw if item.get("scan_warning"))
    )
    row = empty_row(target, "error" if errors else "not-found")
    row["lookup_method"] = "DIRECT_MAC" if target["type"] == "MAC" else "DIRECT_IP"
    row["verification"] = "PRIMARY"
    if errors:
        row["notes"] = "One-IP lookup incomplete: " + "; ".join(errors)
    elif warnings:
        row["notes"] = "; ".join(warnings)
    return [row], raw


def connected_switch_port_lookup(
    nb: NetBrain, target: dict[str, str]
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    if target["type"] != "IP":
        return [], []

    path = f"/ServicesAPI/API/V1/CMDB/Topology/Devices/{target['value']}/ConnectedSwitchPort"
    result = nb.try_call("GET", path)
    if not result:
        return [], []

    raw = [{"path": path, "response": result}]
    rows = useful_rows(target, records_from(result), path)
    return rows, raw


# ============================================================================
# SECTION 10 - ONE-IP TABLE LOOKUP AND PAGINATION
# ============================================================================

def _find_oneip_total(response: Any) -> tuple[int | None, str]:
    """Return a total-record counter from response metadata when one is exposed.

    NetBrain releases are not fully consistent about metadata names. This
    function checks common total-counter names while deliberately ignoring
    One-IP record lists so a per-record value cannot be mistaken for the table
    total.
    """
    wanted = {
        "totalresultcount",
        "totalcount",
        "totalrecords",
        "recordcount",
        "rowcount",
        "totalrows",
        "totalsize",
        "total",
    }

    def walk_dict(data: dict[str, Any], prefix: str = "") -> tuple[int | None, str]:
        # First inspect scalar values at the current metadata level.
        for key, value in data.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
            path = f"{prefix}.{key}" if prefix else str(key)
            if normalized in wanted and isinstance(value, (int, str)) and not isinstance(value, bool):
                try:
                    number = int(value)
                except (TypeError, ValueError):
                    continue
                if number >= 0:
                    return number, path

        # Recurse into metadata dictionaries only. Do not descend into lists of
        # One-IP records because those contain operational network data.
        for key, value in data.items():
            if isinstance(value, dict):
                path = f"{prefix}.{key}" if prefix else str(key)
                found, found_path = walk_dict(value, path)
                if found is not None:
                    return found, found_path
        return None, ""

    if not isinstance(response, dict):
        return None, ""
    return walk_dict(response)


def _oneip_response_keys(response: Any) -> str:
    """Return only top-level response field names; never print record values."""
    if not isinstance(response, dict):
        return type(response).__name__
    return ", ".join(sorted(str(key) for key in response.keys())) or "none"


def _safe_oneip_request(
    nb: NetBrain, path: str, params: dict[str, Any]
) -> tuple[Any | None, list[dict[str, Any]], str]:
    """Execute a diagnostic One-IP GET and return response, records, and error text."""
    result = nb.try_call("GET", path, params=params)
    if result is None:
        return None, [], str(nb.last_error or "Unknown API error")
    return result, records_from(result), ""



def _first_record_value(records: list[dict[str, Any]], *field_names: str) -> str:
    """Return the first non-empty value for any requested top-level field.

    Used only for capability tests. The returned value is sent back to NetBrain
    as a query parameter and is never printed to the terminal.
    """
    wanted = {clean(name) for name in field_names}
    for record in records:
        for key, value in record.items():
            if clean(str(key)) in wanted:
                rendered = stringify(value).strip()
                if rendered:
                    return rendered
    return ""


def _test_oneip_filter(
    nb: NetBrain,
    path: str,
    parameter: str,
    sample_value: str,
    count: int = 100,
) -> tuple[str, int, str]:
    """Test a One-IP filter without exposing the sample value.

    Returns:
        ("SUPPORTED", rows, "")
        ("REJECTED", 0, error)
        ("NO_SAMPLE", 0, "")
    """
    if not sample_value:
        return "NO_SAMPLE", 0, ""

    params = {
        parameter: sample_value,
        "beginIndex": 0,
        "count": max(1, min(count, 100)),
    }
    result, records, error = _safe_oneip_request(nb, path, params)
    if result is None:
        return "REJECTED", 0, error
    return "SUPPORTED", len(records), ""



def _record_matches_filter(record: dict[str, Any], parameter: str, sample_value: str) -> bool:
    """Verify that a returned One-IP record actually satisfies a tested filter."""
    flat = {clean(k): stringify(v).strip() for k, v in flatten(record).items()}
    parameter = clean(parameter)

    if parameter == "mac":
        wanted = normalize_mac(sample_value)
        for key, value in flat.items():
            if clean(key).endswith("mac") or clean(key) == "mac":
                for candidate in MAC_RE.findall(value):
                    try:
                        if normalize_mac(candidate) == wanted:
                            return True
                    except ValueError:
                        pass
        return False

    aliases = {
        "ip": ["ip", "ipaddress"],
        "lan": ["lansegment", "lan"],
        "switchname": ["switchname", "switch_name"],
    }.get(parameter, [parameter])
    wanted = clean(sample_value)
    for key, value in flat.items():
        key_clean = clean(key)
        if any(key_clean == clean(a) or key_clean.endswith(clean(a)) for a in aliases):
            if clean(value) == wanted:
                return True
    return False


def _test_oneip_filter_verified(
    nb: NetBrain,
    path: str,
    parameter: str,
    sample_value: str,
    count: int = 100,
) -> tuple[str, int, int, str]:
    """Test both HTTP acceptance and semantic filtering of a One-IP query."""
    if not sample_value:
        return "NO_SAMPLE", 0, 0, ""
    params = {parameter: sample_value, "beginIndex": 0, "count": max(1, min(count, 100))}
    result, records, error = _safe_oneip_request(nb, path, params)
    if result is None:
        return "REJECTED", 0, 0, error
    matches = sum(_record_matches_filter(record, parameter, sample_value) for record in records)
    if matches:
        return "VERIFIED", len(records), matches, ""
    if not records:
        return "ACCEPTED_EMPTY", 0, 0, ""
    return "UNVERIFIED", len(records), 0, ""


def _test_mac_format_matrix(
    nb: NetBrain,
    path: str,
    sample_mac: str,
) -> list[tuple[str, str, int, int]]:
    """Test MAC representations without printing the sampled production MAC value."""
    if not sample_mac:
        return []
    target = {"type": "MAC", "value": normalize_mac(sample_mac), "original": "<sanitized>"}
    outcomes: list[tuple[str, str, int, int]] = []
    for style, value in mac_query_variants(sample_mac):
        params = {"mac": value, "beginIndex": 0, "count": 100}
        result, records, error = _safe_oneip_request(nb, path, params)
        if result is None:
            outcomes.append((style, "REJECTED", 0, 0))
            continue
        exact = len(filter_target_records(records, target))
        if exact:
            outcomes.append((style, "VERIFIED", len(records), exact))
        elif records:
            outcomes.append((style, "UNVERIFIED", len(records), 0))
        else:
            outcomes.append((style, "ACCEPTED_EMPTY", 0, 0))
    return outcomes

def _get_product_version(nb: NetBrain) -> tuple[str, str]:
    """Return sanitized NetBrain product/software version information if exposed."""
    paths = (
        "/ServicesAPI/API/V1/System/ProductVersion",
        "/ServicesAPI/API/V1/System/nodeinfo",
    )
    for path in paths:
        result = nb.try_call("GET", path)
        if not isinstance(result, dict):
            continue
        product = ci_get(result, "productVersion")
        software = ci_get(result, "softwareVersion")
        if product or software:
            return stringify(product).strip(), stringify(software).strip()
    return "", ""


def run_oneip_diagnostics(nb: NetBrain, requested_count: int) -> int:
    """Inspect One-IP table size and pagination without exposing network records.

    The diagnostic answers seven questions:
      1. Which NetBrain product/software version is exposed?
      2. Does the API expose an exact total record count?
      3. Is record index 19,999 accessible?
      4. What happens when beginIndex reaches 20,000?
      5. Does the accessible response expose a usable afterId/cursor?
      6. Which documented One-IP filters work in this deployment?
      7. Can switch_name or lan partitioning bypass the global 20,000-row limit?

    Only counts, response field names, and capability results are printed.
    IP addresses, MAC addresses, hostnames, cursor values, and One-IP rows are
    intentionally suppressed.
    """
    path = "/ServicesAPI/API/V1/CMDB/Topology/OneIPTable"
    page_size = max(1, min(requested_count, 1000))

    say("\n" + "=" * 68, style="green")
    say("ONE-IP TABLE DIAGNOSTICS".center(68), style="green")
    say("=" * 68, style="green")

    say("[+] Reading NetBrain version information...", style="green")
    product_version, software_version = _get_product_version(nb)
    if product_version or software_version:
        say(f"    Product version    : {product_version or 'N/A'}")
        say(f"    Software version   : {software_version or 'N/A'}")
    else:
        say("    Product version    : Not exposed by tested version endpoint", style="yellow")

    say("\n[+] Reading One-IP metadata...", style="green")

    first_params = {"ip": "", "beginIndex": 0, "count": page_size}
    first, first_records, first_error = _safe_oneip_request(nb, path, first_params)
    if first is None:
        say("[-] Unable to read the first One-IP page.", style="red")
        say(f"    Error : {first_error}", style="red")
        return 5

    say(f"    Requested rows     : {page_size}")
    say(f"    Returned rows      : {len(first_records)}")
    say(f"    Response fields    : {_oneip_response_keys(first)}")

    total, total_field = _find_oneip_total(first)
    if total is not None:
        say(f"    Total One-IP rows  : {total:,}", style="green")
        say(f"    Total count field  : {total_field}")
    else:
        say("    Total One-IP rows  : Not exposed in first-page metadata", style="yellow")

    say("\n[+] Testing the 20,000-row offset boundary...", style="green")
    before_params = {"ip": "", "beginIndex": ONEIP_DEEP_OFFSET_LIMIT - 1, "count": 1}
    before, before_records, before_error = _safe_oneip_request(nb, path, before_params)
    if before is not None:
        say(
            f"    beginIndex {ONEIP_DEEP_OFFSET_LIMIT - 1:,} : "
            f"SUCCESS ({len(before_records)} row(s))",
            style="green" if before_records else "yellow",
        )
    else:
        say(
            f"    beginIndex {ONEIP_DEEP_OFFSET_LIMIT - 1:,} : REJECTED",
            style="yellow",
        )
        if nb.verbose:
            debug(f"Boundary-1 error: {before_error}")

    limit_params = {"ip": "", "beginIndex": ONEIP_DEEP_OFFSET_LIMIT, "count": 1}
    limit_result, limit_records, limit_error = _safe_oneip_request(nb, path, limit_params)
    if limit_result is not None:
        say(
            f"    beginIndex {ONEIP_DEEP_OFFSET_LIMIT:,} : "
            f"SUCCESS ({len(limit_records)} row(s))",
            style="green" if limit_records else "yellow",
        )
    else:
        say(f"    beginIndex {ONEIP_DEEP_OFFSET_LIMIT:,} : REJECTED", style="yellow")
        # The error text contains API behavior, not credentials. Show a compact
        # classification in normal mode and the complete exception only in -v.
        lower_error = limit_error.casefold()
        if "afterid" in lower_error or "deep offset" in lower_error:
            say("    Server behavior    : Deep-offset paging blocked; cursor paging requested", style="yellow")
        else:
            say("    Server behavior    : Offset request rejected", style="yellow")
        if nb.verbose:
            debug(f"Boundary error: {limit_error}")

    # Fetch the last accessible 1,000-row window. This is the best place to
    # discover a next-cursor or a row identifier before the offset restriction.
    last_window_start = max(0, ONEIP_DEEP_OFFSET_LIMIT - 1000)
    last_params = {"ip": "", "beginIndex": last_window_start, "count": 1000}
    last_page, last_records, last_error = _safe_oneip_request(nb, path, last_params)

    cursor = ""
    cursor_field = ""
    available_fields: list[str] = []
    if last_page is not None:
        cursor, cursor_field, available_fields = after_id_cursor(last_page, last_records)
        say("\n[+] Inspecting cursor pagination support...", style="green")
        say(f"    Last window start  : {last_window_start:,}")
        say(f"    Last window rows   : {len(last_records)}")
        if cursor:
            say(f"    Cursor detected    : YES (field: {cursor_field})", style="green")
        else:
            say("    Cursor detected    : NO", style="yellow")
            if last_records:
                # Field NAMES are useful for engineering and do not disclose the
                # actual operational values stored in the One-IP row.
                fields = sorted(flatten(last_records[-1]).keys())
                preview = ", ".join(fields[:24])
                suffix = " ..." if len(fields) > 24 else ""
                say(f"    Last-row fields    : {preview}{suffix}")
            elif available_fields:
                say(f"    Response fields    : {', '.join(available_fields[:24])}")
    else:
        say("\n[+] Inspecting cursor pagination support...", style="green")
        say("    Last accessible window could not be read.", style="yellow")
        if nb.verbose:
            debug(f"Last-window error: {last_error}")

    cursor_supported = False
    cursor_rows = 0
    if cursor:
        # Never print the cursor value. Only test whether NetBrain accepts it.
        cursor_params = {"ip": "", "afterId": cursor, "count": min(page_size, 10)}
        cursor_result, cursor_records, cursor_error = _safe_oneip_request(nb, path, cursor_params)
        if cursor_result is not None:
            cursor_supported = True
            cursor_rows = len(cursor_records)
            say(f"    afterId test       : SUCCESS ({cursor_rows} row(s))", style="green")
        else:
            say("    afterId test       : REJECTED", style="yellow")
            if nb.verbose:
                debug(f"afterId test error: {cursor_error}")

    # ------------------------------------------------------------------
    # VERIFIED FILTER CAPABILITY TESTS
    # ------------------------------------------------------------------
    # Use samples from the last accessible window when possible.  This is
    # deliberate: if NetBrain silently ignores a filter and simply returns the
    # first page, a sample taken around row 19,000 should not appear there.
    sample_source = last_records if last_records else first_records
    sample_ip = _first_record_value(sample_source, "ip")
    sample_mac = _first_record_value(sample_source, "mac")
    sample_lan = _first_record_value(sample_source, "lanSegment", "lan")
    sample_switch = _first_record_value(sample_source, "switchName", "switch_name")

    verified_tests: dict[str, tuple[str, int, int, str]] = {}
    for label, parameter, sample in (
        ("ip", "ip", sample_ip),
        ("lan", "lan", sample_lan),
        ("switch_name", "switch_name", sample_switch),
    ):
        verified_tests[label] = _test_oneip_filter_verified(nb, path, parameter, sample)

    say("\n[+] Verifying One-IP filter semantics...", style="green")
    for label in ("ip", "lan", "switch_name"):
        state, rows_count, match_count, error = verified_tests[label]
        if state == "VERIFIED":
            say(
                f"    {label:<16}: VERIFIED ({match_count}/{rows_count} returned row(s) match filter)",
                style="green",
            )
        elif state == "ACCEPTED_EMPTY":
            say(f"    {label:<16}: ACCEPTED but returned no rows", style="yellow")
        elif state == "UNVERIFIED":
            say(
                f"    {label:<16}: UNVERIFIED ({rows_count} row(s) returned, 0 matched filter)",
                style="yellow",
            )
        elif state == "NO_SAMPLE":
            say(f"    {label:<16}: NOT TESTED (no sample value)", style="yellow")
        else:
            say(f"    {label:<16}: REJECTED", style="yellow")
            if nb.verbose and error:
                debug(f"One-IP filter test {label}: {error}")

    # MAC is special because R12.x deployments can be strict about notation.
    # Test common representations, but only print the format name -- never the
    # sampled production MAC value.
    say("\n[+] Testing MAC query representations...", style="green")
    if sample_mac:
        say(f"    Stored sample style : {mac_style(sample_mac)}")
    mac_matrix = _test_mac_format_matrix(nb, path, sample_mac)
    verified_mac_styles = [style for style, state, _, _ in mac_matrix if state == "VERIFIED"]
    for style, state, rows_count, exact_count in mac_matrix:
        if state == "VERIFIED":
            say(
                f"    {style:<16}: VERIFIED ({exact_count}/{rows_count} row(s) exact MAC match)",
                style="green",
            )
        elif state == "REJECTED":
            say(f"    {style:<16}: REJECTED", style="yellow")
        elif state == "ACCEPTED_EMPTY":
            say(f"    {style:<16}: ACCEPTED, no rows", style="yellow")
        else:
            say(
                f"    {style:<16}: UNVERIFIED ({rows_count} row(s), 0 exact MAC matches)",
                style="yellow",
            )

    direct_mac_verified = bool(verified_mac_styles)
    if direct_mac_verified:
        say(f"    Preferred MAC style: {verified_mac_styles[0]}", style="green")
    else:
        say("    Preferred MAC style: none verified", style="yellow")

    # Verify that switch_name is not merely HTTP-accepted but actually filters.
    switch_partition_viable = False
    switch_state, switch_rows, switch_matches, _ = verified_tests["switch_name"]
    if switch_state == "VERIFIED" and sample_switch:
        probe_params = {"switch_name": sample_switch, "beginIndex": 100, "count": 1}
        probe_result, probe_records, probe_error = _safe_oneip_request(nb, path, probe_params)
        if probe_result is not None:
            probe_match = not probe_records or all(
                _record_matches_filter(record, "switch_name", sample_switch) for record in probe_records
            )
            if probe_match:
                switch_partition_viable = True
                say(
                    f"    switch partition   : VERIFIED PAGING "
                    f"(offset 100 returned {len(probe_records)} row(s))",
                    style="green",
                )
            else:
                say("    switch partition   : PAGING RESPONSE DID NOT MATCH FILTER", style="yellow")
        else:
            say("    switch partition   : FILTER VERIFIED; paging probe rejected", style="yellow")
            if nb.verbose:
                debug(f"switch_name partition paging probe: {probe_error}")

    lan_partition_viable = verified_tests["lan"][0] == "VERIFIED"

    # ------------------------------------------------------------------
    # CONCLUSION
    # ------------------------------------------------------------------
    say("\n[+] Diagnostic conclusion", style="green")

    if total is not None:
        say(f"    Exact table size   : {total:,} row(s)", style="green")
        if total > ONEIP_DEEP_OFFSET_LIMIT:
            say(
                f"    Rows beyond 20,000 : {total - ONEIP_DEEP_OFFSET_LIMIT:,}",
                style="yellow",
            )
        else:
            say("    Rows beyond 20,000 : 0")
    elif limit_result is not None and limit_records:
        say(
            f"    Table size         : At least {ONEIP_DEEP_OFFSET_LIMIT + 1:,} rows",
            style="yellow",
        )
        say("    Exact table size   : Unknown (no total-count metadata)", style="yellow")
    elif limit_result is not None and not limit_records:
        if before is not None and before_records:
            say(f"    Table size         : Approximately {ONEIP_DEEP_OFFSET_LIMIT:,} rows")
        else:
            say(f"    Table size         : Fewer than {ONEIP_DEEP_OFFSET_LIMIT:,} rows")
    elif before is not None and before_records:
        say(
            f"    Table size         : At least {ONEIP_DEEP_OFFSET_LIMIT:,} rows",
            style="yellow",
        )
        say("    Exact table size   : Unknown because the server blocks deeper offsets", style="yellow")
    else:
        say("    Table size         : Could not be determined from offset tests", style="yellow")

    if cursor_supported:
        say("    Cursor paging      : SUPPORTED", style="green")
        say("    Next engineering   : We can replace the 20,000-row cap with afterId pagination.", style="green")
    elif cursor:
        say("    Cursor paging      : Cursor field exists, but afterId request was rejected", style="yellow")
    else:
        say("    Cursor paging      : No usable cursor exposed in the tested response", style="yellow")

    # Prefer a verified exact MAC query over partition scanning.  It is far
    # faster and avoids the global 20,000-row pagination issue entirely.
    if direct_mac_verified:
        say(
            f"    Direct MAC lookup   : VERIFIED using {verified_mac_styles[0]}",
            style="green",
        )
        say(
            "    Next engineering   : Use format-aware direct MAC lookup; only fall back to partitions on a true miss.",
            style="green",
        )
    elif switch_partition_viable:
        say(
            "    Alternate strategy : VERIFIED - partition One-IP lookups by switch_name",
            style="green",
        )
        say(
            "    Next engineering   : Enumerate switches, query each switch partition, and match target MACs locally.",
            style="green",
        )
    elif lan_partition_viable:
        say(
            "    Alternate strategy : VERIFIED - partition One-IP lookups by LAN segment",
            style="green",
        )
        say(
            "    Next engineering   : Enumerate LAN segments and search target MACs per partition.",
            style="green",
        )
    elif cursor_supported:
        say(
            "    Next engineering   : Replace the 20,000-row cap with afterId pagination.",
            style="green",
        )
    else:
        say(
            "    Alternate strategy : No semantically verified workaround confirmed yet",
            style="yellow",
        )
    say("\n[+] Diagnostic completed. No One-IP record values were printed.", style="green")
    return 0


def _is_invalid_mac_filter_error(exc: Exception | None) -> bool:
    """Return True when this NetBrain deployment rejects the One-IP ``mac`` filter."""
    if not isinstance(exc, NetBrainAPIError) or exc.http_status != 400:
        return False
    message = str(exc).casefold()
    return "parameter 'mac' is invalid" in message or 'parameter "mac" is invalid' in message


def _device_flat(record: dict[str, Any]) -> dict[str, str]:
    """Flatten one NetBrain device record for inventory lookups."""
    return {clean(k): stringify(v).strip() for k, v in flatten(record).items()}


def _device_hostname(record: dict[str, Any]) -> str:
    flat = _device_flat(record)
    return pick(flat, ["hostname", "name", "devicename"])


def _is_switch_device(record: dict[str, Any]) -> bool:
    """Return whether a CMDB device is a plausible Layer-2 switch partition.

    NetBrain device subtype names normally contain ``Switch``. Extra platform
    keywords keep the fallback useful when a driver uses a vendor/platform name
    instead of the literal word.
    """
    flat = _device_flat(record)
    type_text = " ".join(
        filter(
            None,
            [
                pick(flat, ["subtypename", "devicetypename", "drivertype", "drivername", "type"]),
                pick(flat, ["vendor"]),
                pick(flat, ["model", "platform"]),
            ],
        )
    ).casefold()
    keywords = (
        "switch", "nexus", "catalyst", "arista", "brocade", "extreme",
        "procurve", "comware", "fabric switch", "ethernet switch",
    )
    return any(keyword in type_text for keyword in keywords)


def _load_device_inventory(
    nb: NetBrain,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Read CMDB devices once and return hostname map, switch candidates, raw summaries."""
    path = "/ServicesAPI/API/V1/CMDB/Devices"
    inventory: dict[str, dict[str, Any]] = {}
    devices: list[dict[str, Any]] = []
    raw: list[dict[str, Any]] = []
    skip = 0
    limit = 100
    seen_pages: set[str] = set()

    while True:
        params = {"version": 1, "fullattr": 1, "skip": skip, "limit": limit}
        result = nb.try_call("GET", path, params=params)
        if result is None:
            raw.append({"path": path, "params": params, "api_error": str(nb.last_error or "unknown error")})
            break

        records = records_from(result)
        raw.append({"path": path, "params": params, "record_count": len(records)})
        if not records:
            break

        signature = json.dumps(records, sort_keys=True, ensure_ascii=False)
        if signature in seen_pages:
            raw.append({"path": path, "lookup_error": "Device inventory pagination repeated a page."})
            break
        seen_pages.add(signature)

        for record in records:
            hostname = _device_hostname(record)
            if hostname:
                inventory.setdefault(clean(hostname), record)
                devices.append(record)

        skip += len(records)
        if len(records) < limit:
            break

    switches = [record for record in devices if _is_switch_device(record)]
    # If NetBrain's device drivers do not label switches clearly, using the
    # complete device inventory is safer than silently disabling the fallback.
    if not switches:
        switches = devices
    return inventory, switches, raw


def _extract_record_macs(record: dict[str, Any]) -> set[str]:
    """Extract normalized MAC addresses from fields whose names indicate MAC."""
    values: set[str] = set()
    for key, value in flatten(record).items():
        if "mac" not in clean(str(key)):
            continue
        for candidate in MAC_RE.findall(stringify(value)):
            try:
                values.add(normalize_mac(candidate))
            except ValueError:
                continue
    return values


def _enrich_switch_metadata(row: dict[str, str], device: dict[str, Any] | None) -> None:
    """Add switch management IP/site/location without changing endpoint identity."""
    if not device:
        return
    flat = _device_flat(device)
    row["switch_ip"] = row.get("switch_ip") or pick(
        flat, ["mgmtip", "managementip", "managementaddress", "deviceip"]
    )
    row["site"] = row.get("site") or pick(flat, ["site", "sitepath"])
    row["location"] = row.get("location") or pick(flat, ["loc", "location"])


def resolve_mac_misses_by_switch_partitions(
    nb: NetBrain,
    rows: list[dict[str, str]],
    *,
    page_size: int = 1000,
    progress_callback: Callable[[int, int], None] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Verify unresolved MAC targets using ``switch_name`` partitions.

    RC4 behavior:
      * Direct dotted-lower MAC lookup remains the authoritative primary search.
      * Every direct miss may be checked across switch_name partitions.
      * ``VERIFIED_NOT_FOUND`` means the direct miss was also fully verified.
      * ``DIRECT_MAC_NOT_FOUND`` means the direct lookup returned no exact match
        but secondary partition verification was partial.
      * Partition/API/pagination problems are written to the runtime .log file.

    A secondary verification failure no longer changes a valid direct MAC miss
    into UNRESOLVED.
    """
    unresolved_rows: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        # Only a successful primary query that returned no exact match is eligible
        # for secondary verification. Primary API errors remain ERROR and are logged.
        if row.get("target_type") != "MAC" or row.get("status") != "not-found":
            continue
        try:
            mac = normalize_mac(row.get("target", ""))
        except ValueError:
            continue
        unresolved_rows.setdefault(mac, []).append(row)

    stats = {
        "requested": len(unresolved_rows),
        "switches": 0,
        "scanned": 0,
        "resolved": 0,
        "remaining": 0,
        "verified_not_found": 0,
        "partial_not_found": 0,
        "failed_switches": 0,
        "inventory_errors": 0,
        "pagination_limited": 0,
        "verification_complete": 0,
        "partitions_complete": 0,
        "partitions_incomplete": 0,
    }
    raw: list[dict[str, Any]] = []
    if not unresolved_rows:
        stats["verification_complete"] = 1
        return raw, stats

    inventory, switch_devices, inventory_raw = _load_device_inventory(nb)
    raw.extend(inventory_raw)
    inventory_errors = sum(
        1 for item in inventory_raw if item.get("api_error") or item.get("lookup_error")
    )
    stats["inventory_errors"] = inventory_errors
    if inventory_errors:
        log_event("ERROR", f"Device inventory returned {inventory_errors} API/pagination diagnostic error(s).")
        for item in inventory_raw:
            detail = item.get("api_error") or item.get("lookup_error")
            if detail:
                log_event("ERROR", f"Device inventory detail: {detail}")

    # Unique switch names, preserving CMDB order.
    candidates: list[str] = []
    seen_names: set[str] = set()
    for device in switch_devices:
        name = _device_hostname(device)
        key = clean(name)
        if name and key not in seen_names:
            seen_names.add(key)
            candidates.append(name)

    stats["switches"] = len(candidates)
    if progress_callback:
        progress_callback(0, stats["switches"])
    path = "/ServicesAPI/API/V1/CMDB/Topology/OneIPTable"
    count = max(1, min(page_size, 1000))

    # If inventory itself could not be enumerated, verification is incomplete.
    # We still scan any candidates that were successfully obtained because they
    # may resolve some targets, but remaining misses cannot be definitive.
    verification_problem = bool(inventory_errors or not candidates)
    if not candidates:
        log_event("WARNING", "Secondary MAC verification could not enumerate any candidate switch partitions.")

    for switch_name in candidates:
        if not unresolved_rows:
            break

        stats["scanned"] += 1
        begin = 0
        seen_pages: set[str] = set()
        partition_complete = False
        partition_failed = False

        while unresolved_rows:
            if begin >= ONEIP_DEEP_OFFSET_LIMIT:
                partition_failed = True
                stats["pagination_limited"] += 1
                reason = (
                    f"Switch partition '{switch_name}' reached the {ONEIP_DEEP_OFFSET_LIMIT:,}-row "
                    f"offset safety boundary at beginIndex={begin}; deeper offset pagination is unavailable."
                )
                log_event("WARNING", reason)
                raw.append({"path": path, "pagination_warning": reason})
                break

            params = {"switch_name": switch_name, "beginIndex": begin, "count": count}
            result = nb.try_call("GET", path, params=params)
            if result is None:
                partition_failed = True
                reason = str(nb.last_error or "unknown error")
                log_event(
                    "ERROR",
                    f"Switch partition '{switch_name}' API request failed at beginIndex={begin}: {reason}",
                )
                raw.append(
                    {
                        "path": path,
                        "params": {"switch_name": "<redacted>", "beginIndex": begin, "count": count},
                        "api_error": reason,
                    }
                )
                break

            if error := api_status_error(result):
                partition_failed = True
                log_event(
                    "ERROR",
                    f"Switch partition '{switch_name}' returned an API status error at beginIndex={begin}: {error}",
                )
                raw.append(
                    {
                        "path": path,
                        "params": {"switch_name": "<redacted>", "beginIndex": begin, "count": count},
                        "api_error": error,
                    }
                )
                break

            records = records_from(result)
            raw.append(
                {
                    "path": path,
                    "params": {"switch_name": "<redacted>", "beginIndex": begin, "count": count},
                    "record_count": len(records),
                }
            )
            if not records:
                partition_complete = True
                break

            signature = json.dumps(records, sort_keys=True, ensure_ascii=False)
            if signature in seen_pages:
                partition_failed = True
                reason = f"Switch partition '{switch_name}' repeated a page at beginIndex={begin}; pagination stopped."
                log_event("ERROR", reason)
                raw.append({"path": path, "lookup_error": reason})
                break
            seen_pages.add(signature)

            for record in records:
                matches = _extract_record_macs(record) & set(unresolved_rows)
                for mac in list(matches):
                    target = {"type": "MAC", "value": mac, "original": mac}
                    candidate_rows = useful_rows(target, [record], path)
                    if not candidate_rows:
                        continue
                    resolved = candidate_rows[0]
                    resolved["lookup_method"] = "SWITCH_PARTITION"
                    resolved["verification"] = "FALLBACK_FOUND"
                    switch_key = clean(resolved.get("switch_name") or switch_name)
                    _enrich_switch_metadata(resolved, inventory.get(switch_key))
                    resolved["notes"] = "Verified by switch_name partition fallback after direct MAC miss."
                    for original_row in unresolved_rows[mac]:
                        original_row.update(resolved)
                        original_row["target"] = mac
                        original_row["target_type"] = "MAC"
                        original_row["status"] = "found"
                    del unresolved_rows[mac]
                    stats["resolved"] += 1

            if not unresolved_rows:
                break

            begin += len(records)
            if len(records) < count:
                partition_complete = True
                break

        if partition_failed:
            stats["failed_switches"] += 1
            stats["partitions_incomplete"] += 1
            verification_problem = True
        elif partition_complete:
            stats["partitions_complete"] += 1
        elif unresolved_rows:
            # Defensive guard: the partition ended without a demonstrated EOF.
            stats["failed_switches"] += 1
            stats["partitions_incomplete"] += 1
            verification_problem = True
            log_event(
                "WARNING",
                f"Switch partition '{switch_name}' ended without an explicit completion condition.",
            )

        if progress_callback:
            progress_callback(stats["scanned"], stats["switches"])

    remaining_count = len(unresolved_rows)
    stats["remaining"] = remaining_count

    if remaining_count:
        full_inventory_scanned = stats["scanned"] == stats["switches"] and stats["switches"] > 0
        verification_complete = full_inventory_scanned and not verification_problem
        stats["verification_complete"] = int(verification_complete)

        for mac, target_rows in unresolved_rows.items():
            for row in target_rows:
                row["status"] = "not-found"
                if verification_complete:
                    row["lookup_method"] = "VERIFIED_NOT_FOUND"
                    row["verification"] = "COMPLETE"
                    note = (
                        "Direct MAC lookup returned no exact match and all switch partitions "
                        "were verified successfully."
                    )
                    stats["verified_not_found"] += 1
                else:
                    row["lookup_method"] = "DIRECT_MAC_NOT_FOUND"
                    row["verification"] = "PARTIAL"
                    note = (
                        "Direct MAC lookup returned no exact match. Secondary switch-partition "
                        "verification was partial; see the runtime log for partition diagnostics."
                    )
                    stats["partial_not_found"] += 1
                row["notes"] = "; ".join(filter(None, (row.get("notes", ""), note)))

        if not verification_complete:
            log_event(
                "WARNING",
                f"Secondary verification was partial: {stats['partitions_complete']} partition(s) complete, "
                f"{stats['partitions_incomplete']} incomplete. {stats['partial_not_found']} direct MAC miss(es) "
                "remain NOT FOUND based on the successful primary server-side MAC filter.",
            )
    else:
        # Every miss was resolved; no negative conclusion depends on completing
        # all remaining switch partitions.
        stats["verification_complete"] = 1

    return raw, stats


def oneip_lookup(
    nb: NetBrain, target: dict[str, str], *, scan: bool, count: int
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    """Lookup an IP or MAC in NetBrain's One-IP Table.

    v2.6.2 RC4 behavior:
      * IP  -> exact server-side ``ip`` filter.
      * MAC -> exact server-side ``mac`` filter. The default representation is
               Cisco dotted-lower (``aaaa.aaaa.aaaa``), verified by diagnostics.
      * A MAC miss returns immediately to the caller so the batch-level
        switch_name partition fallback can verify all misses together.
      * The global 20,000-row scan is never invoked automatically for MACs.
    """
    path = "/ServicesAPI/API/V1/CMDB/Topology/OneIPTable"
    page_size = max(1, min(count, 1000))
    raw: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # DIRECT IP LOOKUP
    # ------------------------------------------------------------------
    if target["type"] == "IP":
        params = {"ip": target["value"], "beginIndex": 0, "count": page_size}
        result = nb.try_call("GET", path, params=params)
        candidates = records_from(result) if result else []
        records = filter_target_records(candidates, target)

        if result:
            entry: dict[str, Any] = {"path": path, "params": params, "response": result}
            if error := api_status_error(result):
                entry["api_error"] = error
            raw.append(entry)
        elif nb.last_error:
            raw.append({"path": path, "params": params, "api_error": str(nb.last_error)})

        if nb.verbose:
            debug(
                f"One-IP exact IP query: records={len(candidates)}, matches={len(records)}"
            )

        if records:
            rows = useful_rows(target, records, path)
            for row in rows:
                row["lookup_method"] = "DIRECT_IP"
                row["verification"] = "PRIMARY"
            if rows:
                return rows, raw

        if not scan:
            return [], raw

    # ------------------------------------------------------------------
    # DIRECT MAC LOOKUP
    # ------------------------------------------------------------------
    else:
        if nb.mac_query_style == "auto":
            variants = mac_query_variants(target["value"], nb.oneip_mac_preferred_style)
        else:
            variants = [(nb.mac_query_style, format_mac(target["value"], nb.mac_query_style))]

        accepted_any = False
        for style, value in variants:
            params = {"mac": value, "beginIndex": 0, "count": page_size}
            result = nb.try_call("GET", path, params=params)

            if result is not None:
                accepted_any = True
                candidates = records_from(result)
                records = filter_target_records(candidates, target)
                entry: dict[str, Any] = {
                    "path": path,
                    "params": {"mac": f"<{style}>", "beginIndex": 0, "count": page_size},
                    "response": result,
                }
                if error := api_status_error(result):
                    entry["api_error"] = error
                raw.append(entry)

                if nb.verbose:
                    debug(
                        f"One-IP direct MAC style={style}: "
                        f"records={len(candidates)}, exact_matches={len(records)}"
                    )

                if records:
                    nb.oneip_mac_filter_supported = True
                    nb.oneip_mac_preferred_style = style
                    rows = useful_rows(target, records, path)
                    for row in rows:
                        row["lookup_method"] = "DIRECT_MAC"
                        row["verification"] = "PRIMARY"
                    if rows:
                        return rows, raw

                # In fixed-style mode, HTTP 200 with no exact match is a true
                # server-side miss. Do not waste calls on alternate notations.
                if nb.mac_query_style != "auto":
                    break
                continue

            # In auto mode only, notation-specific HTTP 400 is allowed to move
            # to the next representation. Other errors are preserved.
            if nb.mac_query_style == "auto" and _is_invalid_mac_filter_error(nb.last_error):
                raw.append(
                    {
                        "path": path,
                        "params": {"mac": f"<{style}>", "beginIndex": 0, "count": page_size},
                        "capability_warning": f"MAC representation {style} rejected by NetBrain.",
                    }
                )
                continue

            if nb.last_error:
                raw.append(
                    {
                        "path": path,
                        "params": {"mac": f"<{style}>", "beginIndex": 0, "count": page_size},
                        "api_error": str(nb.last_error),
                    }
                )
            break

        nb.oneip_mac_filter_supported = accepted_any
        # Return the miss. The batch-level switch partition fallback handles it
        # once all direct targets have completed.
        return [], raw

    # ------------------------------------------------------------------
    # OPTIONAL GLOBAL SCAN FOR IP MISSES ONLY
    # ------------------------------------------------------------------
    begin = 0
    seen_pages: set[str] = set()
    last_page: Any = None

    while True:
        if begin >= ONEIP_DEEP_OFFSET_LIMIT:
            cursor, cursor_field, _ = after_id_cursor(last_page, [])
            if cursor:
                if nb.verbose:
                    debug(
                        f"One-IP offset limit reached at {begin}; resuming with "
                        f"afterId from response metadata ({cursor_field})."
                    )
                return scan_oneip_after_id(nb, target, path, page_size, raw, cursor)

            raw.append(
                {
                    "path": path,
                    "params": {"ip": "", "beginIndex": begin, "count": page_size},
                    "scan_warning": (
                        f"One-IP optional IP scan stopped at {ONEIP_DEEP_OFFSET_LIMIT} rows to avoid "
                        "NetBrain deep-offset HTTP 400."
                    ),
                }
            )
            break

        params = {"ip": "", "beginIndex": begin, "count": page_size}
        result = nb.try_call("GET", path, params=params)
        if not result:
            if nb.last_error:
                raw.append({"path": path, "params": params, "api_error": str(nb.last_error)})
            break

        records = records_from(result)
        matches = filter_target_records(records, target)
        entry = {"path": path, "params": params, "record_count": len(records)}
        if error := api_status_error(result):
            entry["api_error"] = error
        raw.append(entry)

        if not records:
            break

        signature = json.dumps(records, sort_keys=True, ensure_ascii=False)
        if signature in seen_pages:
            raw.append(
                {
                    "path": path,
                    "params": params,
                    "lookup_error": "NetBrain returned the same page twice; scan stopped before completion.",
                }
            )
            break
        seen_pages.add(signature)

        if matches:
            rows = useful_rows(target, matches, path)
            for row in rows:
                row["lookup_method"] = "GLOBAL_IP_SCAN"
            if rows:
                return rows, raw

        last_page = result
        begin += len(records)

    return [], raw


def scan_oneip_after_id(
    nb: NetBrain,
    target: dict[str, str],
    path: str,
    page_size: int,
    raw: list[dict[str, Any]],
    cursor: str,
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    seen_cursors = {cursor}
    seen_pages: set[str] = set()
    while True:
        params = {"ip": "", "afterId": cursor, "count": page_size}
        result = nb.try_call("GET", path, params=params)
        if not result:
            if nb.last_error:
                raw.append({"path": path, "params": params, "api_error": str(nb.last_error)})
            break

        records = records_from(result)
        matches = filter_target_records(records, target)
        entry = {"path": path, "params": params, "record_count": len(records), "pagination": "afterId"}
        if error := api_status_error(result):
            entry["api_error"] = error
        raw.append(entry)
        if nb.verbose:
            status = ci_get(result, "statusCode") if isinstance(result, dict) else "unavailable"
            description = ci_get(result, "statusDescription") if isinstance(result, dict) else ""
            debug(
                f"One-IP cursor scan: rows={len(records)}, matches={len(matches)}, statusCode={status}, "
                f"description={description or 'N/A'}"
            )
        if not records:
            break

        signature = json.dumps(records, sort_keys=True, ensure_ascii=False)
        if signature in seen_pages:
            raw.append(
                {
                    "path": path,
                    "params": params,
                    "lookup_error": "NetBrain repeated an afterId page; the cursor did not advance safely.",
                }
            )
            break
        seen_pages.add(signature)
        if matches:
            rows = useful_rows(target, matches, path)
            if rows:
                return rows, raw
        if len(records) < page_size:
            break

        next_cursor, cursor_field, fields = after_id_cursor(result, records)
        if not next_cursor:
            raw.append(
                {
                    "path": path,
                    "params": params,
                    "lookup_error": (
                        "NetBrain returned a full afterId page without a next cursor/row ID "
                        f"(fields: {', '.join(fields) or 'none'})."
                    ),
                }
            )
            break
        if next_cursor in seen_cursors:
            raw.append(
                {
                    "path": path,
                    "params": params,
                    "lookup_error": f"NetBrain afterId cursor did not advance (field: {cursor_field}).",
                }
            )
            break
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    return [], raw


def after_id_cursor(
    response: Any, records: list[dict[str, Any]]
) -> tuple[str, str, list[str]]:
    """Extract a cursor from common NetBrain response metadata or the last row."""
    if isinstance(response, dict):
        for key, value in response.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
            if normalized in {"nextafterid", "nextid", "lastid", "nextcursor", "cursor"}:
                if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value).strip():
                    return str(value).strip(), str(key), list(response)

    row = records[-1] if records else {}
    fields = list(flatten(row))
    cursor_names = {
        "afterid",
        "oneipentryid",
        "oneiprecordid",
        "oneipid",
        "recordid",
        "rowid",
        "entryid",
        "itemid",
        "objectid",
        "id",
    }
    for key, value in row.items():
        normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
        if normalized in cursor_names and isinstance(value, (str, int)) and not isinstance(value, bool):
            if str(value).strip():
                return str(value).strip(), str(key), fields
    return "", "", fields


# ============================================================================
# SECTION 11 - RESULT PARSING, NORMALIZATION, AND CORRELATION
# ============================================================================

def filter_target_records(records: list[dict[str, Any]], target: dict[str, str]) -> list[dict[str, Any]]:
    wanted = normalize_mac(target["value"]) if target["type"] == "MAC" else clean(target["value"])
    matches = []
    for record in records:
        values = [stringify(value).strip() for value in flatten(record).values()]
        if target["type"] == "MAC":
            candidates = {
                normalize_mac(mac)
                for value in values
                for mac in MAC_RE.findall(value)
            }
            if wanted in candidates:
                matches.append(record)
        else:
            normalized = [clean(value) for value in values]
            if wanted in normalized or any(wanted in value for value in normalized):
                matches.append(record)
    return matches


def mac_samples(records: list[dict[str, Any]], limit: int = 5) -> list[str]:
    samples: list[str] = []
    for record in records:
        for key, value in flatten(record).items():
            if "mac" not in clean(key):
                continue
            for candidate in MAC_RE.findall(stringify(value)):
                normalized = normalize_mac(candidate)
                if normalized not in samples:
                    samples.append(normalized)
                    if len(samples) == limit:
                        return samples
    return samples


def useful_rows(target: dict[str, str], records: list[dict[str, Any]], source: str) -> list[dict[str, str]]:
    rows = [row_from(target, record, "found", source) for record in records]
    return [row for row in rows if has_real_endpoint_data(row, target)]


def merge_rows(*rows: dict[str, str]) -> dict[str, str]:
    merged = rows[0].copy()
    sources = [merged["source_api"]] if merged["source_api"] else []
    for row in rows[1:]:
        for column in COLS:
            if column not in {"notes", "source_api"} and not merged[column] and row.get(column):
                merged[column] = row[column]
        if row.get("source_api") and row["source_api"] not in sources:
            sources.append(row["source_api"])
        if row.get("notes") and row["notes"] not in merged["notes"]:
            merged["notes"] = "; ".join(filter(None, (merged["notes"], row["notes"])))
    merged["source_api"] = "; ".join(sources)
    return merged


def correlate_mac_targets(rows: list[dict[str, str]]) -> None:
    """Reuse verified IP lookup rows to resolve matching MAC targets in the same input."""
    by_mac: dict[str, dict[str, str]] = {}
    for row in rows:
        if row.get("status") != "found" or row.get("target_type") != "IP":
            continue
        mac = row.get("endpoint_mac", "")
        if mac:
            try:
                by_mac.setdefault(normalize_mac(mac), row)
            except ValueError:
                continue

    for row in rows:
        # Only a successful primary query that returned no exact match is eligible
        # for secondary verification. Primary API errors remain ERROR and are logged.
        if row.get("target_type") != "MAC" or row.get("status") != "not-found":
            continue
        match = by_mac.get(normalize_mac(row["target"]))
        if not match:
            continue
        resolved = merge_rows(match, row)
        resolved.update({"target": row["target"], "target_type": "MAC", "status": "found", "lookup_method": "IP_CORRELATION"})
        resolved["endpoint_mac"] = normalize_mac(row["target"])
        note = "MAC correlacionada con un resultado IP del mismo archivo"
        resolved["notes"] = "; ".join(filter(None, (resolved["notes"], note)))
        row.update(resolved)


def has_real_endpoint_data(row: dict[str, str], target: dict[str, str]) -> bool:
    useful_fields = [
        "endpoint_mac",
        "endpoint_name",
        "switch_name",
        "switch_ip",
        "switch_port",
        "vlan",
        "vrf",
        "site",
        "location",
        "device_type",
        "vendor",
        "model",
        "serial",
    ]
    if any(row.get(field) for field in useful_fields):
        return True
    if target["type"] == "MAC" and row.get("endpoint_ip"):
        return True
    return False


def records_from(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if not isinstance(data, dict):
        return []
    for key in (
        "OneIPList oneIPList oneIpList oneIPTable oneIpTable oneiptable oneIPTables oneIpTables oneIpTableList "
        "ipTable iptable ipTables ipList table list records rows "
        "connectedSwitchPorts connectedSwitchPort switchPorts switchPort ports "
        "interfaces results data items devices"
    ).split():
        value = ci_get(data, key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
        if isinstance(value, dict):
            return records_from(value) or [value]
    metadata = {"statuscode", "statusdescription", "totalresultcount", "total", "count"}
    clean_keys = {clean(k) for k in data}
    if clean_keys <= metadata or clean_keys <= (metadata | IGNORE_KEYS):
        return []
    return [data]


def row_from(target: dict[str, str], rec: dict[str, Any], status: str, source: str) -> dict[str, str]:
    flat = {
        clean(k): stringify(v)
        for k, v in flatten(rec).items()
        if clean(k) not in IGNORE_KEYS
    }
    row = empty_row(target, status)
    row["source_api"] = source
    if "OneIPTable" in source:
        row["lookup_method"] = "DIRECT_MAC" if target["type"] == "MAC" else "DIRECT_IP"
    elif "ConnectedSwitchPort" in source:
        row["lookup_method"] = "CONNECTED_SWITCH_PORT"
    elif source.endswith("/CMDB/Devices"):
        row["lookup_method"] = "DEVICE_LOOKUP"
    for col, aliases in ALIASES.items():
        row[col] = pick(flat, aliases)
    if row["switch_port"]:
        switch_name, port_name = split_switch_port(row["switch_port"])
        row["switch_name"] = row["switch_name"] or switch_name
        row["switch_port"] = port_name
    if row["endpoint_mac"] and MAC_RE.fullmatch(row["endpoint_mac"]):
        row["endpoint_mac"] = normalize_mac(row["endpoint_mac"])
    enrich_from_gui_text(row, " ".join(flat.values()))
    if target["type"] == "IP" and not row["endpoint_ip"]:
        row["endpoint_ip"] = target["value"]
    if target["type"] == "MAC" and not row["endpoint_mac"]:
        row["endpoint_mac"] = target["value"]
    row["notes"] = row["notes"] or "; ".join(f"{k}={v[:60]}" for k, v in list(flat.items())[:4] if v)
    return row


def enrich_from_gui_text(row: dict[str, str], text: str) -> None:
    mac = re.search(r"MAC Address:\s*([0-9a-fA-F.:-]{12,17})", text, re.I)
    ip = re.search(r"IP Address:\s*([0-9a-fA-F:.]+)", text, re.I)
    port = re.search(r"Connected Switch Port:\s*([^\s,;]+)", text, re.I)
    if mac and not row["endpoint_mac"]:
        row["endpoint_mac"] = normalize_mac(mac.group(1))
    if ip and not row["endpoint_ip"]:
        row["endpoint_ip"] = ip.group(1)
    if port:
        switch, interface = split_switch_port(port.group(1))
        row["switch_name"] = switch or row["switch_name"]
        row["switch_port"] = interface or row["switch_port"]


def split_switch_port(value: str) -> tuple[str, str]:
    """Split NetBrain's Switch.Interface value and keep only the interface."""
    value = value.strip()
    match = INTERFACE_RE.search(value)
    if match and match.start() and value[match.start() - 1] == ".":
        return value[: match.start() - 1].rstrip("."), value[match.start() :]
    if "." in value:
        switch, _, interface = value.rpartition(".")
        return switch, interface
    return "", value


def empty_row(target: dict[str, str], status: str) -> dict[str, str]:
    row = {col: "" for col in COLS}
    row.update({"target": target["value"], "target_type": target["type"], "status": status})
    if status == "not-found":
        row["lookup_method"] = "DIRECT_MAC" if target["type"] == "MAC" else "DIRECT_IP"
    return row


def flatten(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out = {}
    for key, value in data.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        out.update(flatten(value, name) if isinstance(value, dict) else {name: value})
    return out


def clean(text: str) -> str:
    return re.sub(r"[^0-9a-z]", "", text.casefold())


def pick(flat: dict[str, str], aliases: list[str]) -> str:
    aliases = [clean(a) for a in aliases]
    for alias in aliases:
        if alias in flat:
            return flat[alias]
    suffix_aliases = [a for a in aliases if a not in {"ip", "mac", "name", "type", "host"}]
    return next(
        (v for k, v in flat.items() if k not in IGNORE_KEYS and any(k.endswith(a) for a in suffix_aliases)),
        "",
    )


def ci_get(data: dict[str, Any], wanted: str) -> Any:
    return next((v for k, v in data.items() if str(k).casefold() == wanted.casefold()), None)


def api_status_error(data: Any) -> str:
    if not isinstance(data, dict):
        return ""
    code = ci_get(data, "statusCode")
    if code is None or str(code) in {"0", "200", "790200"}:
        return ""
    description = ci_get(data, "statusDescription") or "Unknown NetBrain API error"
    return f"statusCode={code}: {description}"


def stringify(value: Any) -> str:
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)


# ============================================================================
# SECTION 12 - CSV AND TERMINAL OUTPUT
# ============================================================================

def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLS)
        writer.writeheader()
        writer.writerows(rows)


def say(message: str, *, error: bool = False, style: str | None = None) -> None:
    """Print plain operational text through Rich when it is installed."""
    if console and not error:
        console.print(Text(message, style=style) if style and Text else message)
    else:
        print(message, file=sys.stderr if error else sys.stdout)


def debug(message: str) -> None:
    """Verbose diagnostics go to the runtime log to keep terminal output concise."""
    log_event("DEBUG", message)


def show_banner() -> None:
    width = 68
    say("=" * width, style="green")
    say("NETBRAIN ENDPOINT LOOKUP".center(width), style="green")
    say("=" * width, style="green")


def display_search_summary(
    rows: list[dict[str, str]],
    output: Path,
    log_path: Path,
) -> None:
    """Display only the concise user-facing summary requested for normal runs."""
    width = 68
    total = len(rows)
    ip_targets = sum(row.get("target_type") == "IP" for row in rows)
    mac_targets = sum(row.get("target_type") == "MAC" for row in rows)
    found = sum(row.get("status") == "found" for row in rows)
    not_found = sum(row.get("status") == "not-found" for row in rows)
    errors = sum(row.get("status") == "error" for row in rows)

    say("\n" + "=" * width, style="green")
    say("SUMMARY".center(width), style="green")
    say("=" * width, style="green")
    say("[+] Input", style="green")
    say(f"    Total targets          : {total}", style="green")
    say(f"    IP targets             : {ip_targets}", style="green")
    say(f"    MAC targets            : {mac_targets}", style="green")
    say("", style="green")
    say("[+] Results", style="green")
    say(f"    Found                  : {found}", style="green")
    say(f"    Not found              : {not_found}", style="green")
    say(f"    Errors                 : {errors}", style="green")
    say("[+] Output", style="green")
    say(f"    CSV report             : {output}", style="green")
    say(f"    Diagnostic log         : {log_path}", style="green")
    say("", style="green")
    say("=" * width, style="green")


def display_results(rows: list[dict[str, str]]) -> None:
    """Display the concise result table. Method/Hostname remain available in CSV/log data."""
    columns = [
        ("Target", "target"),
        ("Type", "target_type"),
        ("Status", "status"),
        ("Endpoint IP", "endpoint_ip"),
        ("MAC Address", "endpoint_mac"),
        ("Switch", "switch_name"),
        ("Switch IP", "switch_ip"),
        ("Interface", "switch_port"),
        ("Port Description", "port_description"),
    ]
    say("\nNetBrain Endpoint Results", style="green")
    if console and Table and Text:
        table = Table(box=box.SQUARE, show_lines=False, expand=True, border_style="green", header_style="green")
        for heading, _ in columns:
            table.add_column(heading, no_wrap=True, overflow="ellipsis")
        for row in rows:
            status = row["status"]
            label = {"found": "FOUND", "not-found": "NOT FOUND", "error": "ERROR"}.get(status, status.upper())
            color = {"found": "green", "not-found": "yellow", "error": "red"}.get(status, "")
            values = [row.get(key, "") for _, key in columns]
            values[2] = Text(label, style=color)
            if row.get("target_type") == "INVALID":
                values[1] = Text("INVALID", style="red")
            table.add_row(*values)
        console.print(table)
        return

    say(" | ".join(heading for heading, _ in columns))
    for row in rows:
        values = [row.get(key, "") for _, key in columns]
        values[2] = {"found": "FOUND", "not-found": "NOT FOUND", "error": "ERROR"}.get(
            row["status"], row["status"].upper()
        )
        say(" | ".join(values))


def report_error(message: str, code: int) -> int:
    """Show a short actionable error in terminal and keep technical detail in the log."""
    clean_message = message.strip()
    clean_message = re.sub(r"^\[-\]\s*ERROR:\s*", "", clean_message, flags=re.I)
    log_event("ERROR", clean_message)
    log_execution_time()
    say(f"[-] ERROR: {clean_message}", error=True)
    if LOG_PATH is not None:
        say(f"    Diagnostic log: {LOG_PATH.resolve()}", error=True)
    return code


# ============================================================================
# SECTION 13 - PROGRAM ENTRY POINT AND ERROR HANDLING
# ============================================================================

if __name__ == "__main__":
    try:
        exit_code = main()
    except KeyboardInterrupt:
        exit_code = report_error("Cancelled by user.", 130)
    except AuthenticationError as exc:
        log_event("ERROR", f"Authentication failure detail: {exc}")
        exit_code = report_error("NetBrain authentication failed.", 3)
    except NetBrainUnreachable as exc:
        log_event("ERROR", f"Reachability failure detail: {exc}")
        exit_code = report_error("Unable to reach NetBrain server.", 4)
    except NetBrainAPIError as exc:
        log_event("ERROR", f"API failure detail: {exc}")
        exit_code = report_error("NetBrain API request failed.", 5)
    except NetBrainError as exc:
        exit_code = report_error(str(exc), 1)
    except OSError as exc:
        log_event("ERROR", f"Operating system error: {exc}")
        exit_code = report_error("Operating system/file error. See diagnostic log for details.", 1)
    except Exception as exc:
        log_event("ERROR", f"Unexpected {type(exc).__name__}: {exc}")
        exit_code = report_error(f"Unexpected error ({type(exc).__name__}).", 1)
    raise SystemExit(exit_code)
