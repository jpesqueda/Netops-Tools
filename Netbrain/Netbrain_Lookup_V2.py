#!/usr/bin/env python3
"""
NetBrain Endpoint Lookup
========================

Description:
    Searches NetBrain endpoint information using IPv4 or MAC addresses.
    Automatically detects target types, supports single and file lookups,
    displays a concise terminal table, and exports complete results to CSV.

Author:
    Peskicorp

Version:
    2.4.0

Requirements:
    Python 3.10+
    rich

Installation:
    pip install rich

Security / Sanitization:
    This source file contains no production server names, usernames, passwords,
    tenant/domain names, IP addresses, MAC addresses, serial numbers, or site names.
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
import re
import ssl
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

try:
    from rich import box
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
except ImportError:
    box = Console = Table = Text = None


# ============================================================================
# SECTION 02 - GLOBAL CONFIGURATION AND NETBRAIN API PATHS
# ============================================================================

SESSION = "/ServicesAPI/API/V1/Session"
DEFAULT_OUTPUT = "netbrain_endpoint_report.csv"
ONEIP_DEEP_OFFSET_LIMIT = 20000
VERSION = "NetBrain Endpoint Lookup 2.4.0"
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
        self.password = password
        self.auth_id = args.auth_id
        self.timeout = args.timeout
        self.verify_tls = not args.insecure
        self.verbose = args.verbose
        self.headers = {"Content-Type": "application/json", "Accept": "application/json"}
        self.last_error: Exception | None = None

        # Capability/cache state for NetBrain releases where the One-IP Table
        # documents a ``mac`` filter but the deployed API rejects it with HTTP 400.
        # In that case we transparently build a bounded One-IP cache once and
        # reuse it for every MAC target instead of failing every lookup.
        self.oneip_mac_filter_supported: bool | None = None
        self.oneip_cache: list[dict[str, Any]] | None = None
        self.oneip_cache_complete = False
        self.oneip_cache_warning = ""

    # -------------------------------------------------------------------------
    # AUTHENTICATION - REQUESTING TOKEN
    # -------------------------------------------------------------------------
    # Sends username/password to the NetBrain Session API. If authentication is
    # successful, NetBrain returns a token that is added to subsequent requests.
    def login(self) -> None:
        body = {"username": self.user, "password": self.password}
        if self.auth_id:
            body["authentication_id"] = self.auth_id
        try:
            response = self.call("POST", SESSION, body=body, auth=False)
            token = response.get("token") if isinstance(response, dict) else None
        except NetBrainAPIError as exc:
            if exc.http_status in {400, 401, 403}:
                raise AuthenticationError("NetBrain authentication failed.") from exc
            raise
        finally:
            # Do not keep the clear-text password longer than necessary.
            self.password = ""
            body["password"] = ""
        if not token:
            raise AuthenticationError("NetBrain authentication failed.")
        self.headers.update({"Token": token, "token": token})

    # -------------------------------------------------------------------------
    # SESSION - DELETING TOKEN / LOGOUT
    # -------------------------------------------------------------------------
    def logout(self) -> None:
        if "Token" in self.headers:
            self.try_call("DELETE", SESSION)

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
                    say(f"    Status : Reachable (HTTP {resp.status})", style="green")
                    return
            except HTTPError as exc:
                say(f"    Status : Reachable (HTTP {exc.code})", style="green")
                return
            except URLError as exc:
                last_error = exc
                if self.verbose:
                    debug(f"Connectivity probe failed: {type(exc).__name__}")
        raise NetBrainUnreachable("Unable to reach NetBrain server.") from last_error

    # -------------------------------------------------------------------------
    # REST CLIENT - SENDING AUTHENTICATED API REQUESTS
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
        req = Request(url, data=data, headers=self.headers.copy(), method=method.upper())
        ctx = None if self.verify_tls else ssl._create_unverified_context()

        if self.verbose:
            debug(f"Connecting to NetBrain API: {method.upper()} {url}")
        try:
            with urlopen(req, timeout=self.timeout, context=ctx) as resp:
                code = resp.status
                text = resp.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            code = exc.code
            text = exc.read().decode("utf-8", errors="replace")
        except URLError as exc:
            raise NetBrainUnreachable("Unable to reach NetBrain server.") from exc

        if self.verbose:
            debug(f"HTTP status: {code}")
        if code != 200:
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
            suffix = f": {detail[:500]}" if detail else ""
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
        except Exception as exc:
            self.last_error = exc
            if self.verbose:
                debug(f"Request unavailable: {method.upper()} {path}: {exc}")
            return None


# ============================================================================
# SECTION 05 - MAIN WORKFLOW
# ============================================================================

def main() -> int:
    args = parse_args()
    show_banner()
    if args.verbose:
        debug(f"Script file: {Path(__file__).resolve()}")
    if args.insecure:
        say("[!] WARNING: SSL certificate verification is disabled.", style="yellow")

    # ---------------------------------------------------------------------
    # DIAGNOSTIC MODE - ONE-IP TABLE CAPABILITIES
    # ---------------------------------------------------------------------
    # This mode does not require --host or --hosts-file. It authenticates to
    # NetBrain, inspects One-IP pagination behavior, and reports only metadata
    # and counts. It intentionally does not print IPs, MACs, hostnames, or raw
    # One-IP records.
    if args.oneip_info:
        url = (args.url or input("NetBrain URL: ")).strip().rstrip("/")
        if not url:
            say("[-] ERROR: NetBrain URL is required.", error=True)
            return 2
        user = args.username or input("NetBrain Username: ").strip()
        password = args.password if args.password is not None else getpass.getpass("NetBrain Password: ")
        nb = NetBrain(url, user, password, args)
        try:
            say("[+] Validating NetBrain connectivity...", style="green")
            say(f"    URL    : {url}", style="green")
            nb.validate_connection()
            say("[+] Connecting to NetBrain API...", style="green")
            nb.login()
            say("    Login  : Successful", style="green")
            say("    Token  : Received", style="green")
            select_domain(nb, args.tenant, args.domain)
            return run_oneip_diagnostics(nb, args.oneip_count)
        finally:
            nb.logout()

    if args.host is None and args.hosts_file is None:
        say("[-] ERROR: Use --host, --hosts-file, or --oneip-info.", error=True)
        return 2

    if args.host is not None:
        target = make_target(args.host.strip())
        if target["type"] == "INVALID":
            say(f"[-] ERROR: Invalid endpoint: {target['value']}", error=True)
            return 2
        targets = [target]
    else:
        hosts_file = Path(args.hosts_file)
        try:
            targets = load_targets(hosts_file)
        except (OSError, UnicodeError):
            say(f"[-] ERROR: Hosts file not found: {hosts_file}", error=True)
            return 2
    if not targets:
        say("[-] ERROR: Hosts file contains no targets.", error=True)
        return 2

    rows: list[dict[str, str]] = []
    raw: list[dict[str, Any]] = []
    valid_targets = [target for target in targets if target["type"] != "INVALID"]
    for target in targets:
        debug_target(target["value"], target, args.verbose)
    if valid_targets:
        url = (args.url or input("NetBrain URL: ")).strip().rstrip("/")
        if not url:
            say("[-] ERROR: NetBrain URL is required.", error=True)
            return 2
        # Credentials are supplied at runtime. Nothing is hardcoded in the source.
        user = args.username or input("NetBrain Username: ").strip()
        password = args.password if args.password is not None else getpass.getpass("NetBrain Password: ")
        nb = NetBrain(url, user, password, args)
        try:
            say("[+] Validating NetBrain connectivity...", style="green")
            say(f"    URL    : {url}", style="green")
            nb.validate_connection()
            say("[+] Connecting to NetBrain API...", style="green")
            nb.login()
            say("    Login  : Successful", style="green")
            say("    Token  : Received", style="green")
            select_domain(nb, args.tenant, args.domain)
            say(f"[+] Searching {len(valid_targets)} endpoint(s)...", style="green")
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
                for result_row in target_rows:
                    if result_row["status"] in {"not-found", "error"} and result_row.get("notes"):
                        say(f"[WARN] {target['value']}: {result_row['notes']}", style="yellow")
                rows.extend(target_rows)
                raw.append({"target": target["value"], "responses": target_raw})
                if args.verbose:
                    debug("Endpoint lookup completed")
        finally:
            nb.logout()
    else:
        rows.extend(invalid_row(target) for target in targets)

    correlate_mac_targets(rows)
    rows = [{column: row.get(column) or "N/A" for column in COLS} for row in rows]
    output = Path(args.output or DEFAULT_OUTPUT)
    write_csv(output, rows)
    if args.raw_json:
        Path(args.raw_json).write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    display_results(rows)
    found = sum(row["status"] == "found" for row in rows)
    has_errors = any(row["status"] == "error" for row in rows)
    say(
        "[!] Lookup finished with errors; some targets may be incomplete."
        if has_errors
        else "[+] Lookup completed successfully.",
        style="yellow" if has_errors else "green",
    )
    say(f"[+] Endpoints found : {found}", style="green")
    say(f"[+] CSV report      : {output.resolve()}", style="green")
    return 5 if has_errors else 0


# ============================================================================
# SECTION 06 - COMMAND-LINE ARGUMENTS
# ============================================================================

def parse_args() -> argparse.Namespace:
    examples = """USAGE
  python netbrain_endpoint_lookup.py --url URL --host TARGET
  python netbrain_endpoint_lookup.py --url URL --hosts-file FILE
  python netbrain_endpoint_lookup.py --url URL --oneip-info

EXAMPLES
  # Generic IPv4 example (192.168.1.X)
  python netbrain_endpoint_lookup.py --url https://netbrain.example.local --host 192.168.1.10
  python netbrain_endpoint_lookup.py --url https://netbrain.example.local --host aa:aa:aa:aa:aa:aa
  python netbrain_endpoint_lookup.py --url https://netbrain.example.local --host aa-aa-aa-aa-aa-aa
  python netbrain_endpoint_lookup.py --url https://netbrain.example.local --hosts-file hosts.txt
  python netbrain_endpoint_lookup.py --url https://netbrain.example.local --hosts-file hosts.txt --insecure
  python netbrain_endpoint_lookup.py --url https://netbrain.example.local --hosts-file hosts.txt --user USERNAME --insecure
  python netbrain_endpoint_lookup.py --url https://netbrain.example.local --hosts-file hosts.txt --output endpoints.csv

  # One-IP Table diagnostic mode (no endpoint target required)
  python netbrain_endpoint_lookup.py --url https://netbrain.example.local --oneip-info --insecure --user USERNAME"""
    p = argparse.ArgumentParser(
        description=(
            "DESCRIPTION\n"
            "Search NetBrain endpoints by IPv4 or MAC address. --host detects the target type automatically; "
            "--host and --hosts-file are mutually exclusive."
        ),
        epilog=examples,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"{VERSION}\nAuthor: Peskicorp")
    inputs = p.add_argument_group("INPUT OPTIONS")
    inputs.add_argument("--url", help="NetBrain base URL, e.g. https://netbrain.example.local")
    target_input = inputs.add_mutually_exclusive_group(required=False)
    target_input.add_argument("--host", help="Single IPv4 or MAC target; type is detected automatically")
    target_input.add_argument("--hosts-file", help="Text file with one or more IP/MAC targets")

    auth = p.add_argument_group("AUTHENTICATION")
    auth.add_argument("-u", "--user", "--username", dest="username", help="NetBrain username; prompted if omitted")
    auth.add_argument(
        "-p", "--password", help="Password; prompted securely if omitted. CLI use may expose it in shell history/process listings."
    )
    auth.add_argument("--auth-id", help="authentication_id if required by the NetBrain environment")

    ssl_options = p.add_argument_group("SSL OPTIONS")
    ssl_options.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification (not recommended)")

    output = p.add_argument_group("OUTPUT OPTIONS")
    output.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help=f"CSV output path (default: {DEFAULT_OUTPUT})")
    output.add_argument(
        "--raw-json",
        help="Save raw API responses to JSON (WARNING: runtime output may contain live network data)",
    )

    advanced = p.add_argument_group("NETBRAIN OPTIONS")
    advanced.add_argument("--tenant", help="Tenant name or ID")
    advanced.add_argument("--domain", help="Domain name or ID")
    advanced.add_argument(
        "--oneip-info",
        action="store_true",
        help=(
            "Run a sanitized One-IP Table diagnostic: inspect total-count metadata, "
            "the 20,000-row offset boundary, and afterId cursor support. No host target required."
        ),
    )
    advanced.add_argument("--endpoint-path", action="append", help="Additional switch-port endpoint to try")
    advanced.add_argument(
        "--oneip-scan",
        action="store_true",
        help=(
            "Fallback: scan the One-IP Table when exact ip/mac lookup returns no match. "
            "Disabled by default because large tables may reject deep offsets."
        ),
    )
    advanced.add_argument(
        "--no-oneip-scan",
        action="store_true",
        help="Compatibility flag; explicitly keep full One-IP Table scanning disabled",
    )
    advanced.add_argument("--oneip-count", type=int, default=1000, help="Rows per One-IP Table page (max: 1000)")
    advanced.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds (default: 30)")
    advanced.add_argument("-v", "--verbose", action="store_true", help="Show target and request diagnostics; secrets are omitted")
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

    nb.call(
        "PUT",
        "/ServicesAPI/API/V1/Session/CurrentDomain",
        body={"tenantId": tenant["tenantId"], "domainId": domain["domainId"]},
    )
    say(f"    Domain : {tenant.get('tenantName')} / {domain.get('domainName')}", style="green")


def choose(items: list[dict[str, Any]], wanted: str | None, name: str, item_id: str, label: str) -> dict[str, Any] | None:
    if not items:
        say(f"[WARN] Could not list {label}; continuing without selecting it.", error=True)
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


def mac_query_values(mac: str) -> list[str]:
    """Return common MAC representations accepted by different NetBrain releases.

    NetBrain documentation shows Cisco dotted notation, but real deployments may
    normalize the same MAC differently.  Try the indexed ``mac`` query with a
    small set of exact representations instead of scanning the complete One-IP
    table.
    """
    digits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(digits) != 12:
        return [mac]

    dotted = f"{digits[:4]}.{digits[4:8]}.{digits[8:]}"
    colon = ":".join(digits[i : i + 2] for i in range(0, 12, 2))
    hyphen = "-".join(digits[i : i + 2] for i in range(0, 12, 2))
    compact = digits

    values = [
        dotted.upper(),
        dotted.lower(),
        colon.upper(),
        colon.lower(),
        hyphen.upper(),
        hyphen.lower(),
        compact.upper(),
        compact.lower(),
    ]
    # Preserve order while removing duplicates.
    return list(dict.fromkeys(values))


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
    # DOCUMENTED FILTER CAPABILITY TESTS
    # ------------------------------------------------------------------
    # NetBrain public One-IP documentation describes filters including ip,
    # mac, lan, and switch_name. The deployment already showed that "mac"
    # is rejected, so test all four using values sampled internally from the
    # first page. Sample values are never printed.
    sample_ip = _first_record_value(first_records, "ip")
    sample_mac = _first_record_value(first_records, "mac")
    sample_lan = _first_record_value(first_records, "lanSegment", "lan")
    sample_switch = _first_record_value(first_records, "switchName", "switch_name")

    filter_tests: dict[str, tuple[str, int, str]] = {}
    for label, parameter, sample in (
        ("ip", "ip", sample_ip),
        ("mac", "mac", sample_mac),
        ("lan", "lan", sample_lan),
        ("switch_name", "switch_name", sample_switch),
    ):
        filter_tests[label] = _test_oneip_filter(nb, path, parameter, sample)

    say("\n[+] Testing One-IP partition/filter capabilities...", style="green")
    for label in ("ip", "mac", "lan", "switch_name"):
        state, rows_count, error = filter_tests[label]
        if state == "SUPPORTED":
            say(f"    {label:<16}: SUPPORTED ({rows_count} row(s) returned)", style="green")
        elif state == "NO_SAMPLE":
            say(f"    {label:<16}: NOT TESTED (no sample value in first page)", style="yellow")
        else:
            lower = error.casefold()
            if "invalid parameter" in lower:
                reason = "invalid parameter"
            elif "400" in lower:
                reason = "HTTP 400"
            else:
                reason = "request rejected"
            say(f"    {label:<16}: REJECTED ({reason})", style="yellow")
            if nb.verbose:
                debug(f"One-IP filter test {label}: {error}")

    # If switch_name is supported, make one additional partition paging probe.
    # This does not expose the switch name. It only tells us whether a filtered
    # partition can be paged independently.
    switch_partition_viable = False
    switch_state, switch_rows, _ = filter_tests["switch_name"]
    if switch_state == "SUPPORTED" and sample_switch:
        probe_params = {
            "switch_name": sample_switch,
            "beginIndex": 100,
            "count": 1,
        }
        probe_result, probe_records, probe_error = _safe_oneip_request(nb, path, probe_params)
        if probe_result is not None:
            switch_partition_viable = True
            say(
                f"    switch partition   : PAGING ACCEPTED "
                f"(offset 100 returned {len(probe_records)} row(s))",
                style="green",
            )
        else:
            say("    switch partition   : FILTER WORKS; paging probe rejected", style="yellow")
            if nb.verbose:
                debug(f"switch_name partition paging probe: {probe_error}")

    lan_partition_viable = filter_tests["lan"][0] == "SUPPORTED"

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

    # Recommend a tested alternative only when the deployment actually accepts it.
    if switch_partition_viable:
        say(
            "    Alternate strategy : SUPPORTED - partition One-IP lookups by switch_name",
            style="green",
        )
        say(
            "    Next engineering   : Enumerate switches, query each switch partition, "
            "and match target MACs locally.",
            style="green",
        )
    elif lan_partition_viable:
        say(
            "    Alternate strategy : POSSIBLE - partition One-IP lookups by LAN segment",
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
            "    Alternate strategy : No tested partition workaround confirmed yet",
            style="yellow",
        )
        say(
            "    Next engineering   : Inspect deployment-specific APIs or NetBrain support metadata.",
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


def _build_oneip_cache(
    nb: NetBrain, path: str, page_size: int
) -> tuple[list[dict[str, Any]], bool, str]:
    """Build a reusable, bounded One-IP cache for MAC fallback lookups.

    Some NetBrain installations reject ``?mac=...`` even though other releases
    document it.  Scanning once and caching the result avoids repeating a large
    table walk for every MAC address.  The scan stops before the known deep
    offset boundary so it does not generate the HTTP 400 seen in older code.
    """
    if nb.oneip_cache is not None:
        return nb.oneip_cache, nb.oneip_cache_complete, nb.oneip_cache_warning

    cache: list[dict[str, Any]] = []
    begin = 0
    seen_pages: set[str] = set()
    warning = ""
    complete = False

    say(
        "[+] NetBrain does not accept the One-IP MAC filter; "
        "building a reusable One-IP cache...",
        style="yellow",
    )

    while begin < ONEIP_DEEP_OFFSET_LIMIT:
        fetch_count = min(page_size, ONEIP_DEEP_OFFSET_LIMIT - begin)
        params = {"ip": "", "beginIndex": begin, "count": fetch_count}
        result = nb.try_call("GET", path, params=params)

        if not result:
            warning = f"One-IP fallback scan stopped at row {begin}: {nb.last_error or 'empty response'}"
            break

        api_error = api_status_error(result)
        if api_error:
            warning = f"One-IP fallback scan stopped at row {begin}: {api_error}"
            break

        records = records_from(result)
        if not records:
            complete = True
            break

        signature = json.dumps(records, sort_keys=True, ensure_ascii=False)
        if signature in seen_pages:
            warning = "NetBrain returned the same One-IP page twice; fallback scan stopped safely."
            break
        seen_pages.add(signature)

        cache.extend(records)
        begin += len(records)

        if nb.verbose and (begin % 5000 == 0 or len(records) < fetch_count):
            debug(f"One-IP MAC fallback cache: {begin} row(s) loaded")

        if len(records) < fetch_count:
            complete = True
            break

    if not complete and not warning and begin >= ONEIP_DEEP_OFFSET_LIMIT:
        warning = (
            f"One-IP MAC fallback scanned the first {ONEIP_DEEP_OFFSET_LIMIT} rows. "
            "This NetBrain deployment rejects the MAC query parameter and also limits deep offset paging; "
            "MACs outside the cached range may remain unresolved."
        )

    nb.oneip_cache = cache
    nb.oneip_cache_complete = complete
    nb.oneip_cache_warning = warning

    say(f"    One-IP cache : {len(cache)} row(s)", style="green")
    if warning:
        say(f"    Cache note   : {warning}", style="yellow")

    return cache, complete, warning


def oneip_lookup(
    nb: NetBrain, target: dict[str, str], *, scan: bool, count: int
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    """Lookup an IP or MAC in NetBrain's One-IP Table.

    IP lookups use the indexed ``ip`` parameter.  MAC lookups first try the
    documented ``mac`` parameter.  If the deployed NetBrain API rejects that
    parameter, the code automatically falls back to a reusable One-IP cache
    instead of marking every MAC as an API error.
    """
    path = "/ServicesAPI/API/V1/CMDB/Topology/OneIPTable"
    page_size = max(1, min(count, 1000))
    raw: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Fast exact lookup
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
                f"One-IP exact query (ip={target['value']}): "
                f"records={len(candidates)}, matches={len(records)}"
            )

        if records:
            rows = useful_rows(target, records, path)
            if rows:
                return rows, raw

        if not scan:
            return [], raw

    else:
        # Try the server-side MAC filter until the server proves that this
        # deployment does not support it.  Once unsupported, do not repeat the
        # same HTTP 400 for every address in hosts.txt.
        if nb.oneip_mac_filter_supported is not False:
            for value in mac_query_values(target["value"]):
                params = {"mac": value, "beginIndex": 0, "count": page_size}
                result = nb.try_call("GET", path, params=params)

                if result:
                    nb.oneip_mac_filter_supported = True
                    candidates = records_from(result)
                    records = filter_target_records(candidates, target)
                    entry = {"path": path, "params": params, "response": result}
                    if error := api_status_error(result):
                        entry["api_error"] = error
                    raw.append(entry)

                    if nb.verbose:
                        debug(
                            f"One-IP exact query (mac={value}): "
                            f"records={len(candidates)}, matches={len(records)}"
                        )

                    if records:
                        rows = useful_rows(target, records, path)
                        if rows:
                            return rows, raw
                    continue

                if _is_invalid_mac_filter_error(nb.last_error):
                    nb.oneip_mac_filter_supported = False
                    raw.append(
                        {
                            "path": path,
                            "params": params,
                            "capability_warning": (
                                "This NetBrain deployment rejects the One-IP 'mac' query parameter; "
                                "using cached table-scan fallback."
                            ),
                        }
                    )
                    if nb.verbose:
                        debug("One-IP MAC query parameter rejected by server; enabling cached fallback.")
                    break

                if nb.last_error:
                    raw.append({"path": path, "params": params, "api_error": str(nb.last_error)})

        # Automatic compatibility fallback.  This is intentionally enabled for
        # MAC targets when the live server rejects the MAC query parameter.
        if nb.oneip_mac_filter_supported is False:
            cache, complete, warning = _build_oneip_cache(nb, path, page_size)
            matches = filter_target_records(cache, target)
            raw.append(
                {
                    "path": path,
                    "fallback": "cached-oneip-scan",
                    "cached_rows": len(cache),
                    "cache_complete": complete,
                }
            )
            if warning:
                raw.append({"path": path, "scan_warning": warning})
            if matches:
                rows = useful_rows(target, matches, path)
                if rows:
                    return rows, raw
            return [], raw

        if not scan:
            return [], raw

    # ------------------------------------------------------------------
    # Optional generic full scan (mainly useful for an IP exact miss).
    # MACs normally reach this block only when the server accepted ``mac`` but
    # returned no match and the user explicitly supplied --oneip-scan.
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
                        f"One-IP fallback scan stopped at {ONEIP_DEEP_OFFSET_LIMIT} rows to avoid "
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
        if row.get("target_type") != "MAC" or row.get("status") == "found":
            continue
        match = by_mac.get(normalize_mac(row["target"]))
        if not match:
            continue
        resolved = merge_rows(match, row)
        resolved.update({"target": row["target"], "target_type": "MAC", "status": "found"})
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
    print(f"[DEBUG] {message}", file=sys.stderr)


def show_banner() -> None:
    width = 68
    say("=" * width, style="green")
    say("NETBRAIN ENDPOINT LOOKUP".center(width), style="green")
    say("=" * width, style="green")


def display_results(rows: list[dict[str, str]]) -> None:
    columns = [
        ("Target", "target"),
        ("Type", "target_type"),
        ("Status", "status"),
        ("Endpoint IP", "endpoint_ip"),
        ("MAC Address", "endpoint_mac"),
        ("Hostname", "endpoint_name"),
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
    say(message, error=True)
    return code


# ============================================================================
# SECTION 13 - PROGRAM ENTRY POINT AND ERROR HANDLING
# ============================================================================

if __name__ == "__main__":
    try:
        exit_code = main()
    except KeyboardInterrupt:
        exit_code = report_error("Cancelled by user.", 130)
    except AuthenticationError:
        exit_code = report_error("[-] ERROR: NetBrain authentication failed.", 3)
    except NetBrainUnreachable:
        exit_code = report_error("[-] ERROR: Unable to reach NetBrain server.", 4)
    except NetBrainAPIError:
        exit_code = report_error("[-] ERROR: NetBrain API request failed.", 5)
    except NetBrainError as exc:
        exit_code = report_error(f"[-] ERROR: {exc}", 1)
    except OSError as exc:
        exit_code = report_error(f"[-] ERROR: {exc}", 1)
    except Exception as exc:
        exit_code = report_error(f"[-] ERROR: Unexpected error ({type(exc).__name__}).", 1)
    raise SystemExit(exit_code)
