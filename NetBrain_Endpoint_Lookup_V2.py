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
    1.0.0

Requirements:
    Python 3.10+
    requests
    rich

Installation:
    pip install requests rich
"""

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
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    box = Console = Panel = Table = Text = None


SESSION = "/ServicesAPI/API/V1/Session"
DEFAULT_OUTPUT = "netbrain_endpoint_report.csv"
VERSION = "NetBrain Endpoint Lookup 1.0.0"
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
    "switch_port": "port portname interface interfacename intfname localinterface interfacename".split(),
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
        if not token:
            raise AuthenticationError("NetBrain authentication failed.")
        self.headers.update({"Token": token, "token": token})

    def logout(self) -> None:
        if "Token" in self.headers:
            self.try_call("DELETE", SESSION)

    def validate_connection(self) -> None:
        last_error = None
        for path in (SESSION, "/"):
            url = urljoin(self.url + "/", path.lstrip("/"))
            ctx = None if self.verify_tls else ssl._create_unverified_context()
            req = Request(url, headers={"Accept": "application/json"}, method="GET")
            try:
                with urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    say(f"    Status : Reachable (HTTP {resp.status})")
                    return
            except HTTPError as exc:
                say(f"    Status : Reachable (HTTP {exc.code})")
                return
            except URLError as exc:
                last_error = exc
                if self.verbose:
                    debug(f"Connectivity probe failed: {type(exc).__name__}")
        raise NetBrainUnreachable("Unable to reach NetBrain server.") from last_error

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
            exc.read()
            text = ""
        except URLError as exc:
            raise NetBrainUnreachable("Unable to reach NetBrain server.") from exc

        if self.verbose:
            debug(f"HTTP status: {code}")
        if code != 200:
            raise NetBrainAPIError(f"NetBrain API request failed: HTTP {code} at {path}", code)
        try:
            return json.loads(text) if text.strip() else {}
        except json.JSONDecodeError as exc:
            raise NetBrainAPIError(f"NetBrain API returned invalid JSON: {path}") from exc

    def try_call(self, method: str, path: str, **kwargs: Any) -> Any | None:
        try:
            return self.call(method, path, **kwargs)
        except Exception as exc:
            if self.verbose:
                debug(f"Request unavailable: {method.upper()} {path} ({type(exc).__name__})")
            return None


def main() -> int:
    args = parse_args()
    show_banner()
    if args.insecure:
        say("[!] WARNING: SSL certificate verification is disabled.")

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
        user = args.username or input("NetBrain Username: ").strip()
        password = args.password if args.password is not None else getpass.getpass("NetBrain Password: ")
        nb = NetBrain(url, user, password, args)
        try:
            say("[+] Validating NetBrain connectivity...")
            say(f"    URL    : {url}")
            nb.validate_connection()
            say("[+] Connecting to NetBrain API...")
            nb.login()
            say("    Login  : Successful")
            say("    Token  : Received")
            select_domain(nb, args.tenant, args.domain)
            say(f"[+] Searching {len(valid_targets)} endpoint(s)...")
            for target in targets:
                if target["type"] == "INVALID":
                    rows.append(invalid_row(target))
                    continue
                debug(f"Searching endpoint: {target['value']}")
                target_rows, target_raw = lookup(
                    nb,
                    target,
                    args.endpoint_path or DEFAULT_ENDPOINTS,
                    scan_oneip=args.oneip_scan or not args.no_oneip_scan,
                    oneip_count=args.oneip_count,
                )
                rows.extend(target_rows)
                raw.append({"target": target["value"], "responses": target_raw})
                debug("Endpoint lookup completed")
        finally:
            nb.logout()
    else:
        rows.extend(invalid_row(target) for target in targets)

    output = Path(args.output or DEFAULT_OUTPUT)
    write_csv(output, rows)
    if args.raw_json:
        Path(args.raw_json).write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    display_results(rows)
    found = sum(row["status"] == "found" for row in rows)
    say("[+] Lookup completed successfully.")
    say(f"[+] Endpoints found : {found}")
    say(f"[+] CSV report      : {output.resolve()}")
    return 0


def parse_args() -> argparse.Namespace:
    examples = """USAGE
  python netbrain_endpoint_lookup.py --url URL --host TARGET
  python netbrain_endpoint_lookup.py --url URL --hosts-file FILE

EXAMPLES
  python netbrain_endpoint_lookup.py --url https://netbrain.local --host 172.21.68.55
  python netbrain_endpoint_lookup.py --url https://netbrain.local --host e4:b9:7a:f9:b6:27
  python netbrain_endpoint_lookup.py --url https://netbrain.local --host e4-b9-7a-f9-b6-27
  python netbrain_endpoint_lookup.py --url https://netbrain.local --hosts-file hosts.txt
  python netbrain_endpoint_lookup.py --url https://netbrain.local --hosts-file hosts.txt --insecure
  python netbrain_endpoint_lookup.py --url https://netbrain.local --hosts-file hosts.txt --user USERNAME --password PASSWORD --insecure
  python netbrain_endpoint_lookup.py --url https://netbrain.local --hosts-file hosts.txt --output endpoints.csv"""
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
    inputs.add_argument("--url", help="NetBrain base URL, e.g. https://netbrain.local")
    target_input = inputs.add_mutually_exclusive_group(required=True)
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
    output.add_argument("--raw-json", help="Save raw API responses to a JSON file")

    advanced = p.add_argument_group("NETBRAIN OPTIONS")
    advanced.add_argument("--tenant", help="Tenant name or ID")
    advanced.add_argument("--domain", help="Domain name or ID")
    advanced.add_argument("--endpoint-path", action="append", help="Additional switch-port endpoint to try")
    advanced.add_argument("--oneip-scan", action="store_true", help="Compatibility option; One-IP scan is enabled by default")
    advanced.add_argument("--no-oneip-scan", action="store_true", help="Disable full One-IP Table scan fallback")
    advanced.add_argument("--oneip-count", type=int, default=10000, help="Rows per One-IP Table page (default: 10000)")
    advanced.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds (default: 30)")
    advanced.add_argument("-v", "--verbose", action="store_true", help="Show target and request diagnostics; secrets are omitted")
    return p.parse_args()


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
    say(f"    Domain : {tenant.get('tenantName')} / {domain.get('domainName')}")


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


def lookup(
    nb: NetBrain,
    target: dict[str, str],
    endpoints: list[str],
    *,
    scan_oneip: bool = False,
    oneip_count: int = 10000,
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    raw: list[dict[str, Any]] = []

    direct_rows, direct_raw = connected_switch_port_lookup(nb, target)
    raw.extend(direct_raw)
    oneip_rows, oneip_raw = oneip_lookup(nb, target, scan=scan_oneip, count=oneip_count)
    raw.extend(oneip_raw)
    if direct_rows or oneip_rows:
        row = merge_rows(*(direct_rows + oneip_rows))
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

    return [empty_row(target, "not-found")], raw


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


def oneip_lookup(
    nb: NetBrain, target: dict[str, str], *, scan: bool, count: int
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    paths = [
        "/ServicesAPI/API/V1/CMDB/IP/OneIPTable",
        "/ServicesAPI/API/V1/CMDB/Topology/OneIPTable",
    ]
    query_keys = ["ip", "IP", "ipAddress", "IP Address"] if target["type"] == "IP" else [
        "mac",
        "MAC",
        "macAddress",
        "MAC Address",
    ]
    raw: list[dict[str, Any]] = []

    for path in paths:
        for key in query_keys:
            params = {key: target["value"], "beginIndex": 0, "count": count}
            result = nb.try_call("GET", path, params=params)
            records = filter_target_records(records_from(result), target) if result else []
            if result:
                raw.append({"path": path, "params": params, "response": result})
            if records:
                rows = useful_rows(target, records, path)
                if rows:
                    return rows, raw

    if not scan:
        return [], raw

    say(f"    Scanning One-IP Table for {target['value']}...")
    for path in paths:
        begin = 0
        while True:
            params = {"beginIndex": begin, "count": count}
            result = nb.try_call("GET", path, params=params)
            records = records_from(result) if result else []
            if result:
                raw.append({"path": path, "params": params, "record_count": len(records)})
            matches = filter_target_records(records, target)
            if matches:
                rows = useful_rows(target, matches, path)
                if rows:
                    return rows, raw
            if len(records) < count:
                break
            begin += count
    return [], raw


def filter_target_records(records: list[dict[str, Any]], target: dict[str, str]) -> list[dict[str, Any]]:
    wanted = clean(target["value"])
    matches = []
    for record in records:
        flat = {clean(k): clean(stringify(v)) for k, v in flatten(record).items()}
        values = set(flat.values())
        if target["type"] == "MAC":
            values |= {
                clean(normalize_mac(v))
                for v in flat.values()
                if MAC_RE.fullmatch(v)
            }
        if wanted in values or any(wanted in value for value in values):
            matches.append(record)
    return matches


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
        value = port.group(1)
        if "." in value:
            switch, intf = value.rsplit(".", 1)
            row["switch_name"] = row["switch_name"] or switch
            row["switch_port"] = row["switch_port"] or intf
        else:
            row["switch_port"] = row["switch_port"] or value


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


def stringify(value: Any) -> str:
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLS)
        writer.writeheader()
        writer.writerows(rows)


def say(message: str, *, error: bool = False) -> None:
    """Print plain operational text through Rich when it is installed."""
    stream = sys.stderr if error else sys.stdout
    if console:
        console.print(message, file=stream)
    else:
        print(message, file=stream)


def debug(message: str) -> None:
    print(f"[DEBUG] {message}", file=sys.stderr)


def show_banner() -> None:
    if console and Panel:
        console.print(Panel("NETBRAIN ENDPOINT LOOKUP", box=box.ROUNDED, expand=False))
    else:
        say("NETBRAIN ENDPOINT LOOKUP")


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
    say("\nNetBrain Endpoint Results")
    if console and Table and Text:
        table = Table(box=box.SQUARE, show_lines=False, expand=True)
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
