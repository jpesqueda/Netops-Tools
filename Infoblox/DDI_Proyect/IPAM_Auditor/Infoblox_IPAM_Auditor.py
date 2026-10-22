#!/usr/bin/env python3
"""
Infoblox Enterprise IPAM Auditor
Version: 1.0.2

Read-only IPv4 IPAM auditing utility for Infoblox NIOS WAPI.

V1 capabilities:
- Audit all IPv4 networks.
- Audit one IPv4 network.
- Audit a list of IPv4 networks from a text file.
- Validate whether requested networks exist.
- Enumerate all IPv4 addresses returned by IPAM for each network.
- Classify USED / UNUSED / OTHER states.
- Export network summaries and detailed IP address data to CSV.
- Auto-detect the newest WAPI version exposed by the Grid Master,
  or allow an explicit version with --wapi-version.
- Support WAPI pagination.

The script performs GET requests only; it does not modify Infoblox data.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import ipaddress
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

import requests
import urllib3
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import RequestException, SSLError, Timeout
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table


# =============================================================================
# APPLICATION METADATA
# =============================================================================

APP_NAME = "INFOBLOX ENTERPRISE IPAM AUDITOR"
VERSION = "1.0.2"
DEFAULT_PAGE_SIZE = 1000
DEFAULT_TIMEOUT = 30

console = Console()


# =============================================================================
# DATA MODELS
# =============================================================================


@dataclass
class NetworkRecord:
    network: str
    network_view: str = ""
    comment: str = ""
    exists: bool = True
    used: int = 0
    unused: int = 0
    other: int = 0
    conflicts: int = 0
    total_audited: int = 0
    utilization: float = 0.0
    health: str = "OK"
    error: str = ""
    detail_preview: List[Dict[str, Any]] = field(default_factory=list)


# =============================================================================
# EXCEPTIONS
# =============================================================================


class InfobloxError(RuntimeError):
    """Base exception for Infoblox API errors."""


class AuthenticationError(InfobloxError):
    """Raised when WAPI authentication fails."""


class APIRequestError(InfobloxError):
    """Raised when a WAPI request fails."""


# =============================================================================
# INFOBLOX WAPI CLIENT
# =============================================================================


class InfobloxClient:
    """Small read-only Infoblox NIOS WAPI client."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
        page_size: int = DEFAULT_PAGE_SIZE,
        wapi_version: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.page_size = page_size
        self.wapi_version = wapi_version

        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.headers.update({"Accept": "application/json"})

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _raw_get(self, url: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        try:
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
        except SSLError as exc:
            raise APIRequestError(
                "SSL validation failed. Use a trusted certificate or --insecure if appropriate."
            ) from exc
        except Timeout as exc:
            raise APIRequestError(f"Request timed out after {self.timeout} seconds.") from exc
        except RequestsConnectionError as exc:
            raise APIRequestError(f"Unable to connect to {self.base_url}.") from exc
        except RequestException as exc:
            raise APIRequestError(f"HTTP request failed: {exc}") from exc

        if response.status_code == 401:
            raise AuthenticationError("Authentication failed: invalid username/password or access denied.")
        if response.status_code == 403:
            raise AuthenticationError("Authentication succeeded but the account is not authorized for this request.")
        if not response.ok:
            detail = self._extract_error(response)
            raise APIRequestError(f"WAPI returned HTTP {response.status_code}: {detail}")

        return response

    @staticmethod
    def _extract_error(response: requests.Response) -> str:
        try:
            payload = response.json()
            return str(payload.get("text") or payload.get("Error") or payload)
        except ValueError:
            return response.text.strip() or response.reason

    def detect_wapi_version(self) -> str:
        """Detect and select the highest supported WAPI version."""
        if self.wapi_version:
            return self.wapi_version

        schema_url = f"{self.base_url}/wapi/v1.0/"
        response = self._raw_get(schema_url, params={"_schema": "1"})
        try:
            payload = response.json()
        except ValueError as exc:
            raise APIRequestError("Infoblox returned an invalid JSON schema response.") from exc

        versions = payload.get("supported_versions") or []
        if not versions:
            raise APIRequestError("Could not detect supported WAPI versions from the appliance.")

        def version_key(value: str) -> Tuple[int, ...]:
            parts: List[int] = []
            for item in str(value).split("."):
                try:
                    parts.append(int(item))
                except ValueError:
                    parts.append(0)
            return tuple(parts)

        self.wapi_version = max((str(v) for v in versions), key=version_key)
        return self.wapi_version

    @property
    def api_root(self) -> str:
        if not self.wapi_version:
            raise InfobloxError("WAPI version has not been detected yet.")
        return f"{self.base_url}/wapi/v{self.wapi_version}"

    def paged_get(
        self,
        object_type: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Yield all WAPI objects using server-side pagination."""
        query: Dict[str, Any] = dict(params or {})
        query.update(
            {
                "_paging": 1,
                "_return_as_object": 1,
                "_max_results": self.page_size,
            }
        )

        page_id: Optional[str] = None
        url = f"{self.api_root}/{object_type}"

        while True:
            # Per Infoblox WAPI paging semantics, the first request contains
            # the search/options and subsequent requests continue with only
            # the opaque _page_id returned by the appliance.
            page_query = {"_page_id": page_id} if page_id else dict(query)

            response = self._raw_get(url, params=page_query)
            try:
                payload = response.json()
            except ValueError as exc:
                raise APIRequestError(f"Invalid JSON returned for object {object_type}.") from exc

            # Normal paging response: {"result": [...], "next_page_id": "..."}
            # Be tolerant of a plain list in case an older NIOS behavior is encountered.
            if isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict):
                        yield item
                break

            results = payload.get("result", [])
            if isinstance(results, dict):
                results = [results]

            for item in results:
                if isinstance(item, dict):
                    yield item

            page_id = payload.get("next_page_id")
            if not page_id:
                break

    def get_networks(self, network_view: Optional[str] = None) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {
            "_return_fields": "network,network_view,comment",
        }
        if network_view:
            params["network_view"] = network_view
        return list(self.paged_get("network", params=params))

    def find_network(
        self,
        cidr: str,
        network_view: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {
            "network": cidr,
            "_return_fields": "network,network_view,comment",
        }
        if network_view:
            params["network_view"] = network_view
        return list(self.paged_get("network", params=params))

    def iter_ipv4_addresses(
        self,
        cidr: str,
        network_view: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        params: Dict[str, Any] = {
            "network": cidr,
            "_return_fields": (
                "ip_address,status,usage,types,names,mac_address,lease_state,"
                "is_conflict,objects,network,network_view"
            ),
        }
        if network_view:
            params["network_view"] = network_view
        yield from self.paged_get("ipv4address", params=params)


# =============================================================================
# INPUT VALIDATION
# =============================================================================


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Infoblox URL cannot be empty.")
    if not value.startswith(("https://", "http://")):
        value = "https://" + value
    return value.rstrip("/")


def validate_ipv4_network(value: str) -> str:
    try:
        network = ipaddress.ip_network(value.strip(), strict=True)
    except ValueError as exc:
        raise ValueError(f"Invalid subnet '{value}': {exc}") from exc
    if network.version != 4:
        raise ValueError(f"'{value}' is not an IPv4 network.")
    return str(network)


def load_subnets(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"Subnet file not found: {path}")

    networks: List[str] = []
    seen = set()

    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            value = raw_line.strip()
            if not value or value.startswith("#"):
                continue
            try:
                cidr = validate_ipv4_network(value)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
            if cidr not in seen:
                seen.add(cidr)
                networks.append(cidr)

    if not networks:
        raise ValueError(f"No IPv4 networks were found in {path}.")

    return networks


def is_auditable_host(cidr: str, ip_value: str) -> bool:
    """Exclude classic IPv4 network/broadcast addresses for prefixes <= /30."""
    network = ipaddress.ip_network(cidr, strict=True)
    address = ipaddress.ip_address(ip_value)
    if address not in network:
        return False
    if network.prefixlen <= 30 and address in (network.network_address, network.broadcast_address):
        return False
    return True


# =============================================================================
# AUDIT LOGIC
# =============================================================================


def health_from_utilization(value: float) -> str:
    if value >= 95:
        return "CRITICAL"
    if value >= 90:
        return "HIGH"
    if value >= 80:
        return "WARNING"
    return "OK"


def normalize_list_field(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "; ".join(str(item) for item in value)
    return str(value)


def audit_network(
    client: InfobloxClient,
    network_obj: Dict[str, Any],
    ip_writer: csv.DictWriter,
    preview_limit: int = 100,
) -> NetworkRecord:
    cidr = str(network_obj.get("network", ""))
    view = str(network_obj.get("network_view", ""))
    comment = str(network_obj.get("comment", "") or "")

    result = NetworkRecord(network=cidr, network_view=view, comment=comment)

    for item in client.iter_ipv4_addresses(cidr, view or None):
        ip_value = str(item.get("ip_address", ""))
        if not ip_value:
            continue

        try:
            if not is_auditable_host(cidr, ip_value):
                continue
        except ValueError:
            continue

        status = str(item.get("status", "UNKNOWN") or "UNKNOWN").upper()
        if status == "USED":
            result.used += 1
        elif status == "UNUSED":
            result.unused += 1
        else:
            result.other += 1

        if bool(item.get("is_conflict", False)):
            result.conflicts += 1

        result.total_audited += 1

        row = {
            "Network": cidr,
            "Network View": view,
            "IP Address": ip_value,
            "Status": status,
            "Usage": normalize_list_field(item.get("usage")),
            "Type": normalize_list_field(item.get("types")),
            "Names": normalize_list_field(item.get("names")),
            "MAC Address": str(item.get("mac_address", "") or ""),
            "Lease State": str(item.get("lease_state", "") or ""),
            "Conflict": "YES" if item.get("is_conflict") else "NO",
            "Objects": normalize_list_field(item.get("objects")),
        }
        ip_writer.writerow(row)

        if len(result.detail_preview) < preview_limit:
            result.detail_preview.append(row)

    if result.total_audited:
        result.utilization = (result.used / result.total_audited) * 100
    result.health = health_from_utilization(result.utilization)
    return result


# =============================================================================
# REPORTING
# =============================================================================


IP_FIELDNAMES = [
    "Network",
    "Network View",
    "IP Address",
    "Status",
    "Usage",
    "Type",
    "Names",
    "MAC Address",
    "Lease State",
    "Conflict",
    "Objects",
]

NETWORK_FIELDNAMES = [
    "Network",
    "Network View",
    "Comment",
    "Exists",
    "Used",
    "Unused",
    "Other",
    "Conflicts",
    "Total Audited",
    "Utilization %",
    "Status",
    "Error",
]

VALIDATION_FIELDNAMES = [
    "Requested Network",
    "Status",
    "Network View",
    "Used",
    "Unused",
    "Other",
    "Utilization %",
    "Error",
]


def write_network_summary(path: Path, records: Iterable[NetworkRecord]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=NETWORK_FIELDNAMES)
        writer.writeheader()
        for item in records:
            writer.writerow(
                {
                    "Network": item.network,
                    "Network View": item.network_view,
                    "Comment": item.comment,
                    "Exists": "YES" if item.exists else "NO",
                    "Used": item.used,
                    "Unused": item.unused,
                    "Other": item.other,
                    "Conflicts": item.conflicts,
                    "Total Audited": item.total_audited,
                    "Utilization %": f"{item.utilization:.2f}",
                    "Status": item.health,
                    "Error": item.error,
                }
            )


def write_validation_report(
    path: Path,
    requested: List[str],
    results_by_requested: Dict[str, List[NetworkRecord]],
) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=VALIDATION_FIELDNAMES)
        writer.writeheader()
        for cidr in requested:
            matches = results_by_requested.get(cidr, [])
            if not matches:
                writer.writerow(
                    {
                        "Requested Network": cidr,
                        "Status": "NOT FOUND",
                        "Network View": "",
                        "Used": "",
                        "Unused": "",
                        "Other": "",
                        "Utilization %": "",
                        "Error": "",
                    }
                )
                continue
            for item in matches:
                writer.writerow(
                    {
                        "Requested Network": cidr,
                        "Status": "EXISTS" if item.exists else "ERROR",
                        "Network View": item.network_view,
                        "Used": item.used,
                        "Unused": item.unused,
                        "Other": item.other,
                        "Utilization %": f"{item.utilization:.2f}",
                        "Error": item.error,
                    }
                )


def write_missing_networks(path: Path, requested: List[str], results_by_requested: Dict[str, List[NetworkRecord]]) -> int:
    missing = [cidr for cidr in requested if not results_by_requested.get(cidr)]
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Network"])
        for cidr in missing:
            writer.writerow([cidr])
    return len(missing)


def style_status(status: str) -> str:
    styles = {
        "OK": "green",
        "WARNING": "yellow",
        "HIGH": "bright_yellow",
        "CRITICAL": "bold red",
        "EXISTS": "green",
        "NOT FOUND": "red",
        "ERROR": "bold red",
    }
    return f"[{styles.get(status, 'white')}]{status}[/]"


def print_network_table(records: List[NetworkRecord], title: str) -> None:
    table = Table(title=title, header_style="bold cyan", show_lines=False)
    table.add_column("Network")
    table.add_column("View")
    table.add_column("Used", justify="right")
    table.add_column("Unused", justify="right")
    table.add_column("Other", justify="right")
    table.add_column("Utilization", justify="right")
    table.add_column("Status")

    for item in records:
        table.add_row(
            item.network,
            item.network_view or "-",
            str(item.used),
            str(item.unused),
            str(item.other),
            f"{item.utilization:.2f}%",
            style_status(item.health),
        )
    console.print(table)


def print_validation_table(
    requested: List[str],
    results_by_requested: Dict[str, List[NetworkRecord]],
) -> None:
    table = Table(title="NETWORK VALIDATION", header_style="bold cyan")
    table.add_column("Network")
    table.add_column("Status")
    table.add_column("Network View")
    table.add_column("Used", justify="right")
    table.add_column("Unused", justify="right")
    table.add_column("Utilization", justify="right")

    for cidr in requested:
        matches = results_by_requested.get(cidr, [])
        if not matches:
            table.add_row(cidr, style_status("NOT FOUND"), "-", "-", "-", "-")
            continue
        for item in matches:
            state = "ERROR" if item.error else "EXISTS"
            table.add_row(
                cidr,
                style_status(state),
                item.network_view or "-",
                str(item.used),
                str(item.unused),
                f"{item.utilization:.2f}%",
            )
    console.print(table)


def print_ip_detail_preview(record: NetworkRecord, display_limit: int) -> None:
    table = Table(
        title=f"IP ADDRESS AUDIT - {record.network} [{record.network_view}]",
        header_style="bold cyan",
    )
    table.add_column("IP Address")
    table.add_column("Status")
    table.add_column("Usage")
    table.add_column("Type")
    table.add_column("Names")
    table.add_column("MAC Address")
    table.add_column("Lease State")
    table.add_column("Conflict")

    for row in record.detail_preview[:display_limit]:
        status = row["Status"]
        status_style = "green" if status == "USED" else "dim" if status == "UNUSED" else "yellow"
        conflict = row["Conflict"]
        table.add_row(
            row["IP Address"],
            f"[{status_style}]{status}[/]",
            row["Usage"] or "-",
            row["Type"] or "-",
            row["Names"] or "-",
            row["MAC Address"] or "-",
            row["Lease State"] or "-",
            "[bold red]YES[/]" if conflict == "YES" else "NO",
        )

    console.print(table)
    if record.total_audited > display_limit:
        console.print(
            f"[dim]Showing the first {display_limit} addresses in the terminal; "
            f"all {record.total_audited} audited addresses are saved in CSV.[/]"
        )


# =============================================================================
# CLI
# =============================================================================


def build_parser() -> argparse.ArgumentParser:
    class HelpFormatter(argparse.RawDescriptionHelpFormatter):
        """Preserve the layout of examples and section descriptions."""

    examples = r"""
Quick Start:
  Audit everything:
    python Infoblox_IPAM_Auditor.py --url https://infoblox.example.local --all-networks

  Audit one subnet:
    python Infoblox_IPAM_Auditor.py --url https://infoblox.example.local --subnet 10.10.10.0/24

  Audit a list of subnets:
    python Infoblox_IPAM_Auditor.py --url https://infoblox.example.local --subnets-file subnets.txt

Examples:
  1) Audit all IPv4 networks
     python Infoblox_IPAM_Auditor.py --url https://infoblox.example.local --all-networks

  2) Audit one IPv4 network
     python Infoblox_IPAM_Auditor.py --url https://infoblox.example.local --subnet 10.10.20.0/24

  3) Audit networks listed in a text file
     python Infoblox_IPAM_Auditor.py --url https://infoblox.example.local --subnets-file subnets.txt

  4) Audit all networks in one Network View
     python Infoblox_IPAM_Auditor.py --url https://infoblox.example.local --all-networks --network-view PROD

  5) Audit one subnet and display IP details in the terminal
     python Infoblox_IPAM_Auditor.py --url https://infoblox.example.local --subnet 10.10.20.0/24 --include-details

  6) Display only the first 50 IP detail rows
     python Infoblox_IPAM_Auditor.py --url https://infoblox.example.local --subnet 10.10.20.0/24 --include-details --display-limit 50

  7) Save reports in a custom directory
     python Infoblox_IPAM_Auditor.py --url https://infoblox.example.local --subnets-file subnets.txt --output Audit_GDL

  8) Connect to a Grid using a self-signed/internal certificate
     python Infoblox_IPAM_Auditor.py --url https://infoblox.example.local --all-networks --insecure

  9) Force a specific WAPI version
     python Infoblox_IPAM_Auditor.py --url https://infoblox.example.local --all-networks --wapi-version 2.13.6

 10) Use environment variables for credentials in Windows PowerShell
     $env:INFOBLOX_URL="https://infoblox.example.local"
     $env:INFOBLOX_USER="jose"
     $env:INFOBLOX_PASSWORD="********"
     python Infoblox_IPAM_Auditor.py --all-networks

Input file format (subnets.txt):
  10.10.10.0/24
  10.10.20.0/24
  172.16.50.0/25

Notes:
  - Exactly one audit mode is required: --all-networks, --subnet, or --subnets-file.
  - If --user or --password are omitted, the script uses environment variables or prompts interactively.
  - --insecure disables TLS certificate verification; use it only when appropriate.
  - The script is read-only and performs GET requests only.
"""

    parser = argparse.ArgumentParser(
        prog="Infoblox_IPAM_Auditor.py",
        description=(
            "Read-only Infoblox NIOS IPv4 IPAM auditor.\n"
            "Validate networks, audit address utilization, and export CSV reports."
        ),
        epilog=examples,
        formatter_class=HelpFormatter,
        add_help=False,
    )

    general = parser.add_argument_group("General")
    general.add_argument(
        "-h",
        "--help",
        action="help",
        help="Show this help message and exit.",
    )
    general.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
        help="Show the application version and exit.",
    )

    connection = parser.add_argument_group("Connection")
    connection.add_argument(
        "--url",
        help="Infoblox Grid Master base URL. Can also be supplied with INFOBLOX_URL.",
    )
    connection.add_argument(
        "-u",
        "--user",
        help="Infoblox username. Can also be supplied with INFOBLOX_USER.",
    )
    connection.add_argument(
        "-p",
        "--password",
        help=(
            "Infoblox password. Can also be supplied with INFOBLOX_PASSWORD. "
            "For normal use, prefer the secure interactive prompt or an environment variable."
        ),
    )
    connection.add_argument(
        "--wapi-version",
        help="Force a WAPI version instead of auto-detection, for example 2.13.6.",
    )
    connection.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate validation for internal/self-signed certificates.",
    )
    connection.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP request timeout in seconds. Default: {DEFAULT_TIMEOUT}.",
    )
    connection.add_argument(
        "--page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        help=f"Maximum number of objects requested per WAPI page. Default: {DEFAULT_PAGE_SIZE}.",
    )

    audit = parser.add_argument_group("Audit Modes")
    mode = audit.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--all-networks",
        action="store_true",
        help="Discover and audit all IPv4 networks accessible to the account.",
    )
    mode.add_argument(
        "--subnet",
        metavar="CIDR",
        help="Audit one IPv4 network, for example 10.10.20.0/24.",
    )
    mode.add_argument(
        "--subnets-file",
        metavar="FILE",
        type=Path,
        help="Audit IPv4 networks from a text file containing one CIDR per line.",
    )

    filters = parser.add_argument_group("Filters and Display")
    filters.add_argument(
        "--network-view",
        metavar="VIEW",
        help="Limit discovery or validation to one Infoblox Network View.",
    )
    filters.add_argument(
        "--include-details",
        action="store_true",
        help="Display audited IP address details in the terminal in addition to CSV output.",
    )
    filters.add_argument(
        "--display-limit",
        type=int,
        default=100,
        metavar="N",
        help="Maximum IP detail rows displayed per network when --include-details is used. Default: 100.",
    )

    output = parser.add_argument_group("Output")
    output.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("Reports"),
        metavar="DIR",
        help="Directory where CSV audit reports are created. Default: Reports.",
    )

    return parser


def banner() -> None:
    console.print("=" * 88)
    console.print(f"{APP_NAME:^88}", style="bold cyan")
    console.print(f"{'Version ' + VERSION:^88}")
    console.print("=" * 88)


def get_credentials(args: argparse.Namespace) -> Tuple[str, str, str]:
    url = args.url or os.getenv("INFOBLOX_URL")
    username = args.user or os.getenv("INFOBLOX_USER")
    password = args.password or os.getenv("INFOBLOX_PASSWORD")

    if not url:
        url = input("Infoblox URL: ").strip()
    if not username:
        username = input("Username: ").strip()
    if password is None:
        password = getpass.getpass("Password: ")

    return normalize_url(url), username, password


# =============================================================================
# MAIN WORKFLOW
# =============================================================================


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    banner()

    try:
        url, username, password = get_credentials(args)

        if args.subnet:
            args.subnet = validate_ipv4_network(args.subnet)
        if args.display_limit < 1:
            raise ValueError("--display-limit must be at least 1.")
        if args.page_size < 1:
            raise ValueError("--page-size must be at least 1.")

        output_dir: Path = args.output
        output_dir.mkdir(parents=True, exist_ok=True)

        client = InfobloxClient(
            base_url=url,
            username=username,
            password=password,
            verify_ssl=not args.insecure,
            timeout=args.timeout,
            page_size=args.page_size,
            wapi_version=args.wapi_version,
        )

        console.print("\n[bold][+] Validating Infoblox connectivity...[/]")
        console.print(f"    URL             : {url}")

        started = time.perf_counter()
        wapi_version = client.detect_wapi_version()

        console.print("    Status          : [green]Reachable[/]")
        console.print("\n[bold][+] Connecting to Infoblox WAPI...[/]")
        console.print("    Authentication  : [green]Successful[/]")
        console.print(f"    WAPI Version    : {wapi_version}")
        console.print(f"    Network View    : {args.network_view or 'All'}")

        ip_csv = output_dir / "IP_Address_Audit.csv"
        networks_csv = output_dir / "Networks.csv"

        all_results: List[NetworkRecord] = []
        requested: List[str] = []
        results_by_requested: Dict[str, List[NetworkRecord]] = {}

        with ip_csv.open("w", newline="", encoding="utf-8-sig") as ip_handle:
            ip_writer = csv.DictWriter(ip_handle, fieldnames=IP_FIELDNAMES)
            ip_writer.writeheader()

            if args.all_networks:
                console.print("\n[bold][+] Discovering IPv4 networks...[/]")
                network_objects = client.get_networks(args.network_view)
                network_objects.sort(
                    key=lambda x: (
                        str(x.get("network_view", "")),
                        ipaddress.ip_network(str(x.get("network"))).network_address,
                        ipaddress.ip_network(str(x.get("network"))).prefixlen,
                    )
                )
                console.print(f"    Networks Found  : {len(network_objects)}")

                console.print("\n[bold][+] Auditing IP utilization...[/]")
                with Progress(
                    SpinnerColumn(),
                    TextColumn("{task.description}"),
                    BarColumn(),
                    TextColumn("{task.completed}/{task.total}"),
                    TimeElapsedColumn(),
                    console=console,
                ) as progress:
                    task = progress.add_task("IPAM Audit", total=len(network_objects))
                    for network_obj in network_objects:
                        try:
                            record = audit_network(
                                client,
                                network_obj,
                                ip_writer,
                                preview_limit=args.display_limit,
                            )
                        except InfobloxError as exc:
                            record = NetworkRecord(
                                network=str(network_obj.get("network", "")),
                                network_view=str(network_obj.get("network_view", "")),
                                comment=str(network_obj.get("comment", "") or ""),
                                exists=True,
                                health="ERROR",
                                error=str(exc),
                            )
                        all_results.append(record)
                        progress.advance(task)

                write_network_summary(networks_csv, all_results)
                console.print()
                print_network_table(all_results, "NETWORK SUMMARY")

            else:
                if args.subnet:
                    requested = [args.subnet]
                else:
                    requested = load_subnets(args.subnets_file)
                    console.print("\n[bold][+] Loading input file...[/]")
                    console.print(f"    File            : {args.subnets_file}")
                    console.print(f"    Networks Loaded : {len(requested)}")

                console.print("\n[bold][+] Validating networks against Infoblox IPAM...[/]")
                with Progress(
                    SpinnerColumn(),
                    TextColumn("{task.description}"),
                    BarColumn(),
                    TextColumn("{task.completed}/{task.total}"),
                    TimeElapsedColumn(),
                    console=console,
                ) as progress:
                    task = progress.add_task("Network Validation", total=len(requested))
                    for cidr in requested:
                        matches = client.find_network(cidr, args.network_view)
                        records: List[NetworkRecord] = []
                        for network_obj in matches:
                            try:
                                record = audit_network(
                                    client,
                                    network_obj,
                                    ip_writer,
                                    preview_limit=args.display_limit,
                                )
                            except InfobloxError as exc:
                                record = NetworkRecord(
                                    network=str(network_obj.get("network", cidr)),
                                    network_view=str(network_obj.get("network_view", "")),
                                    comment=str(network_obj.get("comment", "") or ""),
                                    exists=True,
                                    health="ERROR",
                                    error=str(exc),
                                )
                            records.append(record)
                            all_results.append(record)
                        results_by_requested[cidr] = records
                        progress.advance(task)

                write_network_summary(networks_csv, all_results)
                validation_csv = output_dir / "Network_Validation.csv"
                missing_csv = output_dir / "Missing_Networks.csv"
                write_validation_report(validation_csv, requested, results_by_requested)
                missing_count = write_missing_networks(missing_csv, requested, results_by_requested)

                console.print()
                print_validation_table(requested, results_by_requested)

                if args.include_details:
                    for record in all_results:
                        console.print()
                        print_ip_detail_preview(record, args.display_limit)

        elapsed = time.perf_counter() - started
        total_used = sum(r.used for r in all_results)
        total_unused = sum(r.unused for r in all_results)
        total_other = sum(r.other for r in all_results)
        total_conflicts = sum(r.conflicts for r in all_results)

        console.print("\n" + "=" * 88)
        console.print(f"{'SUMMARY':^88}", style="bold cyan")
        console.print("=" * 88)

        if requested:
            found_requested = sum(1 for cidr in requested if results_by_requested.get(cidr))
            console.print(f"Networks Requested   : {len(requested)}")
            console.print(f"Networks Found       : {found_requested}")
            console.print(f"Networks Not Found   : {len(requested) - found_requested}")
        else:
            console.print(f"Networks Audited     : {len(all_results)}")

        console.print(f"Used IP Addresses    : {total_used}")
        console.print(f"Unused IP Addresses  : {total_unused}")
        console.print(f"Other IP States      : {total_other}")
        console.print(f"Conflicts             : {total_conflicts}")
        console.print(f"Execution Time        : {elapsed:.2f} seconds")

        console.print("\n[bold green][+] Reports generated successfully:[/]")
        console.print(f"    {networks_csv}")
        console.print(f"    {ip_csv}")
        if requested:
            console.print(f"    {output_dir / 'Network_Validation.csv'}")
            console.print(f"    {output_dir / 'Missing_Networks.csv'}")

        console.print("\n[bold green][+] Audit completed successfully.[/]")
        return 0

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Execution cancelled by user.[/]")
        return 130
    except AuthenticationError as exc:
        console.print(f"\n[bold red][ERROR] Authentication failure:[/] {exc}")
        return 2
    except (APIRequestError, InfobloxError) as exc:
        console.print(f"\n[bold red][ERROR] Infoblox API failure:[/] {exc}")
        return 3
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"\n[bold red][ERROR] Input validation failure:[/] {exc}")
        return 4
    except Exception as exc:
        console.print(f"\n[bold red][ERROR] Unexpected failure:[/] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
