#!/usr/bin/env python3
"""
Inventario IPAM Infoblox con dos modos:

1. manual: lee un export Excel/CSV de Infoblox y valida IPs activas.
2. wapi: consulta Infoblox WAPI y ejecuta la misma validacion activa.

El objetivo es que ambos modos generen una salida comparable para justificar
el acceso read-only a WAPI.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import getpass
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
from collections import Counter, OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote


OPENPYXL_IMPORTS: dict[str, Any] = {}
REQUESTS = None
DNS = None


IP_COLUMN_CANDIDATES = (
    "IP Address",
    "IP",
    "IPAddress",
    "IPv4 Address",
    "ip_address",
    "address",
)
NAME_COLUMN_CANDIDATES = ("Name", "Names", "Hostname", "Host Name", "DNS Name", "names")
MAC_COLUMN_CANDIDATES = ("MAC Address", "MAC", "mac_address")
STATUS_COLUMN_CANDIDATES = ("Status", "status")
LEASE_COLUMN_CANDIDATES = ("Lease State", "lease_state", "DHCP Lease State")
TYPE_COLUMN_CANDIDATES = ("Type", "types", "Types")
USAGE_COLUMN_CANDIDATES = ("Usage", "usage")
NETWORK_COLUMN_CANDIDATES = ("Network", "network")
NETWORK_VIEW_COLUMN_CANDIDATES = ("Network View", "network_view")


DEFAULT_WAPI_FIELDS = [
    "ip_address",
    "status",
    "lease_state",
    "mac_address",
    "names",
    "network",
    "network_view",
    "types",
    "usage",
    "objects",
    "is_conflict",
    "comment",
    "username",
]


class DependencyError(RuntimeError):
    pass


def require_openpyxl() -> dict[str, Any]:
    if OPENPYXL_IMPORTS:
        return OPENPYXL_IMPORTS
    try:
        from openpyxl import Workbook, load_workbook
        from openpyxl.styles import Font, PatternFill
        from openpyxl.worksheet.table import Table, TableStyleInfo
        from openpyxl.utils import get_column_letter
    except ImportError as exc:
        raise DependencyError(
            "Falta openpyxl. Instala dependencias con:\n"
            "  python -m pip install -r requirements_ipam_inventory.txt"
        ) from exc

    OPENPYXL_IMPORTS.update(
        {
            "Workbook": Workbook,
            "load_workbook": load_workbook,
            "Font": Font,
            "PatternFill": PatternFill,
            "Table": Table,
            "TableStyleInfo": TableStyleInfo,
            "get_column_letter": get_column_letter,
        }
    )
    return OPENPYXL_IMPORTS


def require_requests() -> Any:
    global REQUESTS
    if REQUESTS is not None:
        return REQUESTS
    try:
        import requests
    except ImportError as exc:
        raise DependencyError(
            "Falta requests. Instala dependencias con:\n"
            "  python -m pip install -r requirements_ipam_inventory.txt"
        ) from exc
    REQUESTS = requests
    return REQUESTS


def require_dns() -> Any:
    global DNS
    if DNS is not None:
        return DNS
    try:
        import dns.exception
        import dns.reversename
        import dns.resolver
    except ImportError as exc:
        raise DependencyError(
            "Falta dnspython para usar --dns-server. Instala dependencias con:\n"
            "  python -m pip install -r requirements_ipam_inventory.txt"
        ) from exc
    DNS = dns
    return DNS


def parse_ports(raw_ports: Iterable[int]) -> list[int]:
    ports = []
    for port in raw_ports:
        if port < 1 or port > 65535:
            raise ValueError(f"Puerto TCP no valido: {port}")
        ports.append(port)
    return sorted(set(ports))


def parse_networks(raw_networks: Iterable[str] | None) -> list[ipaddress.IPv4Network]:
    networks = []
    for raw in raw_networks or []:
        networks.append(ipaddress.IPv4Network(raw.strip(), strict=False))
    return networks


def parse_ip_range(ip_desde: str | None, ip_hasta: str | None) -> tuple[int, int] | None:
    if not ip_desde and not ip_hasta:
        return None
    if not ip_desde or not ip_hasta:
        raise ValueError("Usa --ip-desde y --ip-hasta juntos.")
    start = int(ipaddress.IPv4Address(ip_desde))
    end = int(ipaddress.IPv4Address(ip_hasta))
    if start > end:
        raise ValueError("--ip-desde debe ser menor o igual que --ip-hasta.")
    return start, end


def should_include_ip(
    address: str,
    networks: list[ipaddress.IPv4Network],
    ip_range: tuple[int, int] | None,
) -> bool:
    ip_obj = ipaddress.IPv4Address(address)
    if networks and not any(ip_obj in network for network in networks):
        return False
    if ip_range:
        numeric = int(ip_obj)
        if numeric < ip_range[0] or numeric > ip_range[1]:
            return False
    return True


def normalize_header(value: Any) -> str:
    return "" if value is None else str(value).strip()


def find_column(headers: Iterable[str], candidates: Iterable[str]) -> str | None:
    headers_list = list(headers)
    lower_map = {header.lower().strip(): header for header in headers_list}
    for candidate in candidates:
        found = lower_map.get(candidate.lower().strip())
        if found:
            return found
    return None


def value_as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat(sep=" ", timespec="seconds")
    if isinstance(value, (list, tuple, set)):
        return "; ".join(value_as_text(item) for item in value if item is not None)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def normalize_names(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        raw_values = []
        for item in value:
            raw_values.extend(normalize_names(item))
        return sorted(set(raw_values))
    text = str(value)
    names = {
        item.strip().rstrip(".").lower()
        for item in re.split(r"[,;\s]+", text)
        if item.strip().rstrip(".")
    }
    fqdn_labels = {name.split(".", 1)[0] for name in names if "." in name}
    return sorted(name for name in names if "." in name or name not in fqdn_labels)


def flatten_wapi_extattrs(extattrs: Any) -> str:
    if not isinstance(extattrs, dict):
        return value_as_text(extattrs)
    simplified = {}
    for key, wrapped in extattrs.items():
        if isinstance(wrapped, dict) and "value" in wrapped:
            simplified[key] = wrapped.get("value")
        else:
            simplified[key] = wrapped
    return json.dumps(simplified, ensure_ascii=False, sort_keys=True)


def read_csv_rows(path: Path, encoding: str) -> list[dict[str, Any]]:
    with path.open("r", encoding=encoding, newline="") as handle:
        reader = csv.DictReader(handle)
        return [dict(row) for row in reader]


def read_xlsx_rows(path: Path, sheet_name: str | None) -> list[dict[str, Any]]:
    xl = require_openpyxl()
    workbook = xl["load_workbook"](path, read_only=True, data_only=True)
    try:
        worksheet = workbook[sheet_name] if sheet_name else workbook.active
        row_iter = worksheet.iter_rows(values_only=True)
        for header_values in row_iter:
            headers = [normalize_header(value) for value in header_values]
            if any(headers):
                break
        else:
            return []

        rows = []
        for index, values in enumerate(row_iter, start=2):
            row = {
                headers[col_index]: value
                for col_index, value in enumerate(values)
                if col_index < len(headers) and headers[col_index]
            }
            if any(value not in (None, "") for value in row.values()):
                row["_source_row"] = index
                rows.append(row)
        return rows
    finally:
        workbook.close()


def read_manual_export(path: Path, sheet_name: str | None, encoding: str) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix in {".xlsx", ".xlsm"}:
        return read_xlsx_rows(path, sheet_name)
    if suffix in {".csv", ".txt"}:
        return read_csv_rows(path, encoding)
    raise ValueError("El archivo manual debe ser .xlsx, .xlsm, .csv o .txt.")


def normalize_manual_rows(
    source_rows: list[dict[str, Any]],
    networks: list[ipaddress.IPv4Network],
    ip_range: tuple[int, int] | None,
) -> list[OrderedDict[str, Any]]:
    if not source_rows:
        raise ValueError("El export no contiene filas.")

    headers = list(source_rows[0].keys())
    ip_column = find_column(headers, IP_COLUMN_CANDIDATES)
    if not ip_column:
        raise ValueError(
            "No encontre columna de IP. Esperaba una de: "
            + ", ".join(IP_COLUMN_CANDIDATES)
        )

    name_column = find_column(headers, NAME_COLUMN_CANDIDATES)
    mac_column = find_column(headers, MAC_COLUMN_CANDIDATES)
    status_column = find_column(headers, STATUS_COLUMN_CANDIDATES)
    lease_column = find_column(headers, LEASE_COLUMN_CANDIDATES)
    type_column = find_column(headers, TYPE_COLUMN_CANDIDATES)
    usage_column = find_column(headers, USAGE_COLUMN_CANDIDATES)
    network_column = find_column(headers, NETWORK_COLUMN_CANDIDATES)
    network_view_column = find_column(headers, NETWORK_VIEW_COLUMN_CANDIDATES)

    normalized_rows: list[OrderedDict[str, Any]] = []
    for source_index, row in enumerate(source_rows, start=1):
        row_type = value_as_text(row.get(type_column)).strip() if type_column else ""
        if row_type.lower() == "ipv4 network":
            continue

        raw_address = value_as_text(row.get(ip_column)).strip()
        if not raw_address:
            continue

        try:
            address = str(ipaddress.IPv4Address(raw_address))
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"IP no valida en fila {source_index}: {raw_address}") from exc

        if not should_include_ip(address, networks, ip_range):
            continue

        source_payload = {
            key: value_as_text(value)
            for key, value in row.items()
            if not key.startswith("_")
        }

        normalized_rows.append(
            OrderedDict(
                [
                    ("source", "manual_export"),
                    ("ip_address", address),
                    ("network", value_as_text(row.get(network_column)).strip() if network_column else ""),
                    (
                        "network_view",
                        value_as_text(row.get(network_view_column)).strip()
                        if network_view_column
                        else "",
                    ),
                    ("status", value_as_text(row.get(status_column)).strip() if status_column else ""),
                    (
                        "lease_state",
                        value_as_text(row.get(lease_column)).strip() if lease_column else "",
                    ),
                    ("usage", value_as_text(row.get(usage_column)).strip() if usage_column else ""),
                    ("types", row_type),
                    ("names", "; ".join(normalize_names(row.get(name_column))) if name_column else ""),
                    ("mac_address", value_as_text(row.get(mac_column)).strip() if mac_column else ""),
                    ("is_conflict", ""),
                    ("comment", ""),
                    ("username", ""),
                    ("objects", ""),
                    ("extattrs", ""),
                    ("source_ref", value_as_text(row.get("_source_row") or source_index)),
                    ("source_payload", json.dumps(source_payload, ensure_ascii=False, sort_keys=True)),
                ]
            )
        )
    return normalized_rows


def ping_ip(address: str, timeout_ms: int) -> bool:
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), address]
    else:
        timeout_seconds = max(1, int((timeout_ms + 999) / 1000))
        command = ["ping", "-c", "1", "-W", str(timeout_seconds), address]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return result.returncode == 0
    except OSError:
        return False


def test_tcp_port(address: str, port: int, timeout_ms: int) -> bool:
    try:
        with socket.create_connection((address, port), timeout=timeout_ms / 1000):
            return True
    except OSError:
        return False


def build_resolver(dns_servers: list[str], dns_timeout: float) -> Any:
    dns = require_dns()
    resolver = dns.resolver.Resolver(configure=not dns_servers)
    if dns_servers:
        resolver.nameservers = dns_servers
    resolver.timeout = dns_timeout
    resolver.lifetime = dns_timeout
    return resolver


def resolve_ptr(
    address: str,
    dns_servers: list[str],
    dns_timeout: float,
) -> tuple[list[str], str]:
    if dns_servers:
        try:
            dns = require_dns()
            resolver = build_resolver(dns_servers, dns_timeout)
            reverse_name = dns.reversename.from_address(address)
            answers = resolver.resolve(reverse_name, "PTR", search=False)
            return sorted({str(answer.target).rstrip(".").lower() for answer in answers}), ""
        except Exception as exc:
            return [], str(exc)

    try:
        host, _, aliases = socket.gethostbyaddr(address)
        names = [host, *aliases]
        return sorted({name.rstrip(".").lower() for name in names if name}), ""
    except (socket.herror, socket.gaierror, OSError) as exc:
        return [], str(exc)


def resolve_a(
    name: str,
    dns_servers: list[str],
    dns_timeout: float,
) -> tuple[list[str], str]:
    query_name = name.rstrip(".") + "."
    if dns_servers:
        try:
            resolver = build_resolver(dns_servers, dns_timeout)
            answers = resolver.resolve(query_name, "A", search=False)
            return sorted({str(answer.address) for answer in answers}), ""
        except Exception as exc:
            return [], str(exc)

    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({info[4][0] for info in infos}), ""
    except OSError as exc:
        return [], str(exc)


def classify_record(record: dict[str, Any], host_detected: bool, dns_review: bool) -> tuple[str, str]:
    status = value_as_text(record.get("status")).strip().lower()
    lease_state = value_as_text(record.get("lease_state")).strip().lower()
    usage = value_as_text(record.get("usage")).strip().lower()
    is_conflict = value_as_text(record.get("is_conflict")).strip().lower() in {"true", "1", "yes"}

    if is_conflict or status == "conflict":
        return "CONFLICTO_IPAM", "CRITICO"

    if lease_state == "abandoned":
        return "REVISAR_DHCP_ABANDONED", "CRITICO"

    if lease_state == "backup":
        return "REVISAR_DHCP_FAILOVER", "MEDIO"

    free_like = {"free", "unused", "available", "libre", "not used"}
    used_like = {"active", "static", "used", "reserved", "assigned", "dynamic"}

    if lease_state in free_like or status in free_like or usage in free_like:
        if host_detected:
            return "IPAM_LIBRE_CON_RESPUESTA", "CRITICO"
        if dns_review:
            return "IPAM_LIBRE_REVISAR_DNS", "MEDIO"
        return "SIN_EVIDENCIA_DE_USO", "NORMAL"

    if lease_state in used_like or status in used_like or usage in used_like:
        if host_detected:
            return "CONSISTENTE", "NORMAL"
        if dns_review:
            return "USADA_SIN_RESPUESTA_REVISAR_DNS", "MEDIO"
        return "USADA_SIN_RESPUESTA", "MEDIO"

    if host_detected:
        return "RESPONDE_SIN_ESTADO_CLARO", "MEDIO"
    if dns_review:
        return "SIN_RESPUESTA_REVISAR_DNS", "MEDIO"
    return "SIN_EVIDENCIA", "NORMAL"


def scan_record(record: OrderedDict[str, Any], args: argparse.Namespace) -> OrderedDict[str, Any]:
    started = dt.datetime.now()
    address = value_as_text(record.get("ip_address"))
    errors: list[str] = []

    ping_ok = False if args.no_ping else ping_ip(address, args.timeout_ms)

    port_results = OrderedDict()
    for port in args.ports:
        port_results[f"tcp_{port}"] = test_tcp_port(address, port, args.timeout_ms)

    tcp_open_ports = [str(port) for port in args.ports if port_results[f"tcp_{port}"]]
    host_detected = ping_ok or bool(tcp_open_ports)

    ptr_names: list[str] = []
    ptr_error = ""
    forward_results: OrderedDict[str, str] = OrderedDict()
    expected_names = normalize_names(record.get("names"))
    dns_match = "NO_EVALUABLE"
    dns_review = False

    if not args.skip_dns:
        ptr_names, ptr_error = resolve_ptr(address, args.dns_server, args.dns_timeout)
        if ptr_error:
            errors.append(f"PTR: {ptr_error}")

        matched_names = 0
        for name in expected_names:
            ips, err = resolve_a(name, args.dns_server, args.dns_timeout)
            if err:
                errors.append(f"A {name}: {err}")
            forward_results[name] = ",".join(ips)
            if address in ips:
                matched_names += 1

        if expected_names:
            if matched_names == len(expected_names):
                dns_match = "COINCIDE"
            elif matched_names:
                dns_match = "PARCIAL"
                dns_review = True
            else:
                dns_match = "NO_COINCIDE"
                dns_review = True

        if expected_names and ptr_names:
            expected_set = set(expected_names)
            ptr_set = set(ptr_names)
            if expected_set.isdisjoint(ptr_set):
                dns_review = True

    result, severity = classify_record(record, host_detected, dns_review)
    finished = dt.datetime.now()

    output = OrderedDict(record)
    output["ping_ok"] = ping_ok
    for key, value in port_results.items():
        output[key] = value
    output["tcp_open_ports"] = "; ".join(tcp_open_ports)
    output["host_detected"] = host_detected
    output["ptr_names"] = "; ".join(ptr_names)
    output["forward_dns"] = "; ".join(
        f"{name}={ips or 'SIN_REGISTRO'}" for name, ips in forward_results.items()
    )
    output["dns_match"] = dns_match
    output["dns_review"] = dns_review
    output["result"] = result
    output["severity"] = severity
    output["scan_started"] = started
    output["scan_finished"] = finished
    output["scan_duration_ms"] = int((finished - started).total_seconds() * 1000)
    output["errors"] = "; ".join(errors)
    return output


def scan_records(records: list[OrderedDict[str, Any]], args: argparse.Namespace) -> list[OrderedDict[str, Any]]:
    if not records:
        raise ValueError("No hay registros para analizar.")

    print(f"Registros a validar: {len(records)}")
    print(f"Workers: {args.workers}. Puertos: {', '.join(str(port) for port in args.ports)}")

    results: list[OrderedDict[str, Any] | None] = [None] * len(records)
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {
            executor.submit(scan_record, record, args): index
            for index, record in enumerate(records)
        }
        completed = 0
        for future in as_completed(future_map):
            index = future_map[future]
            results[index] = future.result()
            completed += 1
            if completed == len(records) or completed % max(1, min(50, len(records))) == 0:
                print(f"Avance: {completed}/{len(records)}")

    return [result for result in results if result is not None]


def build_summary(results: list[OrderedDict[str, Any]], args: argparse.Namespace) -> list[OrderedDict[str, Any]]:
    severity_counts = Counter(value_as_text(row.get("severity")) for row in results)
    result_counts = Counter(value_as_text(row.get("result")) for row in results)
    host_detected_count = sum(1 for row in results if row.get("host_detected"))
    dns_review_count = sum(1 for row in results if row.get("dns_review"))
    ping_count = sum(1 for row in results if row.get("ping_ok"))

    summary = [
        OrderedDict([("metric", "generated_at"), ("value", dt.datetime.now())]),
        OrderedDict([("metric", "mode"), ("value", args.mode)]),
        OrderedDict([("metric", "total_ips"), ("value", len(results))]),
        OrderedDict([("metric", "host_detected"), ("value", host_detected_count)]),
        OrderedDict([("metric", "ping_ok"), ("value", ping_count)]),
        OrderedDict([("metric", "dns_review"), ("value", dns_review_count)]),
        OrderedDict([("metric", "ports"), ("value", ", ".join(str(port) for port in args.ports))]),
        OrderedDict([("metric", "timeout_ms"), ("value", args.timeout_ms)]),
        OrderedDict([("metric", "workers"), ("value", args.workers)]),
    ]

    for severity, count in sorted(severity_counts.items()):
        summary.append(OrderedDict([("metric", f"severity_{severity}"), ("value", count)]))
    for result, count in sorted(result_counts.items()):
        summary.append(OrderedDict([("metric", f"result_{result}"), ("value", count)]))
    return summary


def normalize_excel_value(value: Any) -> Any:
    if isinstance(value, (list, tuple, set, dict)):
        return value_as_text(value)
    return value


def autosize_columns(worksheet: Any, max_width: int = 65) -> None:
    get_column_letter = OPENPYXL_IMPORTS["get_column_letter"]
    for column_index in range(1, worksheet.max_column + 1):
        letter = get_column_letter(column_index)
        max_length = 0
        for row_index in range(1, worksheet.max_row + 1):
            value = worksheet.cell(row=row_index, column=column_index).value
            max_length = max(max_length, len(value_as_text(value)))
        worksheet.column_dimensions[letter].width = min(max(max_length + 2, 10), max_width)


def add_table(worksheet: Any, table_name: str, table_style: str) -> None:
    if worksheet.max_row < 1 or worksheet.max_column < 1:
        return
    Table = OPENPYXL_IMPORTS["Table"]
    TableStyleInfo = OPENPYXL_IMPORTS["TableStyleInfo"]
    get_column_letter = OPENPYXL_IMPORTS["get_column_letter"]
    last_cell = f"{get_column_letter(worksheet.max_column)}{worksheet.max_row}"
    table = Table(displayName=table_name, ref=f"A1:{last_cell}")
    table.tableStyleInfo = TableStyleInfo(
        name=table_style,
        showFirstColumn=False,
        showLastColumn=False,
        showRowStripes=True,
        showColumnStripes=False,
    )
    worksheet.add_table(table)


def style_inventory_sheet(worksheet: Any) -> None:
    Font = OPENPYXL_IMPORTS["Font"]
    PatternFill = OPENPYXL_IMPORTS["PatternFill"]
    worksheet.freeze_panes = "A2"
    for cell in worksheet[1]:
        cell.font = Font(bold=True)

    headers = {worksheet.cell(row=1, column=column).value: column for column in range(1, worksheet.max_column + 1)}
    severity_col = headers.get("severity")
    result_col = headers.get("result")
    fills = {
        "NORMAL": PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid"),
        "MEDIO": PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid"),
        "CRITICO": PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid"),
    }
    for row in range(2, worksheet.max_row + 1):
        severity = worksheet.cell(row=row, column=severity_col).value if severity_col else ""
        if severity_col and severity in fills:
            worksheet.cell(row=row, column=severity_col).fill = fills[severity]
        if result_col and severity in fills:
            worksheet.cell(row=row, column=result_col).fill = fills[severity]


def write_xlsx(path: Path, results: list[OrderedDict[str, Any]], summary: list[OrderedDict[str, Any]]) -> None:
    require_openpyxl()
    Workbook = OPENPYXL_IMPORTS["Workbook"]

    workbook = Workbook()
    inventory_sheet = workbook.active
    inventory_sheet.title = "Inventory"
    headers = list(results[0].keys())
    inventory_sheet.append(headers)
    for row in results:
        inventory_sheet.append([normalize_excel_value(row.get(header)) for header in headers])
    add_table(inventory_sheet, "Inventory", "TableStyleMedium2")
    style_inventory_sheet(inventory_sheet)
    autosize_columns(inventory_sheet)

    summary_sheet = workbook.create_sheet("Summary")
    summary_headers = ["metric", "value"]
    summary_sheet.append(summary_headers)
    for row in summary:
        summary_sheet.append([normalize_excel_value(row.get(header)) for header in summary_headers])
    add_table(summary_sheet, "Summary", "TableStyleMedium6")
    style_inventory_sheet(summary_sheet)
    autosize_columns(summary_sheet)

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(f".{int(time.time())}.tmp.xlsx")
    try:
        workbook.save(tmp_path)
        os.replace(tmp_path, path)
    finally:
        workbook.close()
        if tmp_path.exists():
            tmp_path.unlink()


def write_csv_output(path: Path, results: list[OrderedDict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)


def write_output(path: Path, results: list[OrderedDict[str, Any]], summary: list[OrderedDict[str, Any]], overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"El archivo de salida ya existe: {path}. Usa --overwrite si quieres reemplazarlo.")
    if path.suffix.lower() == ".csv":
        write_csv_output(path, results)
    else:
        write_xlsx(path, results, summary)


class InfobloxWapiClient:
    def __init__(
        self,
        grid: str,
        version: str,
        username: str,
        password: str,
        verify_tls: bool | str,
        timeout: float,
    ) -> None:
        requests = require_requests()
        grid = grid.strip().rstrip("/")
        if not grid.startswith(("http://", "https://")):
            grid = "https://" + grid
        self.base_url = f"{grid}/wapi/{version.strip('/')}"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = verify_tls
        self.session.headers.update({"Accept": "application/json"})

    def get(self, object_type: str, params: dict[str, Any]) -> Any:
        url = f"{self.base_url}/{quote(object_type, safe=':')}"
        response = self.session.get(url, params=params, timeout=self.timeout)
        if response.status_code >= 400:
            raise RuntimeError(f"WAPI GET fallo {response.status_code}: {response.text[:1000]}")
        return response.json()

    def get_paged(self, object_type: str, params: dict[str, Any], page_size: int) -> list[dict[str, Any]]:
        merged = dict(params)
        merged["_paging"] = 1
        merged["_return_as_object"] = 1
        merged["_max_results"] = page_size

        output: list[dict[str, Any]] = []
        while True:
            payload = self.get(object_type, merged)
            if isinstance(payload, list):
                output.extend(payload)
                break
            if not isinstance(payload, dict):
                raise RuntimeError(f"Respuesta WAPI inesperada: {payload!r}")

            result = payload.get("result", [])
            if not isinstance(result, list):
                raise RuntimeError(f"Respuesta WAPI sin lista result: {payload!r}")
            output.extend(result)

            next_page_id = payload.get("next_page_id")
            if not next_page_id:
                break
            merged = {"_page_id": next_page_id}
        return output


def get_wapi_password(args: argparse.Namespace) -> str:
    if args.password:
        return args.password
    if args.password_env:
        password = os.getenv(args.password_env)
        if password:
            return password
    return getpass.getpass("Password WAPI Infoblox: ")


def normalize_wapi_rows(
    wapi_objects: list[dict[str, Any]],
    networks: list[ipaddress.IPv4Network],
    ip_range: tuple[int, int] | None,
) -> list[OrderedDict[str, Any]]:
    rows: list[OrderedDict[str, Any]] = []
    for index, item in enumerate(wapi_objects, start=1):
        raw_address = value_as_text(item.get("ip_address")).strip()
        if not raw_address:
            continue
        try:
            address = str(ipaddress.IPv4Address(raw_address))
        except ipaddress.AddressValueError:
            continue
        if not should_include_ip(address, networks, ip_range):
            continue

        names = normalize_names(item.get("names"))
        rows.append(
            OrderedDict(
                [
                    ("source", "wapi"),
                    ("ip_address", address),
                    ("network", value_as_text(item.get("network")).strip()),
                    ("network_view", value_as_text(item.get("network_view")).strip()),
                    ("status", value_as_text(item.get("status")).strip()),
                    ("lease_state", value_as_text(item.get("lease_state")).strip()),
                    ("usage", value_as_text(item.get("usage")).strip()),
                    ("types", value_as_text(item.get("types")).strip()),
                    ("names", "; ".join(names)),
                    ("mac_address", value_as_text(item.get("mac_address")).strip()),
                    ("is_conflict", item.get("is_conflict", "")),
                    ("comment", value_as_text(item.get("comment")).strip()),
                    ("username", value_as_text(item.get("username")).strip()),
                    ("objects", value_as_text(item.get("objects")).strip()),
                    ("extattrs", flatten_wapi_extattrs(item.get("extattrs")) if "extattrs" in item else ""),
                    ("source_ref", value_as_text(item.get("_ref") or index)),
                    ("source_payload", json.dumps(item, ensure_ascii=False, sort_keys=True)),
                ]
            )
        )
    return rows


def run_manual(args: argparse.Namespace) -> tuple[list[OrderedDict[str, Any]], list[OrderedDict[str, Any]]]:
    input_path = Path(args.input).expanduser().resolve(strict=True)
    networks = parse_networks(args.subnet)
    ip_range = parse_ip_range(args.ip_desde, args.ip_hasta)
    source_rows = read_manual_export(input_path, args.sheet, args.encoding)
    records = normalize_manual_rows(source_rows, networks, ip_range)
    results = scan_records(records, args)
    summary = build_summary(results, args)
    return results, summary


def run_wapi(args: argparse.Namespace) -> tuple[list[OrderedDict[str, Any]], list[OrderedDict[str, Any]]]:
    networks = parse_networks(args.network)
    if not networks and not args.allow_all:
        raise ValueError("Por seguridad indica al menos un --network, o usa --allow-all explicitamente.")

    ip_range = parse_ip_range(args.ip_desde, args.ip_hasta)
    verify_tls: bool | str = not args.insecure
    if args.ca_bundle:
        verify_tls = args.ca_bundle
    elif args.insecure:
        ssl._create_default_https_context = ssl._create_unverified_context

    password = get_wapi_password(args)
    return_fields = list(DEFAULT_WAPI_FIELDS)
    if args.include_extattrs and "extattrs" not in return_fields:
        return_fields.append("extattrs")
    if args.return_fields:
        return_fields = args.return_fields

    client = InfobloxWapiClient(
        grid=args.grid,
        version=args.wapi_version,
        username=args.username,
        password=password,
        verify_tls=verify_tls,
        timeout=args.wapi_timeout,
    )

    all_objects: list[dict[str, Any]] = []
    target_networks = [str(network) for network in networks] or [None]
    for network in target_networks:
        params: dict[str, Any] = {
            "_return_fields": ",".join(return_fields),
        }
        if network:
            params["network"] = network
        if args.network_view:
            params["network_view"] = args.network_view

        print(f"Consultando WAPI ipv4address network={network or '*'} network_view={args.network_view or '*'}")
        all_objects.extend(client.get_paged("ipv4address", params, args.page_size))

    records = normalize_wapi_rows(all_objects, networks, ip_range)
    results = scan_records(records, args)
    summary = build_summary(results, args)
    summary.append(OrderedDict([("metric", "wapi_objects_returned"), ("value", len(all_objects))]))
    summary.append(OrderedDict([("metric", "wapi_version"), ("value", args.wapi_version)]))
    summary.append(OrderedDict([("metric", "network_view"), ("value", args.network_view or "")]))
    return results, summary


def add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-o", "--output", required=True, help="Archivo de salida .xlsx o .csv.")
    parser.add_argument("--subnet", action="append", help="Filtra por subnet CIDR. Se puede repetir.")
    parser.add_argument("--ip-desde", help="Inicio de rango IPv4 opcional.")
    parser.add_argument("--ip-hasta", help="Fin de rango IPv4 opcional.")
    parser.add_argument("--ports", type=int, nargs="+", default=[22, 80, 443], help="Puertos TCP a probar.")
    parser.add_argument("--timeout-ms", type=int, default=1500, help="Timeout ping/TCP en milisegundos.")
    parser.add_argument("--workers", type=int, default=64, help="Cantidad de hilos paralelos.")
    parser.add_argument("--no-ping", action="store_true", help="No ejecutar ping ICMP.")
    parser.add_argument("--skip-dns", action="store_true", help="No ejecutar validacion DNS.")
    parser.add_argument(
        "--dns-server",
        action="append",
        default=[],
        help="Servidor DNS para PTR/A. Se puede repetir. Sin esto usa el resolver del sistema.",
    )
    parser.add_argument("--dns-timeout", type=float, default=2.0, help="Timeout DNS en segundos.")
    parser.add_argument("--overwrite", action="store_true", help="Permite reemplazar el archivo de salida.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inventario IPAM Infoblox por export manual o por WAPI, con validacion activa."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    manual = subparsers.add_parser("manual", help="Lee un export Excel/CSV de Infoblox.")
    manual.add_argument("-i", "--input", required=True, help="Export de Infoblox .xlsx/.csv.")
    manual.add_argument("--sheet", help="Hoja del Excel. Por defecto usa la hoja activa.")
    manual.add_argument("--encoding", default="utf-8-sig", help="Encoding para CSV.")
    add_common_scan_args(manual)

    wapi = subparsers.add_parser("wapi", help="Consulta Infoblox WAPI.")
    wapi.add_argument("--grid", required=True, help="FQDN/IP del Grid Master o URL base https://grid.")
    wapi.add_argument("--username", required=True, help="Usuario WAPI.")
    wapi.add_argument("--password", help="Password WAPI. Mejor usar --password-env.")
    wapi.add_argument("--password-env", default="INFOBLOX_PASSWORD", help="Variable de entorno con password.")
    wapi.add_argument("--wapi-version", default="v2.13.6", help="Version WAPI, por ejemplo v2.13.6.")
    wapi.add_argument("--network", action="append", help="Network CIDR a consultar. Se puede repetir.")
    wapi.add_argument("--network-view", default="default", help="Network view Infoblox.")
    wapi.add_argument("--allow-all", action="store_true", help="Permite consultar sin --network.")
    wapi.add_argument("--page-size", type=int, default=1000, help="Tamano de pagina WAPI.")
    wapi.add_argument("--wapi-timeout", type=float, default=30.0, help="Timeout HTTP WAPI en segundos.")
    wapi.add_argument("--include-extattrs", action="store_true", help="Solicita extattrs en _return_fields.")
    wapi.add_argument(
        "--return-fields",
        nargs="+",
        help="Sobrescribe _return_fields. Ejemplo: ip_address status lease_state names network network_view",
    )
    wapi.add_argument("--insecure", action="store_true", help="No valida certificado TLS.")
    wapi.add_argument("--ca-bundle", help="Ruta a CA bundle para validar TLS.")
    add_common_scan_args(wapi)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        args.ports = parse_ports(args.ports)
        if args.timeout_ms < 100 or args.timeout_ms > 30000:
            raise ValueError("--timeout-ms debe estar entre 100 y 30000.")
        if args.workers < 1:
            raise ValueError("--workers debe ser mayor o igual que 1.")

        if args.mode == "manual":
            results, summary = run_manual(args)
        elif args.mode == "wapi":
            results, summary = run_wapi(args)
        else:
            raise ValueError(f"Modo no soportado: {args.mode}")

        output_path = Path(args.output).expanduser().resolve(strict=False)
        write_output(output_path, results, summary, args.overwrite)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    review_count = sum(1 for row in results if row.get("severity") != "NORMAL" or row.get("dns_review"))
    print(f"Reporte generado: {output_path}")
    print(f"IPs auditadas: {len(results)}. Filas para revisar: {review_count}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
