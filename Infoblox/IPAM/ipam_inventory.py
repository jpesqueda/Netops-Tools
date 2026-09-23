#!/usr/bin/env python3
"""
Inventario manual de IPAM desde export Excel/CSV de Infoblox.

Lee el export, filtra por subnet/rango, valida si las IPs responden por ping
o TCP y genera un reporte Excel simple.
"""

from __future__ import annotations

import argparse
import ipaddress
import platform
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

try:
    import pandas as pd
except ImportError as exc:
    raise SystemExit(
        "Falta pandas/openpyxl. Instala con:\n"
        "  python -m pip install -r requirements_ipam_inventory.txt"
    ) from exc


IP_COLS = ("IP Address", "IP", "IPAddress", "IPv4 Address", "ip_address", "address")
NAME_COLS = ("Name", "Names", "Hostname", "Host Name", "DNS Name")
MAC_COLS = ("MAC Address", "MAC", "mac_address")
LEASE_COLS = ("Lease State", "lease_state", "DHCP Lease State")
STATUS_COLS = ("Status", "status")
TYPE_COLS = ("Type", "types", "Types")
USAGE_COLS = ("Usage", "usage")


def text(value) -> str:
    return "" if pd.isna(value) else str(value).strip()


def find_col(df: pd.DataFrame, names: tuple[str, ...]) -> str | None:
    by_lower = {str(col).strip().lower(): col for col in df.columns}
    return next((by_lower[name.lower()] for name in names if name.lower() in by_lower), None)


def read_export(path: Path, sheet: str | None) -> pd.DataFrame:
    if path.suffix.lower() in (".xlsx", ".xlsm", ".xls"):
        return pd.read_excel(path, sheet_name=sheet or 0)
    if path.suffix.lower() in (".csv", ".txt"):
        return pd.read_csv(path)
    raise ValueError("El archivo debe ser .xlsx, .xlsm, .xls, .csv o .txt")


def parse_networks(values: list[str] | None) -> list[ipaddress.IPv4Network]:
    return [ipaddress.IPv4Network(value, strict=False) for value in values or []]


def ip_in_scope(ip: str, networks: list[ipaddress.IPv4Network], start: str | None, end: str | None) -> bool:
    ip_obj = ipaddress.IPv4Address(ip)
    if networks and not any(ip_obj in network for network in networks):
        return False
    if start and int(ip_obj) < int(ipaddress.IPv4Address(start)):
        return False
    if end and int(ip_obj) > int(ipaddress.IPv4Address(end)):
        return False
    return True


def ping(ip: str, timeout_ms: int) -> bool:
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except OSError:
        return False


def tcp_open(ip: str, port: int, timeout_ms: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout_ms / 1000):
            return True
    except OSError:
        return False


def classify(lease: str, status: str, usage: str, detected: bool) -> tuple[str, str]:
    lease = lease.lower()
    status = status.lower()
    usage = usage.lower()
    if lease == "abandoned":
        return "REVISAR DHCP", "CRITICO"
    if lease == "backup":
        return "REVISAR FAILOVER", "MEDIO"
    if lease in {"free", "available"} or status in {"free", "available"} or usage in {"free", "available"}:
        return ("DISCREPANCIA", "CRITICO") if detected else ("SIN EVIDENCIA DE RESPUESTA", "NORMAL")
    if lease in {"active", "static"} or status in {"used", "active"} or usage in {"used", "assigned"}:
        return ("CONSISTENTE", "NORMAL") if detected else ("REVISAR SIN RESPUESTA", "MEDIO")
    return ("REVISAR", "MEDIO") if detected else ("SIN EVIDENCIA", "NORMAL")


def scan(row: dict, ports: list[int], timeout_ms: int, no_ping: bool) -> dict:
    ping_ok = False if no_ping else ping(row["ip"], timeout_ms)
    tcp = {f"TCP_{port}": tcp_open(row["ip"], port, timeout_ms) for port in ports}
    detected = ping_ok or any(tcp.values())
    result, severity = classify(row["lease"], row["status"], row["usage"], detected)
    return {
        "IP Address": row["ip"],
        "Name": row["name"],
        "MAC Address": row["mac"],
        "Lease State": row["lease"],
        "Status": row["status"],
        "Type": row["type"],
        "Usage": row["usage"],
        "Ping": ping_ok,
        **tcp,
        "Open Ports": ", ".join(str(port) for port in ports if tcp[f"TCP_{port}"]),
        "HostDetected": detected,
        "Resultado": result,
        "Severidad": severity,
        "Fecha": datetime.now(),
    }


def build_rows(df: pd.DataFrame, args: argparse.Namespace) -> list[dict]:
    cols = {
        "ip": find_col(df, IP_COLS),
        "name": find_col(df, NAME_COLS),
        "mac": find_col(df, MAC_COLS),
        "lease": find_col(df, LEASE_COLS),
        "status": find_col(df, STATUS_COLS),
        "type": find_col(df, TYPE_COLS),
        "usage": find_col(df, USAGE_COLS),
    }
    if not cols["ip"]:
        raise ValueError(f"No encontre columna de IP. Esperaba una de: {', '.join(IP_COLS)}")

    networks = parse_networks(args.subnet)
    rows = []
    for index, item in df.iterrows():
        kind = text(item.get(cols["type"])) if cols["type"] else ""
        if kind.lower() == "ipv4 network":
            continue

        raw_ip = text(item.get(cols["ip"]))
        if not raw_ip:
            continue
        try:
            ip = str(ipaddress.IPv4Address(raw_ip))
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"IP invalida en fila Excel {index + 2}: {raw_ip}") from exc
        if not ip_in_scope(ip, networks, args.ip_desde, args.ip_hasta):
            continue

        rows.append(
            {
                "ip": ip,
                "name": text(item.get(cols["name"])) if cols["name"] else "",
                "mac": text(item.get(cols["mac"])) if cols["mac"] else "",
                "lease": text(item.get(cols["lease"])) if cols["lease"] else "",
                "status": text(item.get(cols["status"])) if cols["status"] else "",
                "type": kind,
                "usage": text(item.get(cols["usage"])) if cols["usage"] else "",
            }
        )
    return rows


def write_report(rows: list[dict], output: Path, overwrite: bool) -> None:
    if output.exists() and not overwrite:
        raise FileExistsError(f"Ya existe {output}. Usa --overwrite para reemplazarlo.")

    audit = pd.DataFrame(rows)
    summary = audit.groupby(["Severidad", "Resultado"]).size().reset_index(name="Cantidad")
    output.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        audit.to_excel(writer, sheet_name="Audit", index=False)
        summary.to_excel(writer, sheet_name="Summary", index=False)
        for sheet in writer.book.worksheets:
            sheet.freeze_panes = "A2"
            sheet.auto_filter.ref = sheet.dimensions
            for col in sheet.columns:
                sheet.column_dimensions[col[0].column_letter].width = min(
                    max(len(str(cell.value or "")) for cell in col) + 2,
                    60,
                )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Valida IPs vivas desde un export manual de Infoblox.")
    parser.add_argument("-i", "--input", required=True, help="Export de Infoblox .xlsx/.csv.")
    parser.add_argument("-o", "--output", default="Infoblox_Manual_Audit.xlsx", help="Reporte .xlsx de salida.")
    parser.add_argument("--sheet", help="Hoja del Excel. Por defecto usa la primera.")
    parser.add_argument("--subnet", action="append", help="Filtra por subnet CIDR. Se puede repetir.")
    parser.add_argument("--ip-desde", help="Inicio de rango IPv4 opcional.")
    parser.add_argument("--ip-hasta", help="Fin de rango IPv4 opcional.")
    parser.add_argument("--ports", type=int, nargs="+", default=[22, 80, 443], help="Puertos TCP a probar.")
    parser.add_argument("--timeout-ms", type=int, default=1500, help="Timeout ping/TCP en milisegundos.")
    parser.add_argument("--workers", type=int, default=64, help="Cantidad de hilos paralelos.")
    parser.add_argument("--no-ping", action="store_true", help="No ejecuta ping ICMP.")
    parser.add_argument("--overwrite", action="store_true", help="Reemplaza el reporte si ya existe.")
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        if bool(args.ip_desde) != bool(args.ip_hasta):
            raise ValueError("Usa --ip-desde y --ip-hasta juntos.")
        if args.timeout_ms < 100 or args.timeout_ms > 30000:
            raise ValueError("--timeout-ms debe estar entre 100 y 30000.")
        if any(port < 1 or port > 65535 for port in args.ports):
            raise ValueError("Todos los puertos deben estar entre 1 y 65535.")

        df = read_export(Path(args.input).expanduser().resolve(strict=True), args.sheet)
        source_rows = build_rows(df, args)
        if not source_rows:
            raise ValueError("No hay IPs del export dentro del filtro indicado.")

        print(f"Validando {len(source_rows)} IPs con {args.workers} workers...")
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            rows = list(pool.map(lambda row: scan(row, args.ports, args.timeout_ms, args.no_ping), source_rows))

        output = Path(args.output).expanduser().resolve()
        write_report(rows, output, args.overwrite)
        revisar = sum(1 for row in rows if row["Severidad"] != "NORMAL")
        print(f"Reporte generado: {output}")
        print(f"IPs auditadas: {len(rows)}. Filas para revisar: {revisar}.")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
