#!/usr/bin/env python3
"""
Busca IPs/MACs en NetBrain R12.x y genera un CSV con switch, puerto y datos
relacionados del endpoint.

Ejemplo:
  python netbrain_endpoint_lookup.py --url https://netbrain.local --hosts-file hosts.txt --insecure
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


SESSION = "/ServicesAPI/API/V1/Session"
DEFAULT_OUTPUT = "netbrain_endpoint_report.csv"
DEFAULT_ENDPOINTS = [
    "/ServicesAPI/API/V1/CMDB/Devices/ConnectedSwitchPorts",
    "/ServicesAPI/API/V1/CMDB/Devices/EndSystemConnectedSwitchPorts",
    "/ServicesAPI/API/V1/CMDB/Devices/EndSystem/ConnectedSwitchPorts",
    "/ServicesAPI/API/V1/CMDB/Topology/ConnectedSwitchPort",
    "/ServicesAPI/API/V1/Topology/ConnectedSwitchPort",
]
SEARCH_ENDPOINTS = [
    "/ServicesAPI/API/V1/CMDB/Search",
    "/ServicesAPI/API/V1/Search",
    "/ServicesAPI/API/V1/CMDB/Search/Results",
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
    "endpoint_name": "endpoint endsystem host hostname name client clientname".split(),
    "switch_name": "switch switchname connecteddevice devicename device_name hostname name".split(),
    "switch_ip": "switchip deviceip mgmtip managementip management_ip".split(),
    "switch_port": "port portname interface interfacename intfname localinterface".split(),
    "port_description": "description descr portdescription interfacedescription".split(),
    "vlan": "vlan accessvlan nativevlan".split(),
    "vrf": "vrf vrfname".split(),
    "site": "site sitepath".split(),
    "location": "location loc rack room".split(),
    "device_type": "devicetype type subtypename".split(),
    "vendor": "vendor manufacturer".split(),
    "model": "model platform".split(),
    "serial": "serial sn serialnumber".split(),
}


class NetBrainError(RuntimeError):
    pass


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
        token = self.call("POST", SESSION, body=body, auth=False).get("token")
        if not token:
            raise NetBrainError("NetBrain no regreso token de sesion.")
        self.headers.update({"Token": token, "token": token})

    def logout(self) -> None:
        if "Token" in self.headers:
            self.try_call("DELETE", SESSION)

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
            raise NetBrainError("No hay sesion activa.")

        url = path if path.startswith(("http://", "https://")) else urljoin(self.url + "/", path.lstrip("/"))
        if params:
            url += ("&" if "?" in url else "?") + urlencode(params, doseq=True)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = Request(url, data=data, headers=self.headers.copy(), method=method.upper())
        ctx = None if self.verify_tls else ssl._create_unverified_context()

        if self.verbose:
            print(f"[DEBUG] {method.upper()} {url} {body or ''}", file=sys.stderr)
        try:
            with urlopen(req, timeout=self.timeout, context=ctx) as resp:
                code = resp.status
                text = resp.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            code = exc.code
            text = exc.read().decode("utf-8", errors="replace")
        except URLError as exc:
            raise NetBrainError(f"Error de conexion a {path}: {exc}") from exc

        if code != 200:
            raise NetBrainError(f"{method.upper()} {path} -> HTTP {code}: {text[:500]}")
        return json.loads(text) if text.strip() else {}

    def try_call(self, method: str, path: str, **kwargs: Any) -> Any | None:
        try:
            return self.call(method, path, **kwargs)
        except Exception as exc:
            if self.verbose:
                print(f"[DEBUG] fallo {method.upper()} {path}: {exc}", file=sys.stderr)
            return None


def main() -> int:
    args = parse_args()
    url = args.url or input("URL de NetBrain: ").strip()
    user = args.username or input("Usuario NetBrain: ").strip()
    password = args.password or getpass.getpass("Password NetBrain: ")
    hosts_file = Path(args.hosts_file or input("Archivo de hosts/IPs/MACs: ").strip())

    if not url or not user or not hosts_file.exists():
        print("ERROR: revisa URL, usuario y archivo de hosts.", file=sys.stderr)
        return 2

    targets = load_targets(hosts_file)
    if not targets:
        print("ERROR: no encontre IPs ni MACs validas.", file=sys.stderr)
        return 2

    nb = NetBrain(url, user, password, args)
    rows: list[dict[str, str]] = []
    raw: list[dict[str, Any]] = []

    try:
        print("Conectando a NetBrain...")
        nb.login()
        select_domain(nb, args.tenant, args.domain)
        print(f"Buscando {len(targets)} endpoint(s)...")
        for target in targets:
            target_rows, target_raw = lookup(nb, target, args.endpoint_path or DEFAULT_ENDPOINTS)
            rows.extend(target_rows)
            raw.append({"target": target["value"], "responses": target_raw})
    finally:
        nb.logout()

    output = Path(args.output or DEFAULT_OUTPUT)
    write_csv(output, rows)
    if args.raw_json:
        Path(args.raw_json).write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    print_table(rows, COLS[:10])
    print(f"\nCSV generado: {output.resolve()}")
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Busca IPs/MACs en NetBrain R12.x y exporta CSV.")
    p.add_argument("--url", help="URL base, ej. https://netbrain.local")
    p.add_argument("--username", help="Usuario NetBrain")
    p.add_argument("--password", help="Password. Mejor omitirlo para que se pida oculto.")
    p.add_argument("--auth-id", help="authentication_id si aplica")
    p.add_argument("--tenant", help="Nombre o ID del tenant")
    p.add_argument("--domain", help="Nombre o ID del domain")
    p.add_argument("--hosts-file", help="Archivo con IPs/MACs")
    p.add_argument("--output", default=DEFAULT_OUTPUT, help="CSV de salida")
    p.add_argument("--raw-json", help="Guardar respuestas crudas")
    p.add_argument("--endpoint-path", action="append", help="Endpoint exacto de switchport")
    p.add_argument("--insecure", action="store_true", help="No validar TLS")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--verbose", action="store_true")
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
    print(f"Dominio activo: {tenant.get('tenantName')} / {domain.get('domainName')}")


def choose(items: list[dict[str, Any]], wanted: str | None, name: str, item_id: str, label: str) -> dict[str, Any] | None:
    if not items:
        print(f"[WARN] No pude listar {label}. Sigo sin fijarlo.", file=sys.stderr)
        return None
    if wanted:
        for item in items:
            valid = (str(item.get(name, "")).casefold(), str(item.get(item_id, "")).casefold())
            if wanted.casefold() in valid:
                return item
        raise NetBrainError(f"No encontre {label}: {wanted}")
    if len(items) == 1:
        return items[0]

    print(f"\n{label.title()} disponibles:")
    for i, item in enumerate(items, 1):
        print(f"  {i}. {item.get(name)} [{item.get(item_id)}]")
    answer = input(f"Selecciona {label} por numero/nombre/ID (Enter para omitir): ").strip()
    if not answer:
        return None
    if answer.isdigit() and 1 <= int(answer) <= len(items):
        return items[int(answer) - 1]
    return choose(items, answer, name, item_id, label)


def load_targets(path: Path) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = re.split(r"#|//", line, 1)[0]
        for mac in MAC_RE.findall(line):
            add_target(targets, seen, "mac", norm_mac(mac))
            line = line.replace(mac, " ")
        for token in re.split(r"[\s,;]+", line):
            token = token.strip("[](){}<>")
            try:
                add_target(targets, seen, "ip", str(ipaddress.ip_address(token)))
            except ValueError:
                pass
    return targets


def add_target(targets: list[dict[str, str]], seen: set[tuple[str, str]], kind: str, value: str) -> None:
    key = (kind, value)
    if key not in seen:
        seen.add(key)
        targets.append({"type": kind, "value": value})


def norm_mac(mac: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def lookup(nb: NetBrain, target: dict[str, str], endpoints: list[str]) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    raw: list[dict[str, Any]] = []
    keys = ["ip", "ipAddress", "endSystemIp", "endpointIp"] if target["type"] == "ip" else [
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
                    return [row_from(target, rec, "found", path) for rec in records], raw

    if target["type"] == "ip":
        device = nb.try_call("GET", "/ServicesAPI/API/V1/CMDB/Devices", params={"ip": target["value"], "fullattr": 1})
        records = records_from(device) if device else []
        if records:
            row = row_from(target, records[0], "device-found-no-switchport", "/ServicesAPI/API/V1/CMDB/Devices")
            row["notes"] = "La IP aparece como dispositivo NetBrain, no como endpoint final."
            return [row], raw + [{"path": "/ServicesAPI/API/V1/CMDB/Devices", "response": device}]

    for path in SEARCH_ENDPOINTS:
        for key in ("keyword", "searchText", "q", "query"):
            result = nb.try_call("GET", path, params={key: target["value"]})
            records = records_from(result) if result else []
            if records:
                return [row_from(target, rec, "found", path) for rec in records], raw

    return [empty_row(target, "not-found")], raw


def records_from(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if not isinstance(data, dict):
        return []
    for key in "connectedSwitchPorts connectedSwitchPort switchPorts switchPort ports interfaces results data items devices".split():
        value = ci_get(data, key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
        if isinstance(value, dict):
            return records_from(value) or [value]
    if set(data) <= {"statusCode", "statusDescription"}:
        return []
    return [data]


def row_from(target: dict[str, str], rec: dict[str, Any], status: str, source: str) -> dict[str, str]:
    flat = {clean(k): stringify(v) for k, v in flatten(rec).items()}
    row = empty_row(target, status)
    row["source_api"] = source
    for col, aliases in ALIASES.items():
        row[col] = pick(flat, aliases)
    if target["type"] == "ip" and not row["endpoint_ip"]:
        row["endpoint_ip"] = target["value"]
    if target["type"] == "mac" and not row["endpoint_mac"]:
        row["endpoint_mac"] = target["value"]
    row["notes"] = row["notes"] or "; ".join(f"{k}={v[:60]}" for k, v in list(flat.items())[:4] if v)
    return row


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
    return next((v for k, v in flat.items() if any(k.endswith(a) for a in aliases)), "")


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


def print_table(rows: list[dict[str, str]], cols: list[str]) -> None:
    widths = {c: min(35, max([len(c)] + [len(r.get(c, "")) for r in rows])) for c in cols}
    print(" | ".join(c.ljust(widths[c]) for c in cols))
    print("-+-".join("-" * widths[c] for c in cols))
    for row in rows:
        print(" | ".join(row.get(c, "")[: widths[c]].ljust(widths[c]) for c in cols))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nCancelado.", file=sys.stderr)
        raise SystemExit(130)
    except NetBrainError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
