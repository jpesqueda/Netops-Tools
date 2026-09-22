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

    def validate_connection(self) -> None:
        last_error = None
        for path in (SESSION, "/"):
            url = urljoin(self.url + "/", path.lstrip("/"))
            ctx = None if self.verify_tls else ssl._create_unverified_context()
            req = Request(url, headers={"Accept": "application/json"}, method="GET")
            try:
                with urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    print(f"Conexion OK: NetBrain responde en {url} con HTTP {resp.status}.")
                    return
            except HTTPError as exc:
                print(f"Conexion OK: NetBrain responde en {url} con HTTP {exc.code}.")
                return
            except URLError as exc:
                last_error = exc
                if self.verbose:
                    print(f"[DEBUG] prueba de conexion fallo en {url}: {exc}", file=sys.stderr)
        raise NetBrainError(f"No pude conectar a NetBrain en {self.url}. Detalle: {last_error}")

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
        print("Validando conexion con NetBrain...")
        nb.validate_connection()
        print("Conectando a la API de NetBrain...")
        nb.login()
        print("Login OK: token recibido.")
        select_domain(nb, args.tenant, args.domain)
        print(f"Buscando {len(targets)} endpoint(s)...")
        for target in targets:
            target_rows, target_raw = lookup(
                nb,
                target,
                args.endpoint_path or DEFAULT_ENDPOINTS,
                scan_oneip=args.oneip_scan or not args.no_oneip_scan,
                oneip_count=args.oneip_count,
            )
            rows.extend(target_rows)
            raw.append({"target": target["value"], "responses": target_raw})
    finally:
        nb.logout()

    output = Path(args.output or DEFAULT_OUTPUT)
    write_csv(output, rows)
    if args.raw_json:
        Path(args.raw_json).write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    print_table(rows, COLS[:10])
    if rows and all(row["status"] == "not-found" for row in rows):
        print("\n[WARN] La conexion/login fueron correctos, pero NetBrain no regreso switchport para esas IPs/MACs.")
        print("[WARN] Prueba con --verbose --raw-json raw.json o confirma el endpoint exacto con --endpoint-path.")
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
    p.add_argument("--oneip-scan", action="store_true", help="Compatibilidad: el escaneo One-IP ya viene activo por default")
    p.add_argument("--no-oneip-scan", action="store_true", help="No escanear One-IP Table si el filtro directo no devuelve datos")
    p.add_argument("--oneip-count", type=int, default=10000, help="Registros por pagina al usar --oneip-scan")
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
        line = re.split(r"#|//", line, maxsplit=1)[0]
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
                    rows = useful_rows(target, records, path)
                    if rows:
                        return rows, raw

    if target["type"] == "ip":
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
    if target["type"] != "ip":
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
    query_keys = ["ip", "IP", "ipAddress", "IP Address"] if target["type"] == "ip" else [
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

    print(f"  Escaneando One-IP Table para {target['value']}...")
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
        if target["type"] == "mac":
            values |= {clean(norm_mac(v)) for v in flat.values() if len(re.sub(r"[^0-9a-fA-F]", "", v)) == 12}
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
    if target["type"] == "mac" and row.get("endpoint_ip"):
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
        row["endpoint_mac"] = norm_mac(row["endpoint_mac"])
    enrich_from_gui_text(row, " ".join(flat.values()))
    if target["type"] == "ip" and not row["endpoint_ip"]:
        row["endpoint_ip"] = target["value"]
    if target["type"] == "mac" and not row["endpoint_mac"]:
        row["endpoint_mac"] = target["value"]
    row["notes"] = row["notes"] or "; ".join(f"{k}={v[:60]}" for k, v in list(flat.items())[:4] if v)
    return row


def enrich_from_gui_text(row: dict[str, str], text: str) -> None:
    mac = re.search(r"MAC Address:\s*([0-9a-fA-F.:-]{12,17})", text, re.I)
    ip = re.search(r"IP Address:\s*([0-9a-fA-F:.]+)", text, re.I)
    port = re.search(r"Connected Switch Port:\s*([^\s,;]+)", text, re.I)
    if mac and not row["endpoint_mac"]:
        row["endpoint_mac"] = norm_mac(mac.group(1))
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
