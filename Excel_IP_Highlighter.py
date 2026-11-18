#!/usr/bin/env python3
"""Highlight Excel cells containing any IP address from a text file."""

import argparse
from ipaddress import ip_address
from pathlib import Path
import re
from zipfile import BadZipFile


VERSION = "1.0.0"
YELLOW = "FFFFFF00"
# Match whole IP tokens, not prefixes of longer addresses. A final sentence
# period is allowed. IPv6 is scanned first to handle IPv4-mapped IPv6 tokens.
IPV4_TOKEN = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\w|\.[\w.])")
IPV6_TOKEN = re.compile(r"(?<![\w.])(?:[0-9a-fA-F]*:){2,}[0-9a-fA-F:.]*(?![\w:.])")


def read_hosts(path):
    """Read one address per line. Blank lines, # comments and duplicates are OK."""
    hosts = set()
    with path.open(encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            entry = line.partition("#")[0].strip()
            if not entry:
                continue
            try:
                hosts.add(normalize_ip(entry))
            except ValueError as exc:
                raise ValueError(f"{path}, línea {line_number}: IP no válida.") from exc
    if not hosts:
        raise ValueError(f"No se encontraron IPs en {path}.")
    return hosts


def normalize_ip(entry):
    """Normalize address spelling and ignore any IPv6 zone suffix."""
    address = ip_address(entry)
    return address.version, int(address)


def matching_ips(text, hosts):
    """Yield matching IPs without treating a mapped IPv4 suffix as a separate IP."""
    ipv6_spans = []
    if ":" in text:
        for match in IPV6_TOKEN.finditer(text):
            try:
                key = normalize_ip(match[0].removesuffix("."))
            except ValueError:
                continue
            ipv6_spans.append(match.span())
            if key in hosts:
                yield key

    span_index = 0
    for match in IPV4_TOKEN.finditer(text):
        while span_index < len(ipv6_spans) and ipv6_spans[span_index][1] <= match.start():
            span_index += 1
        if span_index < len(ipv6_spans) and ipv6_spans[span_index][0] <= match.start():
            continue
        try:
            key = normalize_ip(match[0])
        except ValueError:
            continue
        if key in hosts:
            yield key


def highlight_workbook(source, output, hosts):
    """Set the fill on matching text cells and write a separate workbook."""
    from openpyxl import load_workbook
    from openpyxl.cell.rich_text import CellRichText
    from openpyxl.styles import PatternFill

    fill = PatternFill(fill_type="solid", fgColor=YELLOW)
    workbook = load_workbook(source, rich_text=True)
    counts = {}
    found = set()
    try:
        for sheet in workbook.worksheets:
            count = 0
            for row in sheet.iter_rows():
                for cell in row:
                    value = cell.value
                    if cell.data_type == "f" or not isinstance(value, (str, CellRichText)):
                        continue
                    hits = set(matching_ips(str(value), hosts))
                    if hits:
                        cell.fill = fill
                        count += 1
                        found.update(hits)
            counts[sheet.title] = count

        # Exclusive creation prevents overwriting an existing workbook.
        handle = output.open("xb")
        try:
            with handle:
                workbook.save(handle)
        except (Exception, KeyboardInterrupt):
            output.unlink(missing_ok=True)
            raise
    finally:
        workbook.close()
    return counts, found


def main():
    parser = argparse.ArgumentParser(
        description="Resalta en amarillo las celdas con las IPs de un TXT en todas las hojas.",
        epilog="Ejemplo: py Excel_IP_Highlighter.py inventario.xlsx hosts.txt",
    )
    parser.add_argument("excel", type=Path, help="Archivo de Excel de entrada (.xlsx).")
    parser.add_argument("hosts", type=Path, help="TXT en UTF-8, con una IPv4 o IPv6 por línea.")
    parser.add_argument("-o", "--output", type=Path, help="Ruta del nuevo Excel (.xlsx).")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if args.excel.suffix.lower() != ".xlsx":
        parser.error("El archivo de Excel de entrada debe terminar en .xlsx.")
    output = args.output or args.excel.with_name(f"{args.excel.stem}_resaltado.xlsx")
    if output.suffix.lower() != ".xlsx":
        parser.error("El archivo de Excel de salida debe terminar en .xlsx.")
    if output.exists() or output.is_symlink():
        parser.error(f"El archivo {output} ya existe. Usa -o para elegir otro nombre.")

    try:
        hosts = read_hosts(args.hosts)
        counts, found = highlight_workbook(args.excel, output, hosts)
    except ImportError:
        parser.exit(1, 'Instala la dependencia con: py -m pip install "openpyxl>=3.1"\n')
    except (OSError, ValueError, BadZipFile) as exc:
        parser.exit(1, f"Error: {exc}\n")

    for sheet, count in counts.items():
        print(f"{sheet}: {count} celda(s) con coincidencias")
    print(f"Total de celdas resaltadas: {sum(counts.values())}")
    print(f"IPs encontradas: {len(found)} de {len(hosts)}")
    print(f"Archivo generado: {output}")


if __name__ == "__main__":
    main()
