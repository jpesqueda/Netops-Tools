"""Excel exporter using openpyxl (compatible with native Windows Python).

Every parsed command is written to its own worksheet. All raw outputs are
retained in Raw_Commands up to Excel's 32767-character per-cell limit.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableStyleInfo

MAX_EXCEL_CELL = 32767
HEADER_FILL = PatternFill('solid', fgColor='17365D')
HEADER_FONT = Font(color='FFFFFF', bold=True)


def safe_cell(value):
    """Make parsed data safe for Excel cells without executing formulas."""
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    if value is None:
        return None
    if isinstance(value, (int, float, bool)):
        return value
    text = str(value).replace('\x00', '')[:MAX_EXCEL_CELL]
    if text.lstrip().startswith(('=', '+', '-', '@')):
        text = "'" + text[:MAX_EXCEL_CELL - 1]
    return text


def excel_export(path, device, blocks, parsed, master, summary):
    """Generate a multi-sheet audit workbook; returns its output path."""
    wb = Workbook()
    wb.remove(wb.active)
    names_used = set()
    sheet_number = 0

    def add_sheet(name, rows, columns=None):
        nonlocal sheet_number
        name = re.sub(r'[\\/*?:\[\]]', '_', name)[:31]
        base = name
        suffix = 2
        while name.casefold() in names_used:
            ext = f'_{suffix}'
            name = base[:31 - len(ext)] + ext
            suffix += 1
        names_used.add(name.casefold())
        ws = wb.create_sheet(name)
        rows = list(rows)
        if columns is None:
            columns = list(dict.fromkeys(key for row in rows for key in row.keys())) or ['Info']
        ws.append([str(col) for col in columns])
        for entry in rows:
            ws.append([safe_cell(entry.get(col)) for col in columns])

        ws.freeze_panes = 'A2'
        ws.sheet_view.showGridLines = False
        ws.row_dimensions[1].height = 27
        for cell in ws[1]:
            cell.fill = HEADER_FILL
            cell.font = HEADER_FONT
            cell.alignment = Alignment(vertical='center')

        for col_idx, col_name in enumerate(columns, start=1):
            sample = [str(col_name)]
            sample.extend(str(ws.cell(row_idx, col_idx).value or '')[:100]
                          for row_idx in range(2, min(ws.max_row, 201) + 1))
            width = max(13, min(45, max(len(line.split('\n')[0]) for line in sample) + 3))
            ws.column_dimensions[get_column_letter(col_idx)].width = width

        if rows:
            sheet_number += 1
            table_ref = f'A1:{get_column_letter(len(columns))}{ws.max_row}'
            table = Table(displayName=f'AuditTable{sheet_number:03d}', ref=table_ref)
            table.tableStyleInfo = TableStyleInfo(
                name='TableStyleMedium2', showFirstColumn=False,
                showLastColumn=False, showRowStripes=True, showColumnStripes=False,
            )
            ws.add_table(table)
        else:
            ws.auto_filter.ref = f'A1:{get_column_letter(len(columns))}1'
        return ws

    info = device or {}
    add_sheet('Device_Summary', [{
        'hostname': info.get('hostname'), 'model': info.get('model'),
        'serial': info.get('serial'), 'version': info.get('version'),
        'uptime': info.get('uptime'), 'image': info.get('image'),
        'commands_found': len(blocks),
        'parsed_commands': sum(s['status'] == 'PARSED' for s in summary),
    }])
    add_sheet('Parsing_Summary', summary, ['command', 'status', 'records', 'error'])
    add_sheet('Interfaces_Master', master)
    for command, rows in parsed.items():
        add_sheet(command, rows)
    add_sheet('Raw_Commands', [
        {'command': b['command'], 'status': b['status'], 'records': b['records'],
         'raw_output': b['raw_output']}
        for b in blocks
    ], ['command', 'status', 'records', 'raw_output'])

    path = Path(path)
    wb.save(path)
    return path
