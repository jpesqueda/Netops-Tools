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
