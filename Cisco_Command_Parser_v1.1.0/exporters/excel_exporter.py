"""Excel export built with artifact_tool, Windows-compatible Python."""
from artifact_tool import Workbook,SpreadsheetFile
import re

def excel_export(path,device,blocks,parsed,master,summary):
    wb=Workbook.create();used=set()
    def tab(name,rows,columns=None):
        safe=re.sub(r'[\\/*?:\[\]]','_',name)[:31]
        base=safe;n=2
        while safe.lower() in used:
            suffix=f'_{n}';safe=base[:31-len(suffix)]+suffix;n+=1
        used.add(safe.lower())
        sheet=wb.worksheets.add(safe)
        if not columns:
            columns=list(dict.fromkeys(k for row in rows for k in row.keys())) if rows else ['Info']
        matrix=[columns]+[[safe_cell(row.get(c)) for c in columns] for row in rows]
        # Excel limits 32,767 chars per cell; keep raw output in JSON/TXT if longer.
        rng=sheet.get_range_by_indexes(0,0,len(matrix),len(columns));rng.values=matrix
        head=sheet.get_range_by_indexes(0,0,1,len(columns))
        head.format={'fill':'#17365D','font':{'bold':True,'color':'#FFFFFF'},'row_height':28,'vertical_alignment':'center'}
        sheet.freeze_panes.freeze_rows(1)
        if rows:
            try:sheet.tables.add(sheet.get_range_by_indexes(0,0,len(matrix),len(columns)),True,'T'+str(len(used)).zfill(3))
            except Exception:pass
        for col in range(len(columns)):
            longest=max((len(str(row[col] or '')) for row in matrix[:201]),default=16)
            sheet.get_range_by_indexes(0,col,len(matrix),1).format.column_width=max(13,min(longest+3,45))
        return sheet
    info=device or {}
    tab('Device_Summary',[{'hostname':info.get('hostname'),'model':info.get('model'),'serial':info.get('serial'),'version':info.get('version'),'uptime':info.get('uptime'),'image':info.get('image'),'commands_found':len(blocks),'parsed_commands':sum(s['status']=='PARSED' for s in summary)}])
    tab('Parsing_Summary',summary,['command','status','records','error'])
    tab('Interfaces_Master',master)
    for cmd,rows in parsed.items():tab(cmd,rows)
    tab('Raw_Commands',[{'command':b['command'],'status':b['status'],'records':b['records'],'raw_output':b['raw_output']} for b in blocks],['command','status','records','raw_output'])
    SpreadsheetFile.export_xlsx(wb).save(str(path))

def safe_cell(value):
    if isinstance(value,(dict,list)):return str(value)
    if isinstance(value,str):
        value=value[:32750]
        if value.startswith(('=','+','-','@')):return "'"+value
    return value
