"""Join parsed per-interface datasets without losing independent records."""
from utils.core import normalize_interface

def consolidate(parsed):
    master={}
    commands=[('show interfaces status','status'),('show interfaces description','description'),('show ip interface brief','ip'),('show interfaces counters','counters'),('show interfaces counters errors','errors'),('show interfaces trunk','trunk'),('show ip arp inspection interfaces','dai')]
    for cmd,source in commands:
        for record in parsed.get(cmd,[]):
            key=normalize_interface(record.get('interface'))
            if not key:continue
            row=master.setdefault(key,{'interface':key})
            for field,value in record.items():
                if field=='interface':continue
                # Keep per-source fields distinct when ambiguous (status, description, etc.).
                new_field={'status':'port_status' if source=='status' else 'line_status' if source=='description' else 'ip_status' if source=='ip' else 'trunk_status' if source=='trunk' else 'status', 'description':'description'}.get(field,field)
                if new_field in row and row[new_field]!=value:new_field=source+'_'+new_field
                row[new_field]=value
    for cmd,fields in [('show ip dhcp snooping binding',['dhcp_ip','dhcp_mac']),('show device-tracking database',['tracking_ip','tracking_mac','tracking_state'])]:
        for rec in parsed.get(cmd,[]):
            key=normalize_interface(rec.get('interface'))
            if key not in master:master[key]={'interface':key}
            row=master[key]
            if cmd.startswith('show ip dhcp'):
                for key2,val in [('dhcp_ip',rec.get('ip')),('dhcp_mac',rec.get('mac'))]:
                    if row.get(key2):row[key2]+='; '+str(val)
                    else:row[key2]=str(val)
            else:
                for key2,val in [('tracking_ip',rec.get('ip')),('tracking_mac',rec.get('mac')),('tracking_state',rec.get('state'))]:
                    if row.get(key2):row[key2]+='; '+str(val)
                    else:row[key2]=str(val)
    return sorted(master.values(),key=lambda x:x['interface'])
