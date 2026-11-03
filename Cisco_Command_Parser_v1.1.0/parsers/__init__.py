"""Parser registry. Add future command parsers here."""
from .system import parse_version,parse_inventory,parse_environment
from .interfaces import parse_status,parse_description,parse_counters,parse_errors,parse_ip_brief,parse_trunk
from .network import parse_vlan,parse_arp,parse_arp_inspection,parse_dhcp_binding,parse_tracking
PARSERS={
'show version':parse_version,'show inventory':parse_inventory,
'show interfaces status':parse_status,'show interfaces description':parse_description,
'show interfaces counters':parse_counters,'show interfaces counters errors':parse_errors,
'show ip interface brief':parse_ip_brief,'show vlan brief':parse_vlan,
'show interfaces trunk':parse_trunk,'show ip arp':parse_arp,
'show ip arp inspection interfaces':parse_arp_inspection,
'show ip dhcp snooping binding':parse_dhcp_binding,
'show device-tracking database':parse_tracking,'show environment all':parse_environment,
}
ALIASES={'show interface status':'show interfaces status','show interface description':'show interfaces description'}
