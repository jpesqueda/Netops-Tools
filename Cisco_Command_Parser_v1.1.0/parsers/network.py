"""VLAN, ARP, DHCP snooping, device-tracking and DAI parsers."""
import re
from utils.core import clean_lines, normalize_interface, integer

def parse_vlan(raw):
    out=[]
    for line in clean_lines(raw):
        m=re.match(r'^\s*(\d+)\s+(\S+)\s+(active|act/unsup|suspended|shutdown)\s*(.*)$',line,re.I)
        if m:out.append({'vlan':int(m[1]),'name':m[2],'status':m[3],'interfaces':m[4].strip()})
        elif out and re.match(r'^\s{5,}(?:Gi|Te|Fa|Po)\d',line):out[-1]['interfaces']+=', '+line.strip()
    return out

def parse_arp(raw):
    out=[]
    for line in clean_lines(raw):
        p=line.split()
        if len(p)>=6 and p[0]=='Internet':out.append({'ip':p[1],'age':p[2],'mac':p[3],'type':p[4],'interface':normalize_interface(p[5])})
    return out

def parse_arp_inspection(raw):
    out=[]
    for line in clean_lines(raw):
        p=line.split()
        if len(p)>=4 and re.match(r'^[A-Za-z]+\d',p[0]) and p[1].lower() in ('trusted','untrusted'):
            out.append({'interface':normalize_interface(p[0]),'trust_state':p[1],'rate_pps':p[2],'burst_interval':p[3]})
    return out

def parse_dhcp_binding(raw):
    out=[]
    for line in clean_lines(raw):
        p=line.split()
        if len(p)>=6 and ':' in p[0] and re.match(r'\d+\.\d+\.\d+\.\d+',p[1]):
            out.append({'mac':p[0],'ip':p[1],'lease_sec':integer(p[2]),'type':p[3],'vlan':p[4],'interface':normalize_interface(p[5])})
    return out

def parse_tracking(raw):
    out=[]
    for line in clean_lines(raw):
        p=line.split()
        if len(p)>=7 and re.match(r'\d+\.\d+\.\d+\.\d+$',p[0]):
            out.append({'ip':p[0],'mac':p[1],'interface':normalize_interface(p[2]),'vlan':p[3],'prlvl':p[4],'age':p[5],'state':p[6]})
    return out
