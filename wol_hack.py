#! /usr/bin/env python

# Quick & dirty script to catch WakeOnLan packets and start Proxmox VMs if required
# WTFPL
# Requires pcap, dpkt, available on proxmox through apt, yey \o/

import subprocess, pcap, dpkt, binascii, re

def exec_clean(commande):
    return subprocess.check_output(commande).rstrip().split('\n')

qm = exec_clean(['qm', 'list'])
vm_macs = {}

for ligne in qm[1:]:
    vm = ligne.strip().partition(' ')[0]
    config = exec_clean(['qm', 'config', vm])
    for info in config:
        if info.startswith('net'):
            mac = re.sub('^net[0-9]+: [^=]+=([A-F0-9:]+),.+', '\g<1>', info)
            vm_macs[mac] = vm

#print(vm_macs)
pc = pcap.pcap()

pc.setfilter('udp port 9 and (udp[8:4] == 0xFFFFFFFF and udp[12:2] == 0xFFFF)')

def add_colons_to_mac( mac_addr ) :
    """This function accepts a 12 hex digit string and converts it to a colon separated string"""
    s = list()
    for i in range(12/2) : 	# mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append( mac_addr[i*2:i*2+2] )
    r = ":".join(s)		# I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
    return r

for ts, pkt in pc:
    a = dpkt.ethernet.Ethernet(pkt)
    i = a.data
    u = i.data
    w = u.data
    macd = add_colons_to_mac(binascii.hexlify(w[6:13])).upper()
    if macd in vm_macs.keys():
        print('Demarrage de ' + vm_macs[macd])
        try:
            r = subprocess.check_output(['qm', 'start', vm_macs[macd]])
            print(r)
        except subprocess.CalledProcessError:
            print('Start failed, probably because VM is already running')
