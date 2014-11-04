#! /usr/bin/env python

# Quick & dirty script to catch WakeOnLan packets and start Proxmox VMs if required
# WTFPL
# Requires pcap, dpkt, available on proxmox through apt (python-pypcap python-dpkt), yey \o/
# Not tested on Python 3 as python is 2.7 by default on proxmox 3

import subprocess, pcap, dpkt, binascii, re

def exec_clean(command):
    """ Simple wrapper to execute a command, and get the result as a list """ 
    return subprocess.check_output(command).rstrip().split('\n')

def vmlist():
    """ Returns a dictionnary with each MACs as keys, and the VM as value """
    qm = exec_clean(['qm', 'list'])
    vm_macs = {}
    for ligne in qm[1:]:
        vm = ligne.strip().partition(' ')[0]
        config = exec_clean(['qm', 'config', vm])
        for info in config:
            if info.startswith('net'):
                mac = re.sub('^net[0-9]+: [^=]+=([A-F0-9:]+),.+', '\g<1>', info)
                vm_macs[mac] = vm
    return vm_macs

def add_colons_to_mac( mac_addr ) :
    """This function accepts a 12 hex digit string and converts it to a colon separated string"""
    s = list()
    for i in range(12/2) : 	# mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append( mac_addr[i*2:i*2+2] )
    r = ":".join(s)		# I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
    return r

def start_scan():
    pc = pcap.pcap()
    pc.setfilter('udp port 9 and (udp[8:4] == 0xFFFFFFFF and udp[12:2] == 0xFFFF)')


    for ts, pkt in pc:
        a = dpkt.ethernet.Ethernet(pkt)
        #IP
        i = a.data
        #UDP
        u = i.data
        #WoL
        w = u.data
        macd = add_colons_to_mac(binascii.hexlify(w[6:13])).upper()
        if macd in vm_macs.keys():
            print('Demarrage de ' + vm_macs[macd])
            try:
                r = subprocess.check_output(['qm', 'start', vm_macs[macd]])
                print(r)
            except subprocess.CalledProcessError:
                print('Start failed, probably because VM is already running, I know, I could have checked, but well.')

if __name__ == '__main__':
    vm_macs = vmlist()
    start_scan()
