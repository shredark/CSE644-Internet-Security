#!/usr/bin/env python3

from scapy.all import *
def print_pkt(pkt):
	pkt.show()

pkt = sniff(iface="br-d273fff9cb7d", filter="icmp", prn=print_pkt)
