#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
	pkt.show()

pkt = sniff(iface="enp0s3", filter="host 8.8.8.8 and tcp port 23", prn=print_pkt)