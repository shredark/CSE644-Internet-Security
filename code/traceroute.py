#!/usr/bin/env python3

from scapy.all import *

a = IP()
b = ICMP()
a.dst = "8.8.8.8"
TTL = 1

a.ttl = TTL 

h = sr1(a/b, timeout=2, verbose=0)

i = 0 
 
if h is None: 
	print("Router : *** (hops {})".format(TTL))
else: 
	print("Router : {} (hops {})".format(h.src, TTL))