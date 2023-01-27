from scapy.all import *
a = IP()
a.dst = "8.8.8.8"
b = ICMP()
p = a/b
send(p)

ls(a)
