#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
  pkt.show()

pkt = sniff(iface='br-85907b6c22b1', filter='icmp', prn=print_pkt)