#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
        pkt.show()


subnet = '128.230.0.0/16'


filter_expression = f'net {subnet}'

pkt = sniff(iface='br-85907b6c22b1', filter=filter_expression, prn=print_pkt)