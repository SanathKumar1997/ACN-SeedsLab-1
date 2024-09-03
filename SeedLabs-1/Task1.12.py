#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
        pkt.show()


src_ip='10.9.0.6'
dst_port=23


filter_expression = f'tcp and src host {src_ip} and dst port {dst_port}'

pkt = sniff(iface='br-85907b6c22b1', filter=filter_expression, prn=print_pkt)