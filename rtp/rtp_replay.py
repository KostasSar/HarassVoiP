#!/usr/bin/python3

import argparse
from scapy.all import sniff
import scapy.fields
import re


def traffic_parser(packet):
    payload=packet[3]
    print(payload)
    print(type(payload))
    # header=re.match("Raw\(load\=(.*)\ssip", payload)
    # print(header)



parser = argparse.ArgumentParser(description="rtp replay script. Arguments: -i <interface> -f <sniff filter> -o <sniff outputfile> Interface defaults to 'eth0' and filter defaults to 'udp and port 5060'")
parser.add_argument('-i', "--interface", default="eth0", help="interface to use for sniffing")
parser.add_argument('-f', '--filter', default="udp and port 5060", help="filter to be used in scapy")
parser.add_argument('-o', "--outfile", help="output file (optional)")
args=parser.parse_args()

if __name__ == '__main__':
	# print(args.interface)
	# print(args.filter)

    sniff(iface=args.interface, filter=args.filter, prn=traffic_parser)
