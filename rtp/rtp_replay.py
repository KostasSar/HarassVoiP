#!/usr/bin/python3

import argparse
from scapy.all import sniff, Ether, IP, UDP, send
import scapy.fields
import re
import codecs


def traffic_parser(packet):
    whole_packet=packet.command()
    print(whole_packet)
    print(type(whole_packet))

    payload=packet[3].command()
    # print(payload)
    # print(type(payload))
    header=re.match("Raw\(load\=b\'(.*)\ssip", payload)
    # print(type(header))
    if header:
    	print(header.groups())

    header=re.match("Raw\(load\=b\'(.*)\ssip", payload)


def Ether_layer(attributes):
    layer2=Ether()
    layer2.dst=attributes['dst']
    layer2.src=attributes['src']
    layer2.type=attributes['type']

    return layer2


def IP_layer(attributes):
    layer3=IP()
    layer3.version=attributes['version']
    layer3.ihl=attributes['ihl']
    layer3.tos=attributes['tos']
    layer3.len=attributes['len']
    layer3.id=attributes['id']
    layer3.flags=attributes['flags']
    layer3.frag=attributes['frag']
    layer3.ttl=attributes['ttl']
    layer3.proto=attributes['proto']
    layer3.src=attributes['src']
    layer3.dst=attributes['dst']

    return layer3


def UDP_layer(attributes):
    layer4=UDP()
    layer4.sport=attributes['sport']
    layer4.dport=attributes['dport']
    layer4.len=attributes['len']

    return layer4





parser = argparse.ArgumentParser(description="rtp replay script. Arguments: -i <interface> -f <sniff filter> -o <sniff outputfile> Interface defaults to 'eth0' and filter defaults to 'udp and port 5060'")
parser.add_argument('-i', "--interface", default="eth0", help="interface to use for sniffing")
parser.add_argument('-f', '--filter', default="udp and (port 5060 or portrange 15000-15010)", help="filter to be used in scapy")
parser.add_argument('-o', "--outfile", help="output file (optional)")
args=parser.parse_args()

if __name__ == '__main__':
    print("capturing from: "+args.interface)
    print("capture filter is: '"+args.filter+"'\n---------------------")
    
    sniff(iface=args.interface, filter=args.filter, prn=traffic_parser)
 