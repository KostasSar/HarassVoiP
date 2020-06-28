#!/usr/bin/python3

import argparse
from scapy.all import sniff, Ether, IP, UDP, sendp, ICMP,RTP
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
    
    # sniff(iface=args.interface, filter=args.filter, prn=traffic_parser)
 
    eth_attributes={}
    eth_attributes["dst"]="04:b1:67:05:25:f1"
    eth_attributes["src"]="70:85:c2:dd:7a:91"
    eth_attributes["type"]=2048

    eth=Ether_layer(eth_attributes)

    ip_attributes={}
    ip_attributes['version']=4
    ip_attributes['ihl']=5
    ip_attributes['tos']=0
    ip_attributes['len']=200
    ip_attributes['id']=46866
    ip_attributes['flags']=2
    ip_attributes['frag']=0
    ip_attributes['ttl']=64
    ip_attributes['proto']=17
    ip_attributes['src']="192.168.1.2"
    ip_attributes['dst']="192.168.1.16"

    ip=IP_layer(ip_attributes)

    udp_attributes={}
    udp_attributes['sport']=8080
    udp_attributes['dport']=8081
    udp_attributes['len']=180

    udp=UDP_layer(udp_attributes)

    # sendp(eth/ip/udp/ICMP("HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567"))
    sendp(eth/ip/udp/RTP("HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567HELLO MFCKERS1234567"))



    Ethernet II, Src: ASRockIn_dd:7a:91 (70:85:c2:dd:7a:91), Dst: XiaomiCo_05:25:f1 (04:b1:67:05:25:f1)



sendp(eth/ip/udp/ICMP("HELLO MFCKERS1234567HELLOHELLO MFCKERS1234567HELLOHELLO MFCKERS1234567HELLOHELLO MFCKERS1234567HELLO"))