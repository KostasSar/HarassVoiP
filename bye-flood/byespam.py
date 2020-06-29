from scapy.all import sniff, Ether, IP, UDP, sendp, ICMP, rdpcap
import scapy.fields
import re
import codecs
import argparse

def traffic_parser(packet):
    BUSY_1 = 'SIP/2.0 486 Busy Here'
    BUSY_2 = 'X-Asterisk-HangupCause: Call Rejected\r\X-Asterisk-HangupCauseCode: 21'
    BUSY_3 = ''

    payload = packet[3].command()


    header=re.findall("Ringing", payload)
    if header:

        ip_attributes={}
        ip_attributes['version']=packet[1].version
        ip_attributes['ihl']=packet[1].ihl
        ip_attributes['tos']=packet[1].tos
        ip_attributes['len']=511 #packet[1].len
        ip_attributes['id']=packet[1].id+10
        ip_attributes['flags']=packet[1].flags
        ip_attributes['frag']=packet[1].frag
        ip_attributes['ttl']=packet[1].ttl
        ip_attributes['proto']=packet[1].proto
        ip_attributes['src']=packet[1].src
        ip_attributes['dst']=packet[1].dst

        IP_layer(ip_attributes)

        udp_attributes={}
        udp_attributes['sport']=packet[2].sport
        udp_attributes['dport']=packet[2].dport
        udp_attributes['len']=491
    
        UDP_layer(udp_attributes)


        # print(payload)
        
        # Implement packet modification
        payload = payload.replace("SIP/2.0 180 Ringing", BUSY_1, 1)
        payload = re.sub("Contact\:.*>", "X-Asterisk-HangupCause: Call Rejected\\\\r\\\X-Asterisk-HangupCauseCode: 21", payload,1)

        print(payload)

    print("\n")

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
parser.add_argument('-f', '--filter', default="udp and port 5060", help="filter to be used in scapy")
parser.add_argument('-o', "--outfile", help="output file (optional)")
parser.add_argument('-t', "--testfile", help="parse test file (optional)")
args=parser.parse_args()

if __name__ == '__main__':
    # sniff(iface=args.interface, prn=traffic_parser, filter="udp and port 5060", store=0)

    packets = rdpcap("mpourdelaaa.pcapng")
    for packet in packets:
        traffic_parser(packet)
