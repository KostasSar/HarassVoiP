from scapy.all import sniff
import scapy.fields
import re
import codecs
import argparse

def pkt_callback(pkt):
    BUSY_1 = 'SIP/2.0 486 Busy Here'
    BUSY_2 = 'X-Asterisk-HangupCause: Call Rejected'
    BUSY_3 = 'X-Asterisk-HangupCauseCode: 21'

    payload = pkt[3].command()

    print(payload)

    header=re.findall("Ringing", payload)
    if header:
        print(header)
        # Implement packet modification
    print("\n")

parser = argparse.ArgumentParser(description="rtp replay script. Arguments: -i <interface> -f <sniff filter> -o <sniff outputfile> Interface defaults to 'eth0' and filter defaults to 'udp and port 5060'")
parser.add_argument('-i', "--interface", default="eth0", help="interface to use for sniffing")
parser.add_argument('-f', '--filter', default="udp and port 5060", help="filter to be used in scapy")
parser.add_argument('-o', "--outfile", help="output file (optional)")
args=parser.parse_args()

if __name__ == '__main__':
    sniff(iface=args.interface, prn=pkt_callback, filter="udp and port 5060", store=0)

