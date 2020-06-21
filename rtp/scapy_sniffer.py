from scapy.all import sniff
import scapy.fields
import re

def traffic_parser(packet):
    payload=packet[3].command()
    print(payload)
    print(type(payload))
    # header=re.match("Raw\(load\=(.*)\ssip", payload)
    # print(header)


    # Raw(load=b'INVITE


if __name__ == "__main__":
    sniff(filter="udp and port 5060",prn=traffic_parser)

#packets = rdpcap("test.pcap")
#sniff(lfilter=lambda x: x.haslayer(UDP) and x[Ether].src==sending_mac and x[UDP].sport==port, prn=lambda x: send(packets))
