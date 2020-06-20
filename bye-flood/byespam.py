from scapy.all import *

BUSY_1 = 'SIP/2.0 486 Busy Here'
BUSY_2 = 'X-Asterisk-HangupCause: Call Rejected'
BUSY_3 = 'X-Asterisk-HangupCauseCode: 21'

ringing = ''

def pkt_callback(pkt):
    pkt.show() # debug statement

sniff(iface="wlp7s0", prn=pkt_callback, filter="udp", store=0, )

