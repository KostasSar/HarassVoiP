from scapy.all import *
# import sip


ringing = ''

def pkt_callback(pkt):
    BUSY_1 = 'SIP/2.0 486 Busy Here'
    BUSY_2 = 'X-Asterisk-HangupCause: Call Rejected'
    BUSY_3 = 'X-Asterisk-HangupCauseCode: 21'

    ringing = pkt # debug statement
    print(ringing.summary())

sniff(iface="wlp7s0", prn=pkt_callback, filter="udp and port 5060", store=0)

