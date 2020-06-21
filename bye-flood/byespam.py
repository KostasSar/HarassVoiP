from scapy.all import *
import binascii

def pkt_callback(pkt):
    BUSY_1 = 'SIP/2.0 486 Busy Here'
    BUSY_2 = 'X-Asterisk-HangupCause: Call Rejected'
    BUSY_3 = 'X-Asterisk-HangupCauseCode: 21'

    ringing = pkt # debug statement
    payload = ringing[3]
    # print(type(payload))
    payload = binascii.hexlify(bytes(payload))
    print(payload.decode('hex'))


sniff(iface="wlp7s0", prn=pkt_callback, filter="udp and port 5060", store=0)

