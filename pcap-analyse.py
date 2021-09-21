#!/usr/bin/python3 -tt

from scapy.all import *
import sys
from datetime import datetime

'''Parse packet capture PCAP files and outputs 5 tuple flows.\n
   Usage:\n
   python pcap_analyse.py [ pcap filename ]\n
'''

def parse_pcap(pkt):  

    type = None

    try:
        type = pkt.getlayer(IP).proto
    except:
        pass

    snifftime = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S').split(' ')[1]

    if type == 6:
        type = 'TCP'
    if type == 17:
        type = 'UDP'
    if type == 1:
        type = 'ICMP'

    if type == 'TCP' or type == 'UDP':
        print( ' '.join([snifftime, type.rjust(4, ' '), str(pkt.getlayer(IP).src).rjust(15, ' ') , str(pkt.getlayer(type).sport).rjust(5, ' ') , '-->' , str(pkt.getlayer(IP).dst).rjust(15, ' ') , str(pkt.getlayer(type).dport).rjust(5, ' ')]))

    elif type == 'ICMP':
        print(' '.join([snifftime, 'ICMP'.rjust(4, ' '),  str(pkt.getlayer(IP).src).rjust(15, ' ') , ('t: '+ str(pkt.getlayer(ICMP).type)).rjust(5, ' '), '-->' , str(pkt.getlayer(IP).dst).rjust(15, ' '), ('c: ' + str(pkt.getlayer(ICMP).code)).rjust(5, ' ')]))

    else:
        pass

if __name__ == '__main__':
    pkts = rdpcap(sys.argv[1])
    print(' '.join(['Date: ',datetime.fromtimestamp(pkts[0].time).strftime('%Y-%m-%d %H:%M:%S').split(' ')[0]]))
    for pkt in pkts:
        parse_pcap(pkt)

