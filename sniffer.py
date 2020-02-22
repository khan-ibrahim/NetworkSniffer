#Network Sniffer using Scapy Framework


import argparse
import socket
from scapy.all import *


def parseFromFile(pcapFile, bpf):
    print('reading from file {}\n'.format(pcapFile))
    sniff(prn=evaluatePacket, filter=bpf, offline=pcapFile, store=0)
    return 0

def sniffLive(interfaceName, bpf):
    print('sniffing live on interface {}\n'.format(interfaceName))
    sniff(prn=evaluatePacket, filter=bpf, iface=interfaceName, store=0)
    return 0 

def evaluatePacket(pkt):
    #print('evaluating packet {}'.format(pkt)) 
    print(pkt.summary())
    return

def main():
    print('Starting sniffer.py')
    
    #parse args
    # sniffer.py [-i interface] [-r tracefile] [-e expression]
    parser = argparse.ArgumentParser()
    whereToReadFrom = parser.add_mutually_exclusive_group()

    whereToReadFrom.add_argument('-i', nargs='?', \
            choices=[x[1] for x in socket.if_nameindex()]+['*'], metavar='interfaceName', \
            help='specify interface to sniff packets on, default *.')
    
    whereToReadFrom.add_argument('-r', nargs=1, metavar='file.cap', help='specify pcap to read from')

    parser.add_argument('-e', metavar='BPF', help='specify BPF expression')
    
    parsed = parser.parse_args()
    print(parsed)

    load_layer('http')
    load_layer('tls')
    
    retval = 0

    if not parsed.r == None:
        retval = parseFromFile(parsed.r, parsed.e)
    else:
        sniffLive(parsed.i, parsed.e)

    return retval

if __name__ == "__main__":
   main()





