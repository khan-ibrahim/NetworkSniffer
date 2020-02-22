#Network Sniffer using Scapy Framework


import argparse
import socket


def parseFromFile(pcapFile, bpf):
    print('reading from file {}'.format(pcapFile))
    return 0

def sniffLive(interfaceName, bpf):
    print('sniffing live on interface {}'.format(interfaceName))
    return 0 

def evaluatePacket(pkt):
    return 0

def main():
    print('Starting sniffer.py')
    
    #parse args
    # sniffer.py [-i interface] [-r tracefile] [-e expression]
    parser = argparse.ArgumentParser()
    
    whereToReadFrom = parser.add_mutually_exclusive_group()

    whereToReadFrom.add_argument('-i', nargs='?', const='*', choices=[x[1] for x in socket.if_nameindex()]+['*'], metavar='interfaceName', help='specify interface to sniff packets on, default *.')

    
    whereToReadFrom.add_argument('-r', nargs=1, metavar='file.cap', help='specify pcap to read from')

    parser.add_argument('-e', nargs=1, metavar='BPF', help='specify BPF expression')
    
    parsed = parser.parse_args()

    #print(parsed)
    retval = 0

    if not parsed.r == None:
        retval = parseFromFile(parsed.r, parsed.e)
    else:
        sniffLive(parsed.i, parsed.e)

    return retval

if __name__ == "__main__":
   main()





