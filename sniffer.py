#Network Sniffer using Scapy Framework


import argparse
import socket
from scapy.all import *
from datetime import *

def parseFromFile(pcapFile, bpf):
    print('Reading from pcap:{} with bpf:{}\n'.format(pcapFile, bpf))
    sniff(prn=evaluatePacket, filter=bpf, offline=pcapFile, store=0)
    return 0

def sniffLive(interfaceName, bpf):
    print('Sniffing live with bpf:{}; Interface specified:{}\n'.format(bpf, interfaceName))
    sniff(prn=evaluatePacket, filter=bpf, iface=interfaceName, store=0)
    return 0 

def evaluatePacket(pkt):
    #print('evaluating packet {}'.format(pkt)) 
    load_layer('tls')
    load_layer('http')
    
    #print('- - - -'pkt.summary())
    timestamp = ''
    proto = ''
    txt = ''
    version = ''
    if pkt.haslayer(TLS):
        proto = 'TLS'
        if pkt.haslayer(TLSClientHello):

            versionCode = pkt[TLSClientHello].version
            
            versionCodes = [769, 770, 771, 772]
            versions = ['1.0', '1.1', '1.2', '1.3']
            if versionCode in versionCodes:
                version = ' ' + versions[versionCodes.index(versionCode)] + '\t'
            
            serverName = pkt[ServerName].servername

            txt = '{}'.format(serverName)
        else:
            return
    elif pkt.haslayer(HTTP) and pkt.haslayer(HTTPRequest):
        proto = 'HTTP'
        if pkt[HTTP].Method == b'POST':
            request = 'POST'
        elif pkt[HTTP].Method == b'GET':
            request = 'GET'
        else:
            return

        host = pkt[HTTP][HTTPRequest].Host
        path = pkt[HTTP][HTTPRequest].Path
        txt = '{}\t{}\t{}'.format(host, request, path)
    else:
        return

    timestamp = (datetime.fromtimestamp(pkt.time)).isoformat(' ', timespec='microseconds')

    src = pkt[IP].src
    sport = pkt[IP].sport

    dst = pkt[IP].dst
    dport = pkt[IP].dport

    return '{}\t{}{}\t{}:{} -> {}:{}\t{}'.format(timestamp, proto, version, src, sport, dst, dport, txt)

def main():
    #print('Starting sniffer.py')
    
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
    #print(parsed)

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





