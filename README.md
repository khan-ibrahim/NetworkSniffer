# NetworkSniffer
Passive HTTP/TLS connection monitoring tool written in Python. Uses Scapy framework.
Tested for Python 3.7.6. Requires root.

## Details

Parses HTTP and TLS packets, on any port in any direction.

### HTTP

Parses HTTP traffic. 

Identifies src/dst ip and prt. Identifies request type, destination hostname, and request URI.

### TLS

Parses TLS Client Hello Packets.

Identifies src/dst ip and prt. Identifies TLS version and destination hostname (exposed in servername field, even though payload is encrypted).

## Usage:

usage: sniffer.py [-h] [-i [interfaceName] | -r file.cap] [-e BPF]

optional arguments:
  -h, --help          show this help message and exit
  -i [interfaceName]  specify interface to sniff packets on. By default sniffs on all.
  -r file.cap         specify pcap to read from
  -e BPF              specify BPF expression


