# NetworkSniffer
Passive HTTP/TLS connection monitoring tool Uses Scapy framework. Requires root to sniff live.

[![Python 3.7.6](https://img.shields.io/badge/python-3.7.6-blue.svg)](https://www.python.org/downloads/release/python-376/)


## Details

Parses HTTP and TLS packets, realtime or from file, on any port in any direction. Can be used to detect hidden services.

### HTTP

Parses HTTP traffic. 

Identifies src/dst ip and prt. Identifies request type, destination hostname, and request URI.

### TLS

Parses TLS Client Hello Packets.

Identifies src/dst ip and prt. Identifies TLS version and destination hostname (exposed in servername field, even though payload is encrypted).

## Usage:
```
usage: sniffer.py [-h] [-i [interfaceName] | -r file.cap] [-e BPF]

optional arguments:
  -h, --help          show this help message and exit
  -i [interfaceName]  specify interface to sniff packets on. By default sniffs on all.
  -r file.cap         specify pcap to read from
  -e BPF              specify BPF expression
```

