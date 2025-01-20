# UDP Scanner

## Requirements
Following Modules and their dependencies of python :
```
import socket
import os
import argparse
import struct
import requests
import ctypes
import ipaddress
import threading
import shutil
import time
```

## Usuage Info
```
./udp-scanner.py -h
usage: udp-scanner.py [-h] -lh LISTEN_HOST -tsn TARGET_SUBNET [-p PORT] [-v] [-raw] [--view-ip-header] [--view-icmp-header]

options:
  -h, --help            show this help message and exit
  -lh LISTEN_HOST, --listen-host LISTEN_HOST
                        IP or hostname of listening host
  -tsn TARGET_SUBNET, --target-subnet TARGET_SUBNET
                        Target Subnet for UDP Scan
  -p PORT, --port PORT  Dest Port for UDP probe
  -v, --verbose         Increase Output Verbosity, Show Address Info, Also view other packets than of icmp dest+port unreachable, This
                        will not view raw/ip/icmp packet, use other options for that
  -raw, --view-raw-buffer
                        View Raw Buffer along with Decoded packet
  --view-ip-header      View IP Header
  --view-icmp-header    View ICMP Header
```

## Coding Algorithm
- Bind your pubic interface to receive raw packets depending on your OS
- Run Seperate Threads for
    - Sending UDP probe
    - Keeping Track of Received Packets
    - Sending SIGINT when sent finish (UDP packets)
- Make sure you give enough time for the receiver to be ready before sending UDP probes, and even after completing sending
- If interrupted of sent finish, print Active Hosts and exit the program

## Extracting IP Header
- From Raw Bytes, first 20 bytes are IP Header
- Pass it to IP class, it will use `struct` module for unpacking/extracting
- Extract accordingly (depending on fields)
- See ![]()

## Extracting ICMP Header
- We are particularly interested on Type:3, Code:3; this is the type and code we should receive coz host will send this type of message when it hit to close UDP port 
- Type and Code will live within 8 bytes after the IP Header
- Hence, raw_buffer[20:20+8] is enough to extract ICMP Header, pass it to ICMP class, it will also use `struct` module like IP class
- Extract accordingly (depending on fields)
- See ![]()

## Update To Expect
- Use of database folder for getting messages according to the type and code of icmp message
- Grow database and Sniffer/Scanner to get other packets as well (like TCP in *ix systems)
- Add more command line options