#!/bin/python3

# this script will capture packet and decode at ip level, all ip header, please check pics/ipv4-header.png 

import socket
import os
import argparse
import struct
import requests
import ctypes
import ipaddress
import shutil


ENABLE = True
DISABLE = False

class IP:
    """
    ip class for extraction of ipv4 header
    """
    def __init__(self, raw_buffer_with_ip_header):
        self.raw_header = raw_buffer_with_ip_header[0:20]
        header = struct.unpack('<BBHHHBBH4s4s', self.raw_header)

        # this is big picture for ip header extraction, you could further go deep on header inspection for extracting sub header
        self.ver = header[0] >> 4       # ip version
        self.ihl = header[0] & 0xF      # ip header length
        self.tos = header[1]            # type of service
        self.len = header[2]            # total length
        self.id = header[3]             # header identification
        self.offset = header[4]         # fragment offset
        self.ttl = header[5]            # timetolive
        self.protocol_num = header[6]   # protocol number
        self.sum = header[7]            # checksum          
        self.src = header[8]            # source ip address
        self.dst = header[9]            # dest ip address

        # extract ip address into human readable form
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # protocol dictionary, protocol_num:protocol_name
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def get_src_ip(self):
        return self.src_address
    
    def get_dest_ip(self):
        return self.dst_address
    
    def get_proto_name(self):
        return self.protocol_map[self.protocol_num]


class Sniffer(socket.socket):
    """
    create a Sniffer class as child of socket.socket to initilize socket for raw packet capture according to the system
    """
    def __init__(self, host):
        if os.name == "nt":
            self.sock_protocol = socket.IPPROTO_IP
        else:
            self.sock_protocol = socket.IPPROTO_ICMP # be specific about your capture if you are not in windows (or if you are in linux)

        # build a sock object for sniffer 
        self.sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.sock_protocol)
        # bind to the public interface 
        self.sniffer.bind((host, 0))
        # set options for ip header i.e HDRINCL (include header)
        self.sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # if platform is windows you should enable promicious mode to capture 
        if os.name == "nt":
            self.promicious_mode(ENABLE)

    def promicious_mode(self, mode: bool=DISABLE):
        # flag should be either ENABLE or DISABLE
        if mode == ENABLE:
            self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    def get_domain_name(self, ip_addr):
        try:
            url = f"http://ip-api.com/json/{ip_addr}"
            response = requests.get(url)
            data = response.json()
            return data.get("org", "")
        except Exception as e:
            print(f"Expection on Sniffer : {e.__class__.__name__} as {str(e)}")
            return ""

    def recv_display(self, bufsize: int=65535):
        # reveive single stream of bytes 
        raw_buffer, addr = self.sniffer.recvfrom(bufsize)
        print(f"Received Address : {addr}, {self.get_domain_name(addr[0])}, {socket.getnameinfo(addr, 0)}")
        print(f"Raw bytes : \n{raw_buffer}")
        ip_obj = IP(raw_buffer)
        print(f"{ip_obj.get_proto_name()} : {ip_obj.get_src_ip()} -> {ip_obj.get_dest_ip()}")
        # Get the terminal size
        terminal_width = shutil.get_terminal_size().columns
        # Print asterisks across the console
        print("*" * terminal_width)

def argument_parser() -> argparse.Namespace:
    """
    add the necessary arguments to the parser and return the parsed arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-lh', '--listen-host', help="IP or hostname of listening host", type=str, required=True)
    args = parser.parse_args()
    return args


def is_admin():
    if os.name == "nt":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    if os.getuid() != 0:
        return False
    return True


def main():
    # get args 
    args = argument_parser()

    # if prev is not root abort 
    if not is_admin():
        print("Run as Root.")
        exit()

    host = args.listen_host
    # get you sniffer object which is nothing but sub class of socket.socket 
    sniff = Sniffer(host)
    print(f"Sniffing for IP packets at {host}......")
    
    try:
        while True:
            sniff.recv_display(65535)
    except KeyboardInterrupt:
        print("Ctrl+C caught, Aborting....")
    except Exception as e:
        print(f"Expection : {e.__class__.__name__} : {str(e)}")
    finally:
        if os.name == "nt":
            sniff.promicious_mode(DISABLE)

if __name__ == "__main__":
    main()
