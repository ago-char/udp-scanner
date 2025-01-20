#!/bin/python3

# this is script to capture one single packet at a time (ICMP on linux, ICMP/TCP/UDP on nt) will run in loop 

import socket
import os
import argparse
import requests

ENABLE = True
DISABLE = False

# create a Sniffer class as child of socket.socket 
class Sniffer(socket.socket):
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
            self.sniffer(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            self.sniffer(socket.SIO_RCVALL, socket.RCVALL_OFF)

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


def argument_parser() -> argparse.Namespace:
    """
    add the necessary arguments to the parser and return the parsed arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-lh', '--listen-host', help="IP or hostname of listening host", type=str, required=True)
    args = parser.parse_args()
    return args


def privilege_check():
    if os.getuid() != 0:
        return "normal"
    return "admin"


def main():
    if privilege_check() == "normal":
        print("Run as Root.")
        exit()

    args = argument_parser()
    host = args.listen_host
    # get you sniffer object which is nothing but sub class of socket.socket 
    sniff = Sniffer(host)
    
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
