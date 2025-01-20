#!/bin/python3

# this script will capture packet and decode at ip/icmp level, all ip header, please check pics/ipv4-header.png, pics/icmp.png

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



ENABLE = True
DISABLE = False
ACTIVE_HOSTS = []
BUFFERED_PACKETS = []    
UDP_MESSAGE = "AREYOUTHERE?"



def argument_parser() -> argparse.Namespace:
    """
    add the necessary arguments to the parser and return the parsed arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-lh', '--listen-host', help="IP or hostname of listening host", type=str, required=True)
    parser.add_argument('-tsn', '--target-subnet', help="Target Subnet for UDP Scan", type=str, required=True)
    parser.add_argument('-p', '--port', type=int, help="Dest Port for UDP probe")
    parser.add_argument('-v', '--verbose', help="Increase Output Verbosity, Show Address Info,  Also view other packets than of icmp dest+port unreachable, This will not view raw packet, us -raw for that",action="store_true")
    parser.add_argument('-raw', '--view-raw-buffer', help="View Raw Buffer along with Decoded packet", action="store_true")
    parser.add_argument('--view-ip-header', help="View IP Header", action="store_true")
    parser.add_argument('--view-icmp-header', help="View ICMP Header", action="store_true")
    args = parser.parse_args()
    return args


def draw_terminal_width(pattern: str):
    """
    Draw given pattern from left of the console to its right
    """
    # Get the terminal size
    terminal_width = shutil.get_terminal_size().columns
    # Print asterisks across the console
    print(pattern * terminal_width)


def is_admin():
    """
    check if this program is being executed as root/admin or not
    """
    if os.name == "nt":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    if os.getuid() != 0:
        return False
    return True


def list_hosts(hosts: list):
    """
    list hosts individually from the list of given hosts
    """
    print()
    if hosts:
        print(f"Active Hosts (Total {len(hosts)}) :")
        for host in hosts:
            print(host)
    else:
        print("No Active Hosts Found..")


def signal_sender(udp_thread: threading.Thread):
    """
    send SIGINT(2) to main thread if udp_thread is dead
    """
    while True:
        if not udp_thread.is_alive():
            pid = os.getpid()
            os.kill(pid, 2)
            break


class IP:
    """
    ip class for extraction of ipv4 header
    """
    def __init__(self, raw_buffer_with_ip_header):
        self.raw_header = raw_buffer_with_ip_header[0:20]
        header = struct.unpack('<BBHHHBBH4s4s', self.raw_header) # 20 bytes (1+1+2+2+2+1+1+2+4+4) unpack in Little Endian format

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


    def get_raw_header(self):
        return self.raw_header

    def get_header_len(self):
        """
        return header len in bytes
        """
        return self.ihl * 4 # ihl stores value in 4-byte block, so if it has value of 5 it means 5*4=20B

    def get_src_ip(self):
        return self.src_address
    
    def get_dest_ip(self):
        return self.dst_address
    
    def get_proto_name(self):
        return self.protocol_map[self.protocol_num]


class ICMP:
    """
    icmp class for extraction of icmp headers
    """
    def __init__(self, raw_buffer_starting_icmp_header):
        self.raw_header = raw_buffer_starting_icmp_header

        icmp_header = struct.unpack('<BBHHH', self.raw_header) # 8 byte (1+1+2+2+2)unpack in Little Endian format

        self.type = icmp_header[0]  # icmp type
        self.code = icmp_header[1]  # icmp type's code
        self.sum = icmp_header[2]   # checksum
        self.id = icmp_header[3]    # identifier
        self.seq = icmp_header[4]   # sequence num

    
    def get_raw_header(self):
        return self.raw_header

    def get_type(self):
        return self.type

    def get_code(self):
        return self.code



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
        """
        ENABLE or DISABLE promicious mode on nt systems
        
        flag should be either ENABLE or DISABLE
        """
        if mode == ENABLE:
            self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    @classmethod
    def get_domain_name(cls, ip_addr):
        """
        get domain name using `http://ip-api.com/json/{ip_addr}"` api
        """
        try:
            url = f"http://ip-api.com/json/{ip_addr}"
            response = requests.get(url)
            data = response.json()
            return data.get("org", "")
        except Exception as e:
            print(f"Expection on Sniffer : {e.__class__.__name__} as {str(e)}")
            return ""

    def start_sniffing(self, bufsize: int=65535):
        """
        return single stream of bytes
        """ 
        return self.sniffer.recvfrom(bufsize)
 


def send_udp_thread(subnet: str, port:int=63323, start_wait:float=1.0, end_wait:float=2.0):
    """
    specify subnet to send udp ports
    optionally specify which port to send the probe

    start_wait -> sleep timer before sending proble

    end_wait -> sleep timer after sending proble
    """
    if not port:
        port = 63323
    time.sleep(start_wait) # just waiting for our receiver be ready
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
        # for host in ipaddress.ip_network(subnet).hosts():
        for host in reversed(list(ipaddress.ip_network(subnet).hosts())):
            udp_sock.sendto(UDP_MESSAGE.encode(), (str(host), port))
        time.sleep(end_wait) # giving enough time to receiver/sniffer so that it could capture all the packets
    

def packet_traker(args):
    """
    from raw capture, handle packet according to args

    this will store active hosts under ACTIVE_HOSTS
    """
    while True:
        if len(BUFFERED_PACKETS):
            packet = BUFFERED_PACKETS.pop()

            raw_buffer, addr = packet
            ip_obj = IP(raw_buffer)

            src_ip = ip_obj.get_src_ip()
            dest_ip = ip_obj.get_dest_ip()
            # udp packets to not active hosts are processed through own ip and at localhost
            if src_ip == dest_ip:
                continue
            protocol = ip_obj.get_proto_name()
            domain_name = Sniffer.get_domain_name(addr[0])
            sock_name_info = socket.getnameinfo(addr, 0)


            if args.verbose:
                print(f"Received Address : {addr}, {domain_name}, {sock_name_info}")
                print(f"{protocol} : {src_ip} -> {dest_ip}")


            if args.view_raw_buffer:
                print(f"Raw bytes : \n{raw_buffer}")

            
            if args.view_ip_header:
                print(f"Raw IP header : \n{ip_obj.get_raw_header()}")


        
            upHost = ""
            if protocol == "ICMP" and bytes(UDP_MESSAGE, 'utf-8') in raw_buffer:
                ip_hl = ip_obj.get_header_len()
                icmp_obj = ICMP(raw_buffer[ip_hl:ip_hl+8]) #only 8 byte sent because ICMP module is designed to extract only 8B of info
                icmp_type = icmp_obj.get_type()
                icmp_code = icmp_obj.get_code()
                if args.view_icmp_header:
                    print(f"Raw ICMP header: \n{icmp_obj.get_raw_header()}")
                if args.verbose:
                    print(f"ICMP : Type = {icmp_type}, Code = {icmp_code}")
                if icmp_type == 3 and icmp_code == 3:
                    print(f"{src_ip} is UP. It replies as : Dest + Port Unreachable")
                    upHost = src_ip
                    ACTIVE_HOSTS.append(upHost)


            if args.verbose or args.view_raw_buffer or upHost:
                draw_terminal_width("*")



# driver code 
def main():
    """
    main code for udp scan
    """
    # get args 
    args = argument_parser()

    # if prev is not root abort 
    if not is_admin():
        print("Run as Root.")
        exit()

    host = args.listen_host
    subnet = args.target_subnet
    port = args.port

    # get you sniffer object which is nothing but sub class of socket.socket 
    sniff = Sniffer(host)
    print(f"Sniffing for IP packets at {host}......")
    draw_terminal_width("#")
    
    try:
        # start udp thread 
        udp_thread = threading.Thread(target=send_udp_thread, args=(subnet, port))
        udp_thread.daemon = True # terminate thread auto if main thread is complete
        udp_thread.start()

        # start packet traker thread 
        packet_thread = threading.Thread(target=packet_traker, args=(args, ))
        packet_thread.daemon = True
        packet_thread.start()

        # signal sender
        sig_thread = threading.Thread(target=signal_sender, args=(udp_thread, ))
        sig_thread.daemon = True
        sig_thread.start()

        while True:
            packet = sniff.start_sniffing()
            BUFFERED_PACKETS.append(packet)   # this BUFFERED_PACKETS is used by packet_traker to handle received packets      

    except KeyboardInterrupt:
        print("Ctrl+C caught, Aborting....")
    except Exception as e:
        print(f"Expection : {e.__class__.__name__} : {str(e)}")
    finally:
        # disable the previously enabled promicious mode if you are in nt systems 
        if os.name == "nt":
            sniff.promicious_mode(DISABLE)
        
        # list active hosts in the subnet 
        list_hosts(ACTIVE_HOSTS)
        draw_terminal_width("#")


if __name__ == "__main__":
    main()
