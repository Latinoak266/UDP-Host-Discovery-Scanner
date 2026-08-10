import ipaddress
import os
import socket
import struct
import sys
import threading
import time
from ctypes import *

# Subnet to target
SUBNET = "<subnet>"

# Magic string we'll check ICMP responses for
MESSAGE = "PYTHONRULES!"



class IP(Structure):
    protocol_str = {6:"TCP",1:"ICMP",17:"UDP"}
    _fields_ = [("ver", c_ubyte, 4),
                ("ihl", c_ubyte, 4),
                ("tos", c_ubyte, 8),
                ("tol", c_ushort, 16),
                ("id", c_ushort, 16),
                ("frag", c_ushort, 16),
                ("ttl", c_ubyte, 8),
                ("protocol", c_ubyte, 8),
                ("sum", c_ushort, 16),
                ("src", c_uint32, 32),
                ("dst", c_uint32, 32)

]
    def __new__(cls,socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self,socket_buffer=None):
        self.src_addr = socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_addr = socket.inet_ntoa(struct.pack("<L",self.dst))
        self.proto = self.protocol_str[self.protocol]

class ICMP:
    def __init__(self, buffer):
        header = struct.unpack("<BBHHH",buffer)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

# This sprays out UDP datagrams with our magic message
def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, "utf8"), (str(ip), 65212))


class Scanner:
    def __init__(self, host):
        self.host = host

        if os.name == "nt":
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        self.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket_protocol
        )

        self.socket.bind((host, 0))
        self.socket.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_HDRINCL,
            1
        )

        if os.name == "nt":
            self.socket.ioctl(
                socket.SIO_RCVALL,
                socket.RCVALL_ON
            )

    def sniff(self):
        hosts_up = set([f"{self.host} *"])

        try:
            while True:
                # Read a packet
                raw_buffer = self.socket.recvfrom(65535)[0]

                # Create an IP header from the first 20 bytes
                ip_header = IP(raw_buffer[0:20])

                # If it's ICMP, we want it
                if ip_header.protocol == "ICMP":
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]
                    icmp_header = ICMP(buf)

                    # Check for Type 3 and Code 3
                    if icmp_header.code == 3 and icmp_header.type == 3:

                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):

                            # Make sure it has our magic message
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, "utf8"):

                                tgt = str(ip_header.src_address)

                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(str(ip_header.src_address))
                                    print(f"Host Up: {tgt}")

        # Handle Ctrl+C
        except KeyboardInterrupt:
            if os.name == "nt":
                self.socket.ioctl(
                    socket.SIO_RCVALL,
                    socket.RCVALL_OFF
                )

            print("\nUser interrupted.")

            if hosts_up:
                print(f"\n\nSummary: Hosts up on {SUBNET}")

                for host in sorted(hosts_up):
                    print(host)
                    print("")

            sys.exit()


if __name__ == "__main__":
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = "<host ip>"

    s = Scanner(host)

    time.sleep(5)

    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff()