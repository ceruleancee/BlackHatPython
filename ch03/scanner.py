import socket
import os
import struct
from ctypes import *
import threading
import time
from netaddr import IPNetwork, IPAddress

# host to listen on
host = "192.168.0.187"

# subnet to target
subnet = '192.168.0.0/24'

# magic string we'll check ICMP responses for
magic_message = "PythonIsTediousAndMehSoFar"


# this sprays out the udp datagrams
def udp_sender(subnet, magic_message):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(subnet):
        try:
            sender.sendto(magic_message, ("%s" % ip, 65212))
        except:
            pass


# start sending packets
t = threading.Thread(target=udp_sender, args=(subnet, magic_message))
t.start()


# our IP header
class IP(Structure):
    _fields_ = [
        ("ih1", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte,),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_ulong),
        ("dst", c_ulong),
    ]

    def _new_(self, socket_buffer=None):
        return self.from_buffer(socket_buffer)

    def _init_(self, socket_buffer=None):
        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
    while True:
        # read in a packet
        raw_buffer = sniffer.recvfrom(65565)[0]

        # create an IP header from first 20 bytes of buffer
        # breaks here with a "TypeError: an integer is required (got type bytes)"
        ip_header = IP(raw_buffer[0:20])

        # print out the protocol that was detected and the hosts
        print("Protocol: %s %s -> %s % (ip_header.protocol,ip_header.src_address, ip_header.dst_address)")
# handle CTRL-C
except KeyboardInterrupt:
    # if we're using windows, turn off promiscuous mode

    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
    ]

    def _new_(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def _init_(self, socket_buffer):
        pass

    print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
    # if its icmp we want it!
    if ip_header.protocol == "ICMP":
        # calculate where icmp packet starts
        offset = ip_header.ihl * 4
        buf = raw_buffer[offset:offset + sizeof(ICMP)]

        # create our ICMP structure
        icmp_header = ICMP(buf)

        print("ICMP -> Type: %d Code: %d " % (icmp_header.type, icmp_header.code))

        # now check for the TYPE 3 and CODE
        if icmp_header.code == 3 and icmp_header.type == 3:

            # make sure host is in out target subnet
            if IPAddress(ip_header.src_address) in IPNetwork(subnet):

                # make sure it has out message
                if raw_buffer[len(raw_buffer) - len(magic_message):] == magic_message:
                    print("Host Up: %s" % ip_header.src_address)

                    # error occurs: "OSError: [Errno 49] Can't assign requested address"
