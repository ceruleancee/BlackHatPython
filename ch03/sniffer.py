import socket
import os

# host to listen on
host = "192.168.1.1"

# create a raw socket and bind it to the public interface
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host,0))

# want IP headers included in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if on Windows, send IOCTL for promiscuous mode
if os.name =="nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# read in single packet
print(sniffer.recvfrom(65565))

# if on windows, turn off promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)