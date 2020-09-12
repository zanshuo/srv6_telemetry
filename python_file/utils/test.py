#!/usr/bin/python2

import socket
ip_port=('127.0.0.1',9001)
udp_sk=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
udp_sk.sendto(b'self.net.linksBetween(self.net.get("r1"),self.net.get("r2"))',ip_port)
back_msg,addr=udp_sk.recvfrom(1024)
print(back_msg)