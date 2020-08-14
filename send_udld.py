#!/usr/bin/python3
from scapy.all import *
import bitstring
sequence=3
s = bitstring.pack('uintbe:32', sequence)
str1=""
for x in [0,8,16,24]:
    temp=s[x:x+8]
    str1=str1+chr(int(temp.hex,16))
flag=2
s1 = bitstring.pack('uintbe:8', flag)
str2=chr(int(s1.hex,16))
pkt = Ether()/LLC()/SNAP(OUI=0x00000C,code=0x0111)/Raw(load=" {1}\0\0\0\a\0\b{0}".format(str1,str2))
sendp(pkt, iface="con-eth0")