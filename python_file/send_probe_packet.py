#!/usr/bin/python3
import subprocess
from scapy.all import *


# def send_detect(dstAddr,entry_num,address_list):
#     a=Ether()/IPv6(plen=8+entry_num*16,src="2004::255",dst=dstAddr)/IPv6ExtHdrSegmentRouting\
#             (len=entry_num*2,segleft=entry_num-2,lastentry=entry_num-1,oam=1,addresses=["2003::3","2002::2","2001::1","0001:0000:6a08:0000:0000:0001:0000:0001"])
#     sendp(a,iface="con-eth0")


def send_probe(address_list):
    pkt = Ether()/ IPv6(plen=48+16*len(address_list), src="2555::255", dst="2001::1") / \
        IPv6ExtHdrSegmentRouting(nh=41,len=len(address_list)*2, segleft=len(address_list)-2, lastentry=len(address_list)-1, oam=1,
         addresses=address_list)/\
        IPv6(plen=0,  fl=1,src="2555::255", dst="2555::255")
    sendp(pkt, iface="con-eth0",verbose=False)




send_probe(["2006::6","2005::5", "2002::2", "2001::1", "0001:0000:6a08:0000:0000:0001:0000:0001"])
# con_eth0 = sniff(prn=parse_packet,filter="udp",store=0,iface=["con-eth0"])
