#!/usr/bin/python3
import subprocess
from scapy.all import *


# def send_detect(dstAddr,entry_num,address_list):
#     a=Ether()/IPv6(plen=8+entry_num*16,src="2004::255",dst=dstAddr)/IPv6ExtHdrSegmentRouting\
#             (len=entry_num*2,segleft=entry_num-2,lastentry=entry_num-1,oam=1,addresses=["2003::3","2002::2","2001::1","0001:0000:6a08:0000:0000:0001:0000:0001"])
#     sendp(a,iface="con-eth0")


pkt = Ether()/ IPv6(plen=128, src="2555::255", dst="2001::1") / \
    IPv6ExtHdrSegmentRouting(nh=41,len=10, segleft=3, lastentry=4, oam=1,
     addresses=["2006::6","2005::5", "2002::2", "2001::1", "0001:0000:6a08:0000:0000:0001:0000:0001"])/\
    IPv6(plen=0,  fl=1,src="2555::255", dst="2555::255")

sendp(pkt, iface="con-eth0")





# con_eth0 = sniff(prn=parse_packet,filter="udp",store=0,iface=["con-eth0"])
