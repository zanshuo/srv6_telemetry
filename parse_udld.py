#!/usr/bin/python3

import bitstring
from collections import OrderedDict
from scapy.all import *
import json
from ipaddr import IPNetwork
path_dict={"11.11.11.1":dict(),"22.22.22.22":dict(),"33.33.33.33":dict(),"44.44.44.44":dict(),"55.55.55.55":dict(),"66.66.66.66":dict()}

def parse_packet(pkt_raw):
    # print(type(pkt_raw[0].type))
    pkt=pkt_raw[3].load
    Opcode=int(bitstring.BitArray(pkt)[3:8].bin,2)
    flag=int(bitstring.BitArray(pkt)[8:16].bin,2)
    if Opcode == 2:
        device_id_raw = pkt[8:12]
        peer_id_raw = pkt[16:20]
        port_id_raw = pkt[20:24]
        sequence_number_raw=pkt[28:32]
        d1 = bitstring.BitArray(device_id_raw)[:8].unpack("uintbe:8")[0]
        d2 = bitstring.BitArray(device_id_raw)[8:16].unpack("uintbe:8")[0]
        d3 = bitstring.BitArray(device_id_raw)[16:24].unpack("uintbe:8")[0]
        d4 = bitstring.BitArray(device_id_raw)[24:32].unpack("uintbe:8")[0]
        device_id = str(d1)+"."+str(d2)+"."+str(d3)+"."+str(d4)
        p1 = bitstring.BitArray(peer_id_raw)[:8].unpack("uintbe:8")[0]
        p2 = bitstring.BitArray(peer_id_raw)[8:16].unpack("uintbe:8")[0]
        p3 = bitstring.BitArray(peer_id_raw)[16:24].unpack("uintbe:8")[0]
        p4 = bitstring.BitArray(peer_id_raw)[24:32].unpack("uintbe:8")[0]
        peer_id = str(p1)+"."+str(p2)+"."+str(p3)+"."+str(p4)
        port_id = bitstring.BitArray(port_id_raw).unpack("uintbe:32")[0]
        sequence_number = bitstring.BitArray(sequence_number_raw).unpack("uintbe:32")[0]
        print(device_id,peer_id,port_id,sequence_number,sep="     ")




con_eth0 = sniff(prn=parse_packet,filter="outbound",store=0,iface="con-eth0",timeout=5)
# wrpcap('packet.cap', con_eth0)