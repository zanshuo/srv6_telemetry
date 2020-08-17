#!/usr/bin/python3

import bitstring
from collections import OrderedDict
from scapy.all import *
import json

config_list=list()
path_dict = dict()
rel=dict()
with open("./build/config.json",mode="r") as f1:
    config_list=json.load(f1)
    f1.close()
for x in config_list:
    if "ipv4_address" in x.keys():
        rel[x["ipv4_address"]] = x["name"]


def parse_packet(pkt_raw):
    # print(type(pkt_raw[0].type))
    try:
        pkt=pkt_raw[3].load
    except:
        return
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
        # print(device_id,peer_id,port_id,sequence_number,sep="     ")
        if device_id in rel.keys():
            if rel[device_id] not in path_dict.keys():
                path_dict[rel[device_id]] = {port_id:[rel[peer_id], sequence_number]}
            else:
                if port_id not in path_dict[rel[device_id]].keys():
                    path_dict[rel[device_id]][port_id] =[rel[peer_id],sequence_number]
                elif rel[peer_id] != path_dict[rel[device_id]][port_id][0] and sequence_number >= path_dict[rel[device_id]][port_id][1] :
                    path_dict[rel[device_id]][port_id][0]=peer_id
                    path_dict[rel[device_id]][port_id][1]=sequence_number
                elif rel[peer_id] == path_dict[rel[device_id]][port_id][0] and sequence_number > path_dict[rel[device_id]][port_id][1]:
                    path_dict[rel[device_id]][port_id][1]=sequence_number

        else:
            print("error")
        print(path_dict)
        print("\n")



con_eth0 = sniff(prn=parse_packet,filter="outbound",store=0,iface="con-eth0")
# wrpcap('packet.cap', con_eth0)