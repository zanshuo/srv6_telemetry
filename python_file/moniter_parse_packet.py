#!/usr/bin/python3
import bitstring
from collections import OrderedDict
from scapy.all import *
import json

def parse_packet(pkt_raw):
    data_dict = OrderedDict()
    print(type(pkt_raw[0].type))
    src_Ipv6_addr = pkt_raw[1].src
    pkt = pkt_raw[3].load
    start_byte_number = 16
    # 网络数据包用大端
    namespace_id = bitstring.BitArray(pkt)[:16].unpack("uintbe:16")[0]
    flags = bitstring.BitArray(pkt)[16:32].unpack("uintbe:16")[0]
    tracetype_raw = bitstring.BitArray(pkt)[32:56]
    reserved = bitstring.BitArray(pkt)[56:64].unpack("uintbe:8")[0]
    flowid = bitstring.BitArray(pkt)[64:96].unpack("uintbe:32")[0]
    sequencenumber = bitstring.BitArray(pkt)[96:128].unpack("uintbe:32")[0]
    dex_dict = OrderedDict(src=src_Ipv6_addr,flowid=flowid, sequencenumber=sequencenumber,namespace_id=namespace_id,tracetype=tracetype_raw.bin, flags=flags, reserved=reserved)
    list_tracetype = "".join(tracetype_raw.bin)
        # 23-实际序号=list序号
    if (list_tracetype[1] == "1"):
        # print("export_port")
        ingress_port = bitstring.BitArray(pkt[start_byte_number:start_byte_number+2]).unpack("uintbe:16")[0]
        egress_port = bitstring.BitArray(pkt[start_byte_number+2:start_byte_number+4]).unpack("uintbe:16")[0]
        data_dict["export_port"] = ingress_port,egress_port
        start_byte_number=start_byte_number+4
    if (list_tracetype[2] == "1"):
        # print("export_timestamp")
        data_dict["export_timestap"] =bitstring.BitArray(pkt[start_byte_number:start_byte_number+8]).unpack("uintbe:64")[0]
        start_byte_number = start_byte_number+8
    if (list_tracetype[4] == "1"):
        # print("export_transit_delay")
        data_dict["export_transit_delay"] = bitstring.BitArray(pkt[start_byte_number:start_byte_number+8]).unpack("uintbe:64")[0]
        start_byte_number = start_byte_number+8
    if (list_tracetype[6]== "1"):
        # print("export_dequene_length")
        data_dict["export_dequene_length"] = bitstring.BitArray(pkt[start_byte_number:start_byte_number+4]).unpack("uintbe:32")[0]
        start_byte_number = start_byte_number+4
    if (list_tracetype[12] == "1"):
        # print("export_enquene_length")
        data_dict["export_enquene_length"] = bitstring.BitArray(pkt[start_byte_number:start_byte_number+4]).unpack("uintbe:32")[0]
        start_byte_number = start_byte_number+4
    if(list_tracetype[23] == "1"):
        data_dict["export_packet_length"] = bitstring.BitArray(pkt[start_byte_number:start_byte_number+4]).unpack("uintbe:32")[0]
        start_byte_number =start_byte_number+4
    dex_dict["data"] = data_dict

    with open("../build/data_list.json",encoding="utf-8",mode="a") as f1:
        f1.write(json.dumps(dex_dict,indent=1)+"\n")
        # f2.write(json.dumps(dex_dict)+"\n")
    f1.close()
    # f2.close()
    # print(type(dex_dict["namespace_id"]))


con_eth0 = sniff(prn=parse_packet,filter="udp port 55551 ",store=0,iface="con-eth0")
# wrpcap("pak.cap",con_eth0)









