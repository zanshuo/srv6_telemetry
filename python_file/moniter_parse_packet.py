
import bitstring
from collections import OrderedDict
from scapy.all import *
import json






def parse_packet(pkt_raw):
    data_dict = OrderedDict()
    raw_data_list = list()
    pkt = pkt_raw[3].load
    start_bit_number = 16
    # 网络数据包用大端
    namespace_id = bitstring.BitArray(pkt)[:16].unpack("uintbe:16")[0]
    flags = bitstring.BitArray(pkt)[16:32].unpack("uintbe:16")[0]
    tracetype_raw = bitstring.BitArray(pkt)[32:56]
    reserved = bitstring.BitArray(pkt)[56:64].unpack("uintbe:8")[0]
    flowid = bitstring.BitArray(pkt)[64:96].unpack("uintbe:32")[0]
    sequencenumber = bitstring.BitArray(pkt)[96:128].unpack("uintbe:32")[0]
    dex_dict = dict(namespace_id=namespace_id, flags=flags, reserved=reserved,flowid=flowid, sequencenumber=sequencenumber)
    list2 = "".join(tracetype_raw.bin)
    for serial, flag in enumerate(list2):
        # 23-实际序号=list序号
        if (serial == 1 and flag == "1"):
            # print("export_port")
            data_dict["export_port"] = ""
        if (serial == 2 and flag == "1"):
            # print("export_timestamp")
            data_dict["export_timestap"] = ""
        if (serial == 4 and flag == "1"):
            # print("export_transit_delay")
            data_dict["export_transit_delay"] = ""
        if (serial == 6 and flag == "1"):
            # print("export_dequene_length")
            data_dict["export_dequene_length"] = ""
        if (serial == 12 and flag == "1"):
            # print("export_enquene_length")
            data_dict["export_enquene_length"] = ""

    for temp in range(int((len(pkt) - 16) / 4)):
        raw_data_list.append(pkt[start_bit_number:start_bit_number + 4])
        start_bit_number = start_bit_number + 4
    for temp1, temp2 in zip(data_dict.keys(), raw_data_list):
        if (len(data_dict.keys()) == len(raw_data_list)):
            data_dict[temp1] = temp2
    if "export_timestap" in data_dict.keys():
        data_dict["export_timestap"] = bitstring.BitArray(data_dict["export_timestap"]).unpack("uintbe:32")[0]
    if "export_transit_delay" in data_dict.keys():
        data_dict["export_transit_delay"] = bitstring.BitArray(data_dict["export_transit_delay"]).unpack("uintbe:32")[0]
    if "export_dequene_length" in data_dict.keys():
        data_dict["export_dequene_length"] = bitstring.BitArray(data_dict["export_dequene_length"]).unpack("uintbe:32")[
            0]
    if "export_enquene_length" in data_dict.keys():
        data_dict["export_enquene_length"] = bitstring.BitArray(data_dict["export_enquene_length"]).unpack("uintbe:32")[
            0]
    if "export_port" in data_dict.keys():
        ingress_port = bitstring.BitArray(data_dict["export_port"])[:16]
        egress_port = bitstring.BitArray(data_dict["export_port"])[16:]
        data_dict["export_port"] = [ingress_port.unpack("uintbe:16")[0], egress_port.unpack("uintbe:16")[0]]

    with open("data_list.json",encoding="utf-8",mode="a") as f1,open("dex.json",encoding="utf-8",mode="a") as f2:
        f1.write(json.dumps(data_dict)+"\n")
        f2.write(json.dumps(dex_dict)+"\n")
    f1.close()
    f2.close()
    # print(type(dex_dict["namespace_id"]))


con_eth0 = sniff(prn=parse_packet,filter="udp",store=0,iface=["con-eth0","con-eth1","con-eth2"],timeout=1)
# con_eth1 = sniff(prn=parse_packet,filter="udp",store=0,iface="con-eth1",timeout=1)
# con_eth2 = sniff(prn=parse_packet,filter="udp",store=0,iface="con-eth2",timeout=1)








