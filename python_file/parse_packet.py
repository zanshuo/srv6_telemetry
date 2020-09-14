#!/usr/bin/python3
import bitstring
from collections import OrderedDict
from scapy.all import *
import json
import shelve
import os
class Parse:
    config_list = list()
    path_dict = dict()
    rel = dict()
    def __init__(self, filter="outbound", iface="con-eth0",path_dir="../build/"):
        """
            filter : the condition  of filtering
            iface: captured interface
            path: configure file of device

        """
        self.filter = filter
        self.iface = iface
        self.path_dir=path_dir
        Parse.share_data(self.path_dir)

    @classmethod
    def share_data(cls,path):
        with open(path+"config.json", mode="r") as f:
            cls.config_list = json.load(f)
            f.close()
        for tmp in cls.config_list:
            if "ipv4_address" in tmp.keys():
                cls.rel[tmp["ipv4_address"]] = tmp["name"]

   
    
    def parse_oam(self,pkt_raw):
        data_dict = OrderedDict()
        if pkt_raw[1].nh == 59:
            src = pkt_raw[1].src
            dst = pkt_raw[1].dst
            flow_id = pkt_raw[1].fl
            # Parse.probe_ipv6_flow_id = flow_id
            if os.path.isdir(self.path_dir):
                f=shelve.open(self.path_dir+"/ack",writeback=True)
                if src == "2555:55" and dst == "25555:55":
                    f["sequence"] = flow_id
                # json.dump({"src":src,"dst":dst,"flow_id":flow_id},f)
                f.close
            else:
                print("error")
                return

        elif pkt_raw[1].nh == 17:
            print("shoudao oam packet")
            try:
                src_Ipv6_addr = pkt_raw[1].src
                pkt = pkt_raw[3].load
            except:
                print("error")
                return
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
            if os.path.isdir(self.path_dir):
                with open(self.path_dir+"/data_list.json",encoding="utf-8",mode="a") as f1:
                    f1.write(json.dumps(dex_dict)+"\n")
                f1.close()
            else:
                print("error")
                return
            
            
    def parse_udld(self,pkt_raw):
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
            if device_id in Parse.rel.keys():
                if Parse.rel[device_id] not in Parse.path_dict.keys():
                    Parse.path_dict[Parse.rel[device_id]] = {port_id:[Parse.rel[peer_id], sequence_number]}
                else:
                    if port_id not in Parse.path_dict[Parse.rel[device_id]].keys():
                        Parse.path_dict[Parse.rel[device_id]][port_id] =[peer_id,sequence_number]
                    elif peer_id != Parse.path_dict[Parse.rel[device_id]][port_id][0] and sequence_number >= Parse.path_dict[Parse.rel[device_id]][port_id][1] :
                        Parse.path_dict[Parse.rel[device_id]][port_id][0]=peer_id
                        Parse.path_dict[Parse.rel[device_id]][port_id][1]=sequence_number
                    elif peer_id == Parse.path_dict[Parse.rel[device_id]][port_id][0] and sequence_number > Parse.path_dict[Parse.rel[device_id]][port_id][1]:
                        Parse.path_dict[Parse.rel[device_id]][port_id][1]=sequence_number
           
            else:
                print("error")
            
    def parse_packet(self,pkt_raw):
        try:
            #34525==0x86dd IPV6
            if pkt_raw[0].type == 34525:
                self.parse_oam(pkt_raw)
            #34929==0x8870 udld
            elif pkt_raw[0].type == 34928:
                self.parse_udld(pkt_raw)
        except:
            return

    def start(self):
        con_eth0 = sniff(prn=self.parse_packet, filter=self.filter, store=0, iface=self.iface)

if __name__ == "__main__":
    obj=Parse()
    obj.start()
    