#!/usr/bin/python

import copy
import sqlite3
import bitstring
from scapy.all import *
import json
from time import sleep
from concurrent.futures import ThreadPoolExecutor
from goto import with_goto
from collections import OrderedDict
from multiprocessing import Process
import os
import shelve
import Queue

class Oam:
    config_list = list()
    name_to_sid = dict()
    ipv6_address_to_sid=dict()
    namesapce_id_list=list()
    sequence = 1
    ipv6_flow_id = 1
    ack_list=list()
    sid_to_name = dict()
    try:
        conn=sqlite3.connect("../db/telemetry.db")
        cursor = conn.cursor()
        cursor.execute("create table data_list(src varchar(40),tracetype varchar(40),namespace_id smallint,reserved tinyint,sequencenumber int,flowid int,flags smallint,\
                            export_ingress_port smallint,export_egress_port smallint,export_timestap bigint,export_transit_delay bigint,export_dequene_length int,export_enquene_length int,export_packet_length int)")
        cursor.execute("create table metric_list(src varchar(40),dst varchar(40),total_delay bigint)")
        cursor.close()
        conn.commit()
        conn.close()
    except:
        pass
    def __init__(self,queue=None,filter="outbound", iface="con-eth0",path_dir="../build/"):

        self.filter = filter
        self.iface=iface
        self.path_dir = path_dir
        Oam.share_data(self.path_dir)
        Oam.share_namespace_id_list(self.path_dir)
        self.queue=queue
  
    @classmethod
    def share_data(cls,path):
        while True:
            if os.path.isfile(path+"config.json"):
                with open(path+"config.json", mode="r") as f:
                    cls.config_list = json.load(f)
                    f.close()
                for tmp in cls.config_list:
                    if "sid" in tmp.keys() and "name" in tmp.keys():
                        cls.name_to_sid[tmp["name"]] = tmp["sid"]
                        cls.sid_to_name[tmp["sid"]] = tmp["name"] 
                
                    if "ipv6_address" in tmp.keys() and "sid" in tmp.keys():
                        cls.ipv6_address_to_sid[tmp["ipv6_address"]] = tmp["sid"]
                break
            else:
                continue
                    
    @classmethod
    def share_namespace_id_list(cls,path):
        cls.namesapce_id_list=list() 
        while True: 
            if os.path.isfile(path+"peer.json"):
                with open(path+"peer.json") as f1:
                    path_dict = json.load(f1)
                    f1.close
                for x , y in path_dict.items():
                    for tmp in y.values():
                        cls.namesapce_id_list.append([cls.name_to_sid[tmp[0]],cls.name_to_sid[x]])
                list_tmp=copy.deepcopy(cls.namesapce_id_list)
                with open (path+"namespace.json",mode="w") as f2:
                    for tmp in list_tmp:
                        tmp[0]=cls.sid_to_name[tmp[0]]
                        tmp[1]=cls.sid_to_name[tmp[1]]
                        tmp.reverse()
                    
                    json.dump(list_tmp,f2)
                    # print(cls.namesapce_id_list)
                    f2.close
                break
            else:
                continue
    def generate_address_list(self,namespace_id,sequence,*address_list):
        address_list_tmp=list(address_list)
        namespace_id = bitstring.pack('uintbe:16',namespace_id).hex
        sequence = bitstring.pack('uintbe:32',sequence).hex
        dex = "%s:0000:6a08:0000:0000:0000:%s:%s"%(namespace_id,sequence[:4],sequence[4:])
        address_list_tmp.append(dex)
        return address_list_tmp

    @staticmethod
    def send_oam_probe_packet(address_list,ipv6_flow_id,dst_addr):
        """
            address_list:segment list
            flow:ipv6 flow_id
        """
        assert (isinstance(address_list,list)),"address_list error"
        assert (isinstance(ipv6_flow_id,int )),"ipv6_flow_id error"
        pkt = Ether()/ IPv6(plen=48+16*len(address_list), src="2555::255", dst=dst_addr) / \
            IPv6ExtHdrSegmentRouting(nh=41,len=len(address_list)*2, segleft=len(address_list)-2, lastentry=len(address_list)-1, oam=1,
             addresses=address_list)/\
            IPv6(plen=0,  fl=ipv6_flow_id,src="2555::255", dst="2555::255")
        # pkt.show()
        sendp(pkt, iface="con-eth0",verbose=False)
        return pkt

    def send_oam_request(self):
        for i in range(2):
            try:
                print(Oam.namesapce_id_list)
                for namesapce_id ,address_list in enumerate(Oam.namesapce_id_list):
                    # print(address_list)
                    address_list_tmp =self.generate_address_list(namesapce_id,Oam.sequence,*address_list)
                    
                    pkt=Oam.send_oam_probe_packet(address_list_tmp,Oam.ipv6_flow_id,address_list_tmp[-2])
                    print("success")
                    self.queue.put(dict(address_list=address_list_tmp,ipv6_flow_id=Oam.ipv6_flow_id,namespace_id=namesapce_id,sequence=Oam.sequence,pkt=pkt))
                    # print(Oam.ipv6_flow_id)
                    Oam.ipv6_flow_id+=1
            except Exception as e:
                print(e)
            # self.queue.put("stop")
            Oam.sequence+=1
            sleep(10)
        

    @with_goto                
    def parse_metric(self):
        count_ack=0
        count_num=0
        while True:
            sleep(0.2)
            data=self.queue.get()
            label.begin
            if data["ipv6_flow_id"] in Oam.ack_list:
                count_ack=0
                dict_metric=dict()
                conn=sqlite3.connect("../db/telemetry.db")
                cursor = conn.cursor()
                cursor.execute("select src,export_timestap,export_transit_delay from data_list where namespace_id=%d and sequencenumber=%d and flowid=0"%(data["namespace_id"],data["sequence"]))
                values=cursor.fetchall()
                for tmp in values:
                    dict_metric[tmp[0]]={"export_timestap":tmp[1],"export_transit_delay":tmp[2]}
                # f=open(self.path_dir+"data_list.json",mode="r")
                # try:
                #     for line in f:
                #         tmp = json.loads(line)
                
                #         # print(tmp)
                #         if tmp["namespace_id"] == data["namespace_id"] and tmp["sequencenumber"] == data["sequence"] and tmp["src"] in data["address_list"]:
                            
                #             dict_metric[tmp["src"]] = {"export_timestap":tmp["data"]["export_timestap"],"export_transit_delay":tmp["data"]["export_transit_delay"]}
                #             # print(dict_metric)
                # except Exception as e:
                #     # print(e)
                #     print(e)
        
                if len(dict_metric.keys()) == 2:
                    count_num=0
                    link_delay=dict_metric[data["address_list"][0]]["export_timestap"] - dict_metric[data["address_list"][1]]["export_timestap"] - dict_metric[data["address_list"][1]]["export_transit_delay"]
                    node_delay=dict_metric[data["address_list"][0]]["export_transit_delay"]
                    total_delay = link_delay+node_delay      
                    
                    data["address_list"].pop()
                    data["address_list"][0] = Oam.sid_to_name[data["address_list"][0]]
                    data["address_list"][1] = Oam.sid_to_name[data["address_list"][1]]
                    data["address_list"].reverse()
                    # conn=sqlite3.connect("../db/telemetry.db")
                    # cursor = conn.cursor()
                    cursor.execute("insert into metric_list values('%s','%s','%d')"%(data["address_list"][0],data["address_list"][1],total_delay))
                    # cursor.close
                    conn.commit()
                    # conn.close()
                    # f=open(self.path_dir+"metric.json",mode="a")
                    # f.write(json.dumps([data["address_list"],total_delay])+"\n")
                    # f.close
                    # print(data["address_list"],total_delay)
                else:
                    sleep(0.1)
                    if count_num<3:
                        count_num+=1
                        goto.begin
                        
                    elif count_num==3:
                        if data["address_list"][:-1] in Oam.namesapce_id_list:
                            sendp(data["pkt"], iface="con-eth0",verbose=False)
                            self.queue.put(data)
                            
                        else:
                            #or raise error
                            print("oam packet don't receieve")
                        count_num=0
                cursor.close()
                conn.close()
            else:
                sleep(0.1)
                if count_ack<3:
                    count_ack+=1
                    goto.begin
                    
                elif count_ack==3:
                    if data["address_list"][:-1] in Oam.namesapce_id_list:
                        sendp(data["pkt"], iface="con-eth0",verbose=False)
                        self.queue.put(data)
                        
                    else:
                        #or raise error
                        print("ack packet don't receieve")
                    count_ack=0

    def parse_interested_flow(self):
        pass
    def parse_oam(self,pkt_raw):
        
        data_dict = OrderedDict()
        
        # print("shou dao oam")
        # print (pkt_raw[1].nh)
        if pkt_raw[1].nh == 59:
            src = pkt_raw[1].src
            dst = pkt_raw[1].dst
            flow_id = pkt_raw[1].fl
            # print(src)
            # print(flow_id)
            # Parse.probe_ipv6_flow_id = flow_id
            if os.path.isdir(self.path_dir):
                f=open(self.path_dir+"/ack.json",mode="w")
                if src == "2555::255" and dst == "2555::255":
                    Oam.ack_list.append(flow_id)
                    json.dump(Oam.ack_list,f)   
                f.close
                # json.dump({"src":src,"dst":dst,"flow_id":flow_id},f)
            
            else:
                print("dir error")
                return

        elif pkt_raw[1].nh == 17:
            # print("shou dao oam insert")
            try:
                # pkt_raw.show()
                src_Ipv6_addr = pkt_raw[1].src
                if src_Ipv6_addr in Oam.ipv6_address_to_sid.keys():
                    src_Ipv6_addr = Oam.ipv6_address_to_sid[src_Ipv6_addr]
                # print(src_Ipv6_addr)
                pkt = pkt_raw[3].load
            except:
                print("error")
                return
            start_byte_number = 16
            # network packet user big duan
            namespace_id = bitstring.BitArray(bytes=pkt)[:16].unpack("uintbe:16")[0]
            flags = bitstring.BitArray(bytes=pkt)[16:32].unpack("uintbe:16")[0]
            tracetype_raw = bitstring.BitArray(bytes=pkt)[32:56]
            reserved = bitstring.BitArray(bytes=pkt)[56:64].unpack("uintbe:8")[0]
            flowid = bitstring.BitArray(bytes=pkt)[64:96].unpack("uintbe:32")[0]
            sequencenumber = bitstring.BitArray(bytes=pkt)[96:128].unpack("uintbe:32")[0]
            dex_dict = OrderedDict(src=src_Ipv6_addr,flowid=flowid, sequencenumber=sequencenumber,namespace_id=namespace_id,tracetype=tracetype_raw.bin, flags=flags, reserved=reserved)
            list_tracetype = "".join(tracetype_raw.bin)
                # 23- real_sequence=list_sequence

            if (list_tracetype[1] == "1"):
                print("export_port")
                ingress_port = bitstring.BitArray(bytes=pkt[start_byte_number:start_byte_number+2]).unpack("uintbe:16")[0]
                egress_port = bitstring.BitArray(bytes=pkt[start_byte_number+2:start_byte_number+4]).unpack("uintbe:16")[0]
                data_dict["export_port"] = ingress_port,egress_port
                start_byte_number=start_byte_number+4
            if (list_tracetype[2] == "1"):
                print("export_timestamp")
                data_dict["export_timestap"] =bitstring.BitArray(bytes=pkt[start_byte_number:start_byte_number+8]).unpack("uintbe:64")[0]
                start_byte_number = start_byte_number+8
            if (list_tracetype[4] == "1"):
                print("export_transit_delay")
                data_dict["export_transit_delay"] = bitstring.BitArray(bytes=pkt[start_byte_number:start_byte_number+8]).unpack("uintbe:64")[0]
                start_byte_number = start_byte_number+8
              
            if (list_tracetype[6]== "1"):
                print("export_dequene_length")
                data_dict["export_dequene_length"] = bitstring.BitArray(bytes=pkt[start_byte_number:start_byte_number+4]).unpack("uintbe:32")[0]
                start_byte_number = start_byte_number+4
            else:
                data_dict["export_dequene_length"]=0
            if (list_tracetype[12] == "1"):
                print("export_enquene_length")
                data_dict["export_enquene_length"] = bitstring.BitArray(bytes=pkt[start_byte_number:start_byte_number+4]).unpack("uintbe:32")[0]
                start_byte_number = start_byte_number+4
            else:
                data_dict["export_enquene_length"]=0
            if(list_tracetype[23] == "1"):
                print("exprt_packet_length")
                data_dict["export_packet_length"] = bitstring.BitArray(bytes=pkt[start_byte_number:start_byte_number+4]).unpack("uintbe:32")[0]
                start_byte_number =start_byte_number+4
            else:
                data_dict["export_packet_length"] = 0
            dex_dict["data"] = data_dict
            # print(dex_dict)
            try:
                conn=sqlite3.connect("../db/telemetry.db")
                cursor = conn.cursor()
                
                cursor.execute("delete from data_list where src='%s' and namespace_id=%d and sequencenumber=%d and flowid=%d"%(dex_dict["src"],dex_dict["namespace_id"],dex_dict["sequencenumber"],dex_dict["flowid"]))
            
                cursor.execute("insert into data_list values('%s','%s','%d','%d','%d','%d','%d','%d','%d','%d','%d','%d','%d','%d')"
                                %(dex_dict["src"],dex_dict["tracetype"],dex_dict["namespace_id"],dex_dict["reserved"],dex_dict["sequencenumber"],dex_dict["flowid"],dex_dict["flags"],data_dict["export_port"][0],
                                data_dict["export_port"][1],data_dict["export_timestap"],data_dict["export_transit_delay"],data_dict["export_dequene_length"],data_dict["export_enquene_length"],
                                data_dict["export_packet_length"]))
                conn.commit()
                cursor.close()
                
                
            except Exception as e:
                print(e)

            # if os.path.isdir(self.path_dir):
            #     with open(self.path_dir+"/data_list.json",mode="a") as f1:
            #         f1.write(json.dumps(dex_dict)+"\n")
            #     f1.close()
            # else:
            #     print("error")
            #     return

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
    def moniter(self):

        con_eth0 = sniff(prn=self.parse_packet, filter=self.filter, store=0, iface=self.iface)
    

if __name__ == "__main__":
    queue=Queue.Queue(40)
    obj1 = Oam()
    obj2 = Oam(queue)
    obj3 = Oam(queue)
    p1=ThreadPoolExecutor(5)
    p1.submit(obj1.moniter)
    # p1.submit(obj2.send_oam_request)
    # p1.submit(obj3.parse_metric)
   