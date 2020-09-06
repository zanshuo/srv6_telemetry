#!/usr/bin/python

from google import protobuf
import bitstring
from scapy.all import *
import json
from time import sleep
import datetime
from concurrent.futures import ThreadPoolExecutor
from goto import with_goto
from sync_time import thrift_connect
class Udld:
    config_list = list()
    path_dict = dict()
    rel = dict()
    
    
    def __init__(self,filter="outbound", iface="con-eth0",path_dir="../build/"):
        self.connect =dict()
        self.filter = filter
        self.iface=iface
        self.path_dir = path_dir
        self.sequence = 1
        Udld.share_data(self.path_dir)
        
        

    @classmethod
    def share_data(cls,path):
        with open(path+"config.json", mode="r") as f:
            cls.config_list = json.load(f)
            f.close()
        for tmp in cls.config_list:
            if "ipv4_address" in tmp.keys():
                cls.rel[tmp["ipv4_address"]] = tmp["name"]
            
    def send_udld_packet(self,sequence,flag):
        """
            sequence:int range:0 < sequence < 2**32-1
            flag:int 0 or 2 
        """
        assert (isinstance(sequence,int )),"sequence error"
        assert (isinstance(flag,int )),"flag error"
        s = bitstring.pack('uintbe:32', sequence)
        str2=""
        for tmp in [0,8,16,24]:
            temp=s[tmp:tmp+8]
            str2=str2+chr(int(temp.hex,16))
        str1=chr(flag)
        pkt = Ether(type=0x8870)/LLC()/SNAP(OUI=0x00000C,code=0x0111)/Raw(load=" %s\0\0\0\a\0\b%s"%(str1,str2))
        sendp(pkt, iface="con-eth0",verbose=False)

    def update_peer_json(self):
        print("start update")
        # for x ,y in Udld.path_dict.items():
        #     for tmp1,tmp2 in y.items():
        #         if tmp2[1] != self.sequence:
        #             del y[tmp1]
        f=open(self.path_dir+"peer.json",mode ="w")
        print(Udld.path_dict)
        json.dump(Udld.path_dict,f,indent=1)
        f.close
    def send_udld_request(self):
        for tmp in Udld.config_list:
            self.connect[tmp["name"]] = thrift_connect(tmp["thrift_port"])
        start_time = datetime.datetime.now()
        while True:
            end_time = datetime.datetime.now()
            # if self.sequence == 2**32 -1:
            #     self.sequence = 1
            #     Udld.path_dict = dict() 
            #     start_time = datetime.datetime.now()
            #     continue
            if (end_time-start_time).seconds > 300:
                self.sequence =1
                start_time = end_time
                Udld.path_dict.clear()
                Udld.share_data(self.path_dir)
            if self.sequence == 1:
                self.send_udld_packet(self.sequence,2)
                sleep(0.3)        
                self.sequence+=1
                self.send_udld_packet(self.sequence,2)
                sleep(0.3)
                self.sequence += 1
                self.send_udld_packet(self.sequence,2)
                sleep(1)
                self.update_peer_json()
                self.sequence +=1
            elif self.sequence > 3:
                self.send_udld_packet(self.sequence,0)
                sleep(0.3)
                # for tmp1,tmp2 in self.connect.items():
            
                    
                    
                    
                     
                self.sequence +=1
            else:
                print("error")
                break
    
    @with_goto
    def parse_udld(self,pkt_raw):
        try:
            
            pkt=pkt_raw[3].load

        except:
            print("error!")
            return
     
        Opcode=int(bitstring.BitArray(bytes=pkt)[3:8].bin,2) 
        flag=int(bitstring.BitArray(bytes=pkt)[8:16].bin,2)
        if Opcode == 2:
            print("shoudaobao")
            device_id_raw = pkt[8:12]
            peer_id_raw = pkt[16:20]
            port_id_raw = pkt[20:24]
            sequence_number_raw=pkt[28:32]
            d1 = bitstring.BitArray(bytes=device_id_raw)[:8].unpack("uintbe:8")[0]
            d2 = bitstring.BitArray(bytes=device_id_raw)[8:16].unpack("uintbe:8")[0]
            d3 = bitstring.BitArray(bytes=device_id_raw)[16:24].unpack("uintbe:8")[0]
            d4 = bitstring.BitArray(bytes=device_id_raw)[24:32].unpack("uintbe:8")[0]
            device_id = str(d1)+"."+str(d2)+"."+str(d3)+"."+str(d4)
            p1 = bitstring.BitArray(bytes=peer_id_raw)[:8].unpack("uintbe:8")[0]
            p2 = bitstring.BitArray(bytes=peer_id_raw)[8:16].unpack("uintbe:8")[0]
            p3 = bitstring.BitArray(bytes=peer_id_raw)[16:24].unpack("uintbe:8")[0]
            p4 = bitstring.BitArray(bytes=peer_id_raw)[24:32].unpack("uintbe:8")[0]
            peer_id = str(p1)+"."+str(p2)+"."+str(p3)+"."+str(p4)
            port_id = bitstring.BitArray(bytes=port_id_raw).unpack("uintbe:32")[0]
            sequence_number = bitstring.BitArray(bytes=sequence_number_raw).unpack("uintbe:32")[0]
            
            if device_id in Udld.rel.keys():
        
                label.begin
                if Udld.rel[device_id] not in Udld.path_dict.keys():
                    Udld.path_dict[Udld.rel[device_id]] = {port_id:[Udld.rel[peer_id], sequence_number]}
                    # print("new node success")
                    if sequence_number > 3:
                        Udld.update_peer_json() 
                else:
                    if port_id not in Udld.path_dict[Udld.rel[device_id]].keys():
                        Udld.path_dict[Udld.rel[device_id]][port_id] =[Udld.rel[peer_id],sequence_number]
                        # print("new port success")
                        if sequence_number >3:
                            Udld.update_peer_json()
                    elif peer_id != Udld.path_dict[Udld.rel[device_id]][port_id][0] and sequence_number >= Udld.path_dict[Udld.rel[device_id]][port_id][1] :
                        Udld.path_dict[Udld.rel[device_id]][port_id][0]=Udld.rel[peer_id]
                        Udld.path_dict[Udld.rel[device_id]][port_id][1]=sequence_number
                        # print("new peer success")
                        if sequence_number>3:
                            Udld.update_peer_json()
                    elif peer_id == Udld.path_dict[Udld.rel[device_id]][port_id][0] and sequence_number > Udld.path_dict[Udld.rel[device_id]][port_id][1]:
                        Udld.path_dict[Udld.rel[device_id]][port_id][1]=sequence_number
                        # if sequence_number>3:
                        #     Udld.update_peer_json()
                        # print("new sequence") 
                              
            else:
                sleep(0.3)
                Udld.share_data(self.path_dir)
                if device_id in Udld.rel.keys():
                    goto.begin 
                else:
                    print("error")
                    return 
                                   
    def parse_packet(self,pkt_raw):       
        try:
            #34525==0x86dd IPV6
            if pkt_raw[0].type == 34525:
                self.parse_oam(pkt_raw)
            #34928==0x8870 udld
            elif pkt_raw[0].type == 34928:
            # else:
                self.parse_udld(pkt_raw)
        except:
            return
    def moniter(self):
        con_eth0 = sniff(prn=self.parse_packet, filter=self.filter, store=0, iface=self.iface)  

if __name__ == "__main__":
    obj1 = Udld()
    obj2 = Udld()
    p1=ThreadPoolExecutor(5)
    p1.submit(obj1.moniter)
    p1.submit(obj2.send_udld_request)
    
    



   

    