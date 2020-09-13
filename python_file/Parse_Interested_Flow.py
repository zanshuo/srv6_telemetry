#!/usr/bin/python
import sys
sys.path.insert(0,"../../behavioral-model/tools/")
sys.path.insert(1,"../../behavioral-model/targets/simple_switch")

from sync_time import thrift_connect
import sqlite3
import os
import json
import copy
from time import sleep
class Parse_interested_flow:
    config_list=list()
    name_to_sid=dict()
    sid_to_thrift_port=dict()
    path_dict=dict()
    sid_to_name=dict()
    def __init__(self,flowid,namespace_id,path="../build/"):
        self.table_name="flow%d"%(flowid)
        self.flowid=flowid
        self.path=path
        self.namespace_id=namespace_id
        self.path_list=list()
        self.start_sequence=1
        self.total_packet_count=0
        self.total_packet_length=0
        self.node_data_dict=dict()
        self.link_delay_dict=dict()
        Parse_interested_flow.share_data(self.path)
        Parse_interested_flow.share_path(self.path)
        # conn=sqlite3.connect("../db/telemetry.db")
        # cursor = conn.cursor()
        # # cursor.execute("create table data_list(src varchar(40),tracetype varchar(40),namespace_id smallint,reserved tinyint,sequencenumber int,flowid int,flags smallint,\
        # #                     export_ingress_port smallint,export_egress_port smallint,export_timestap bigint,export_transit_delay bigint,export_dequene_length int,export_enquene_length int,export_packet_length int)")
        # # cursor.execute("create table %s(src varchar(40),dst varchar(40),total_delay bigint)"%(self.table_name))
        # cursor.close()
        # conn.commit()
        # conn.close()
    @classmethod
    def share_data(cls,path):
        while True:
            if os.path.isfile(path+"config.json"):
                with open(path+"config.json", mode="r") as f:
                    cls.config_list = json.load(f)
                    f.close()
                for tmp in cls.config_list:
                    if "sid" in tmp.keys() and "thrift_port" in tmp.keys() and "name" in tmp.keys():
                        cls.name_to_sid[tmp["name"]] = tmp["sid"]
                        cls.sid_to_thrift_port[tmp["sid"]] = tmp["thrift_port"] 
                        cls.sid_to_name[tmp["sid"]] = tmp["name"]
                
                break
            else:
                continue
    @classmethod
    def share_path(cls,path):
        f=open(path+"namespaceid_for_path.json",mode="r")
        cls.path_dict=json.load(f)
        f.close
    def generate_data(self):
        self.path_list=Parse_interested_flow.path_dict[str(self.namespace_id)]
        
        for serial,tmp in enumerate(self.path_list):
            if tmp not in self.node_data_dict.keys():
                self.node_data_dict[tmp] = {"export_transit_delay":None,"receive_packet_count":None,"loss_packet_count":None,"export_timestap":None}
            else:
                self.node_data_dict[tmp]["export_transit_delay"] = list()
            if serial == len(self.path_list)-1:
                break
            if Parse_interested_flow.sid_to_name[self.path_list[serial]]+"-"+Parse_interested_flow.sid_to_name[self.path_list[serial+1]] not in self.link_delay_dict.keys():
                self.link_delay_dict[Parse_interested_flow.sid_to_name[self.path_list[serial]]+"-"+Parse_interested_flow.sid_to_name[self.path_list[serial+1]]] = None
            else:
                self.link_delay_dict[Parse_interested_flow.sid_to_name[self.path_list[serial]]+"-"+Parse_interested_flow.sid_to_name[self.path_list[serial+1]]] = list()
       
        
    def read_register(self):
        while True:
            sleep(2)
            self.generate_data()
            # f=open(self.path+"namespaceid_for_path.json",mode="r")
            # path_dict=json.load(f)
            # path_list=path_dict[self.namespace_id]
            # path_list=copy.deepcopy(self.path_list)
            
            # for serial,data in enumerate(path_list):
            #     path_list[serial] = Parse_interested_flow.sid_to_thrift_port[path_list[serial]]
        
            # for tmp in path_list:
            #     thrift_obj=thrift_connect(tmp,self.path+"telemetry.json")
            #     result=thrift_obj.do_register_read("MyIngress.dex_sequencenumber %d"%(self.flowid))
            #     sequence_list.append(result)
            
            sequence =thrift_connect(Parse_interested_flow.sid_to_thrift_port[self.path_list[0]],self.path+"telemetry.json").do_register_read("MyIngress.dex_sequencenumber %d"%(self.flowid))
            print(sequence)
            if sequence >1  and sequence-self.start_sequence >0:
                sequence=sequence-1
                result=self.parse_data(sequence)
                print (result[0])
                print (result[1])  
                print(self.total_packet_count)
                print(self.total_packet_length)
            
        
     
    def parse_data(self,sequence):
        conn=sqlite3.connect("../db/telemetry.db")
        for tmp_sequence in range(self.start_sequence,sequence+1):
            
            cursor = conn.cursor()
            cursor.execute("select src,export_timestap,export_transit_delay,export_packet_length from data_list where namespace_id=%d and sequencenumber=%d and flowid=%d"%(self.namespace_id,tmp_sequence,self.flowid))
            values=cursor.fetchall()
            # print(values)
            cursor.close()
            if len(values) == len(self.path_list):
                flag=[tmp[0] in self.path_list for tmp in values]
                if False not in flag:
                    # dict_data=dict()
                    for x in values:
                        if self.node_data_dict[x[0]]["export_transit_delay"] == None:
                            self.node_data_dict[x[0]]["export_transit_delay"] = [x[2],]
                        else:
                            self.node_data_dict[x[0]]["export_transit_delay"].append(x[2])
                        if self.node_data_dict[x[0]]["receive_packet_count"]==None:
                            self.node_data_dict[x[0]]["receive_packet_count"]=1
                        else:
                            self.node_data_dict[x[0]]["receive_packet_count"] += 1
                        if self.node_data_dict[x[0]]["loss_packet_count"] == None:
                            self.node_data_dict[x[0]]["loss_packet_count"]=0
                        self.node_data_dict[x[0]]["export_timestap"]=x[1]
                        if x[0] ==self.path_list[0]:
                            self.total_packet_length=self.total_packet_length+x[3]
                    self.total_packet_count+=1
                    for serial in range(len(self.path_list)):
                        if serial == len(self.path_list)-1:
                            break
                        
                        link_delay=self.node_data_dict[self.path_list[serial+1]]["export_timestap"] - self.node_data_dict[self.path_list[serial]]["export_timestap"]- self.node_data_dict[self.path_list[serial]]["export_transit_delay"][-1]
                        # print(link_delay)
                        if self.link_delay_dict[Parse_interested_flow.sid_to_name[self.path_list[serial]]+"-"+Parse_interested_flow.sid_to_name[self.path_list[serial+1]]]==None:
                            self.link_delay_dict[Parse_interested_flow.sid_to_name[self.path_list[serial]]+"-"+Parse_interested_flow.sid_to_name[self.path_list[serial+1]]]= [link_delay,]
                        else:
                            self.link_delay_dict[Parse_interested_flow.sid_to_name[self.path_list[serial]]+"-"+Parse_interested_flow.sid_to_name[self.path_list[serial+1]]].append(link_delay)
                else:
                    continue
            elif len(values)<len(self.path_list):
                pass
            
        self.start_sequence =sequence+1 
        node_dict=dict()
        link_dict=dict()
        # print(self.node_data_dict)
        for x,y in self.node_data_dict.items():
            # print(y["receive_packet_count"])
            loss_rate="%.3f%%"%((y["loss_packet_count"]/float(y["receive_packet_count"]))*100.0)
            if loss_rate == "0.000%":
                loss_rate="0%"
            # node_dict[Parse_interested_flow.sid_to_name[x]] = {"transit_delay":"%.3fms"%((sum(y["export_transit_delay"])/len(y["export_transit_delay"]))/1000),
            # "loss_rate":"%.3f%%"%((y["loss_packet_count"]/y["receive_packet_count"])*100)}
            node_dict[Parse_interested_flow.sid_to_name[x]] = {"transit_delay":"%.3fms"%((sum(y["export_transit_delay"])/float(len(y["export_transit_delay"])))/1000.0),
            "loss_rate":loss_rate}
           
        # print(self.link_delay_dict)
        for x,y in self.link_delay_dict.items():
            link_dict[x] ="%.3fms"%((sum(y)/float(len(y)))/1000.0)
        return node_dict,link_dict
if __name__ == "__main__":
    obj1=Parse_interested_flow(1,0)
    obj1.read_register()
