#!/usr/bin/python
from os import path
from sqlite3.dbapi2 import connect
import sys
sys.path.insert(0,"../../behavioral-model/tools/")
sys.path.insert(1,"../../behavioral-model/targets/simple_switch")
from goto import with_goto
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
        self.total_real_packet_count=0
        self.total_real_packet_length=0
        self.total_packet_loss=0
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
            sleep(1)
            self.generate_data()
            sequence =thrift_connect(Parse_interested_flow.sid_to_thrift_port[self.path_list[0]],self.path+"telemetry.json").do_register_read("MyIngress.dex_sequencenumber %d"%(self.flowid))
            print(sequence)
            if sequence >1  and sequence-self.start_sequence >0:
                sequence=sequence-1
                result=self.parse_data(sequence)
                print (result[0])
                print (result[1])  
                print(self.total_real_packet_count)
                print(self.total_real_packet_length)
                print(self.total_packet_loss)
            
        
    @with_goto
    def parse_data(self,sequence):
        count=0
        conn=sqlite3.connect("../db/telemetry.db")
        for tmp_sequence in range(self.start_sequence,sequence+1):
            label.begin
            cursor = conn.cursor()
            
            cursor.execute("select src,export_timestap,export_transit_delay,export_packet_length from data_list where namespace_id=%d and sequencenumber=%d and flowid=%d"%(self.namespace_id,tmp_sequence,self.flowid))
            values=cursor.fetchall()
            
            # print(values)
            cursor.close()
            if values == []:
                if count<3:
                    sleep(0.2)
                    count+=1
                    goto.begin
                else:
                    count=0
                for tmp in self.path_list:
                    if self.node_data_dict[tmp]["receive_packet_count"]==None:
                        self.node_data_dict[tmp]["receive_packet_count"]=1
                    else:
                        self.node_data_dict[tmp]["receive_packet_count"]+=1
                    if self.node_data_dict[tmp]["loss_packet_count"] == None:
                        self.node_data_dict[tmp]["loss_packet_count"]=1
                    else:
                        self.node_data_dict[tmp]["loss_packet_count"]+=1
                       
                self.total_packet_loss+=1
                continue
            flag=[tmp[0] in self.path_list for tmp in values]
            if False not in flag:
                if len(values) == len(self.path_list):
                    count=0
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
                            self.total_real_packet_length=self.total_real_packet_length+x[3]
                    self.total_real_packet_count+=1
                    for serial in range(len(self.path_list)):
                        if serial == len(self.path_list)-1:
                            break
                        link_delay=self.node_data_dict[self.path_list[serial+1]]["export_timestap"] - self.node_data_dict[self.path_list[serial]]["export_timestap"]- self.node_data_dict[self.path_list[serial]]["export_transit_delay"][-1]
                        # print(link_delay)
                        if self.link_delay_dict[Parse_interested_flow.sid_to_name[self.path_list[serial]]+"-"+Parse_interested_flow.sid_to_name[self.path_list[serial+1]]]==None:
                            self.link_delay_dict[Parse_interested_flow.sid_to_name[self.path_list[serial]]+"-"+Parse_interested_flow.sid_to_name[self.path_list[serial+1]]]= [link_delay,]
                        else:
                            self.link_delay_dict[Parse_interested_flow.sid_to_name[self.path_list[serial]]+"-"+Parse_interested_flow.sid_to_name[self.path_list[serial+1]]].append(link_delay)
                    
                elif len(values)<len(self.path_list):
                    if count<3:
                        sleep(0.2)
                        count+=1
                        goto.begin
                    else:
                        count=0
                    path_list=copy.deepcopy(self.path_list)
                    values_list=[tmp_value[0] for tmp_value in values]
                    
                    if self.path_list[-1] in values_list:
                        self.total_real_packet_count+=1
                        self.total_real_packet_length=self.total_real_packet_length + [tmp[3] for tmp in values if tmp[0] == self.path_list[-1]][0]-48-16*len(self.path_list)
                        for tmp in values:
                            if self.node_data_dict[tmp[0]]["export_transit_delay"] == None:
                                self.node_data_dict[tmp[0]]["export_transit_delay"] = [tmp[2],]
                            else:
                                self.node_data_dict[tmp[0]]["export_transit_delay"].append(tmp[2])
                            if self.node_data_dict[tmp[0]]["receive_packet_count"]==None:
                                self.node_data_dict[tmp[0]]["receive_packet_count"]=1
                            else:
                                self.node_data_dict[tmp[0]]["receive_packet_count"] += 1
                            if self.node_data_dict[tmp[0]]["loss_packet_count"] == None:
                                self.node_data_dict[tmp[0]]["loss_packet_count"]=0
                            self.node_data_dict[tmp[0]]["export_timestap"]=tmp[1]
                        for sid in self.path_list:
                            if sid not in values_list:
                                if self.node_data_dict[sid]["receive_packet_count"]==None:
                                    self.node_data_dict[sid]["receive_packet_count"]=1
                                else:
                                    self.node_data_dict[sid]["receive_packet_count"] += 1
                                if self.node_data_dict[sid]["loss_packet_count"] == None:
                                    self.node_data_dict[sid]["loss_packet_count"]=0
                                if self.node_data_dict[sid]["export_transit_delay"] == None:
                                    self.node_data_dict[sid]["export_transit_delay"] = ["no_data",]
                                else:
                                    self.node_data_dict[sid]["export_transit_delay"].append("no_data")
                                path_list.remove(sid)
                   
                                        
                    else:
                        self.total_packet_loss+=1
                        for tmp in values:
                            if self.node_data_dict[tmp[0]]["export_transit_delay"] == None:
                                self.node_data_dict[tmp[0]]["export_transit_delay"] = [tmp[2],]
                            else:
                                self.node_data_dict[tmp[0]]["export_transit_delay"].append(tmp[2])
                            if self.node_data_dict[tmp[0]]["receive_packet_count"]==None:
                                self.node_data_dict[tmp[0]]["receive_packet_count"]=1
                            else:
                                self.node_data_dict[tmp[0]]["receive_packet_count"] += 1
                            if self.node_data_dict[tmp[0]]["loss_packet_count"] == None:
                                self.node_data_dict[tmp[0]]["loss_packet_count"]=0
                           
                            self.node_data_dict[tmp[0]]["export_timestap"]=tmp[1]
                        for tmp in self.path_list:
                            if tmp not in values_list:
                                path_list.remove(tmp)
                        for sid in self.path_list[:self.path_list.index(path_list[-1])+1]:
                            if sid not in path_list:
                                if self.node_data_dict[sid]["receive_packet_count"]==None:
                                    self.node_data_dict[sid]["receive_packet_count"]=1
                                else:
                                    self.node_data_dict[sid]["receive_packet_count"] += 1
                                if self.node_data_dict[sid]["loss_packet_count"] == None:
                                    self.node_data_dict[sid]["loss_packet_count"]=0
                                if self.node_data_dict[sid]["export_transit_delay"] == None:
                                    self.node_data_dict[sid]["export_transit_delay"] = ["no_data",]
                                else:
                                    self.node_data_dict[sid]["export_transit_delay"].append("no_data")
                        for serial,sid in enumerate(self.path_list[self.path_list.index(path_list[-1])+1:]):
                            if serial == 0:
                                if self.node_data_dict[sid]["receive_packet_count"]==None:
                                    self.node_data_dict[sid]["receive_packet_count"]=1
                                else:
                                    self.node_data_dict[sid]["receive_packet_count"] += 1
                                if self.node_data_dict[sid]["loss_packet_count"] == None:
                                    self.node_data_dict[sid]["loss_packet_count"]=1
                                else:
                                    self.node_data_dict[sid]["loss_packet_count"]+=1
                                if self.node_data_dict[sid]["export_transit_delay"] == None:
                                    self.node_data_dict[sid]["export_transit_delay"] = ["loss_packet",]
                                else:
                                    self.node_data_dict[sid]["export_transit_delay"].append("loss_packet")
                            else:
                                if self.node_data_dict[sid]["receive_packet_count"]==None:
                                    self.node_data_dict[sid]["receive_packet_count"]=1
                                else:
                                    self.node_data_dict[sid]["receive_packet_count"] += 1
                                if self.node_data_dict[sid]["loss_packet_count"] == None:
                                    self.node_data_dict[sid]["loss_packet_count"]=0
                               
                                if self.node_data_dict[sid]["export_transit_delay"] == None:
                                    self.node_data_dict[sid]["export_transit_delay"] = ["no_data",]
                                else:
                                    self.node_data_dict[sid]["export_transit_delay"].append("no_data")
                            
                    for tmp in self.path_list:
                        if tmp not in path_list:
                            for key in self.link_delay_dict.keys():
                                if Parse_interested_flow.sid_to_name[tmp] in key:
                                    if self.link_delay_dict[key] == None: 
                                        self.link_delay_dict[key] =["no_data",]
                                    else:
                                        self.link_delay_dict[key].append("no_data")          
                    for serial in range(len(path_list)):
                        if serial==len(path_list)-1:
                            break
                        if self.path_list.index(path_list[serial])==self.path_list.index(path_list[serial+1])-1:
                            link_delay=self.node_data_dict[path_list[serial+1]]["export_timestap"] - self.node_data_dict[path_list[serial]]["export_timestap"]- self.node_data_dict[path_list[serial]]["export_transit_delay"][-1]
                    # print(link_delay)
                            if self.link_delay_dict[Parse_interested_flow.sid_to_name[path_list[serial]]+"-"+Parse_interested_flow.sid_to_name[path_list[serial+1]]]==None:
                                self.link_delay_dict[Parse_interested_flow.sid_to_name[path_list[serial]]+"-"+Parse_interested_flow.sid_to_name[path_list[serial+1]]]= [link_delay,]
                            else:
                                self.link_delay_dict[Parse_interested_flow.sid_to_name[path_list[serial]]+"-"+Parse_interested_flow.sid_to_name[path_list[serial+1]]].append(link_delay)
                    
                                   
            else:
                print("wrong path")
                
        self.start_sequence =sequence+1 
        node_dict=dict()
        link_dict=dict()
        # print(self.node_data_dict)
        for x,y in self.node_data_dict.items():
            # print(y["receive_packet_count"])
            print(x,y["loss_packet_count"])
            loss_rate="%.3f%%"%((y["loss_packet_count"]/float(y["receive_packet_count"]))*100.0)
            if loss_rate == "0.000%":
                loss_rate="0%"
            # node_dict[Parse_interested_flow.sid_to_name[x]] = {"transit_delay":"%.3fms"%((sum(y["export_transit_delay"])/len(y["export_transit_delay"]))/1000),
            # "loss_rate":"%.3f%%"%((y["loss_packet_count"]/y["receive_packet_count"])*100)}
            if "no_data" in y["export_transit_delay"]  and y["export_transit_delay"].count("no_data") == len(y["export_transit_delay"]):
                node_dict[Parse_interested_flow.sid_to_name[x]]={"transit_delay":"no_data","loss_rate":loss_rate}

            elif "loss_packet" in y["export_transit_delay"] and y["export_transit_delay"].count("loss_packet") == len(y["export_transit_delay"]):
                node_dict[Parse_interested_flow.sid_to_name[x]]={"transit_delay":"loss_packet","loss_rate":loss_rate}
                
            else:
                transit_delay=list()
                for tmp in y["export_transit_delay"]:
                    if tmp !="loss_packet" and tmp != "no_data":
                        # print("hit")
                        transit_delay.append(tmp)
                # [y["export_transit_delay"].remove(tmp) for tmp in y["export_transit_delay"] if tmp =="loss_packet" or tmp =="no_data"]
                # print(transit_delay)
               
                node_dict[Parse_interested_flow.sid_to_name[x]] = {"transit_delay":"%.3fms"%((sum(transit_delay)/float(len(transit_delay)))/1000.0),
            "loss_rate":loss_rate}
           
        # print(self.link_delay_dict)
        for x,y in self.link_delay_dict.items():
            if "no_data" in y and y.count("no_data") == len(y):

                link_dict[x]="no_data"
            else:
                link_delay=list()
                for tmp in y:
                    if tmp !="no_data":
                        link_delay.append(tmp)
                # [link_delay.append(tmp) for tmp in y if tmp !="no_data"]
                # print(y)
                # print(link_delay)
                link_dict[x] ="%.3fms"%((sum(link_delay)/float(len(link_delay)))/1000.0)
        return node_dict,link_dict
if __name__ == "__main__":
    obj1=Parse_interested_flow(1,0)
    obj1.read_register()
