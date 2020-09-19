#!/usr/bin/python
import sys
sys.path.insert(0,"../../behavioral-model/tools/")
sys.path.insert(1,"../../behavioral-model/targets/simple_switch")

import sqlite3
import json
import os
import networkx as nx
from sync_time import thrift_connect
import time
import datetime
from watchdog.observers import Observer
from watchdog.events import *
class Compute_Topology:
    
    config_list=list()
    graph=dict()
    name_to_sid=dict()
    namespaceid_for_path=dict()
    name_to_thrift_port=dict()
    peer=dict()
    src=None
    dst=None
    k_values=[(1,1,1),(1,0,0)]
    def __init__(self,path_dir):
        self.path_dir=path_dir
        Compute_Topology.share_data(self.path_dir)
        Compute_Topology.share_data_peer(self.path_dir)
        # self.generate_all_path()
        self.start_time=0
        self.trigger_time=0
    @classmethod
    def share_data(cls,path):
        while True:
            if os.path.isfile(path+"config.json"):
                with open(path+"config.json", mode="r") as f:
                    cls.config_list = json.load(f)
                    f.close()
                cls.src=cls.config_list[0]["name"]
                cls.dst=cls.config_list[-2]["name"]
                for tmp in cls.config_list:
                    if "sid" in tmp.keys() and "name" in tmp.keys():
                        cls.name_to_sid[tmp["name"]] = tmp["sid"]
                    if "name" in tmp.keys() and "thrift_port" in tmp.keys():
                        cls.name_to_thrift_port[tmp["name"]]=tmp["thrift_port"]
                        # cls.sid_to_name[tmp["sid"]] = tmp["name"] 
                
                    # if "ipv6_address" in tmp.keys() and "sid" in tmp.keys():
                    #     cls.ipv6_address_to_sid[tmp["ipv6_address"]] = tmp["sid"]
                break
            else:
                continue
    @classmethod
    def share_data_peer(cls,path_dir):
        f1=open(path_dir+"/peer.json")
        cls.peer=json.load(f1)
        f1.close
        G = nx.Graph()
        G.add_node(Compute_Topology.src)
        for src,data in cls.peer.items():
            for tmp in data.values():
                G.add_edge(src,tmp[0])
        path=nx.all_simple_paths(G,source=Compute_Topology.src, target=Compute_Topology.dst)    
        for serial,data in enumerate(list(path)):
            for tmp_serial in range(len(data)):
                data[tmp_serial]=Compute_Topology.name_to_sid[data[tmp_serial]]
            Compute_Topology.namespaceid_for_path[serial] = data
        f=open(path_dir+"namespaceid_for_path.json",mode="w")
        json.dump(Compute_Topology.namespaceid_for_path,f)
        f.close
    # def share_data_peer(cls,path):
    #     f1=open(path+"/peer.json")
    #     cls.peer=json.load(f1)
    #     f1.close
        
    #     for x,y in cls.peer.items():
    #         list_tmp=list()
    #         for tmp in y.values():
    #             list_tmp.append(tmp[0])
    #         cls.graph[x] =list_tmp
    # def find_All_Path(self,graph,start,end,path=[]):
    #     path = path+[start]   
    #     if start == end:
    #         return path  
    #     paths = []   
    #     for node in graph[start]:
    #         if node not in path:
    #             newpaths = self.find_All_Path(graph,node,end,path) 
             
    #             for newpath in newpaths:
    #                 paths.append(newpath)
    #     return paths

    # def generate_all_path(self):
        
    #     # graph = {'r1': ['r2', 'r3'],
    #     #          'r2': ['r1','r3','r4','r5'],
    #     #          'r3': ['r1','r2','r4','r5'],
    #     #          'r4': ['r2','r3','r5','r6'],
    #     #          'r5': ['r2','r3','r4','r6'],
    #     #          'r6': ['r4','r5'],
    #     #         }
        
    #     allpath = self.find_All_Path(Compute_Topology.graph,'r1','r6')
    #     allpath_list=list()
    #     index=0
    #     for serial in range(len(allpath)):
    #         if serial!=0 and allpath[serial] == "r1":
    #             allpath_list.append(allpath[index:serial])
    #             index=serial
    #     allpath_list.append(allpath[index:])
    #     for serial,data in enumerate(allpath_list):
    #         for tmp_serial in range(len(data)):
    #             data[tmp_serial]=Compute_Topology.name_to_sid[data[tmp_serial]]
    #         Compute_Topology.namespaceid_to_path[serial] =data
    #     f=open(self.path_dir+"namespaceid_for_path.json",mode="w")
    #     json.dump(Compute_Topology.namespaceid_to_path,f)
    #     f.close
    def generate_tuple(self,src,dst,intf,time=300.0):
        
        bw=1000000.0
        thrift_conn=thrift_connect(Compute_Topology.name_to_thrift_port[src],self.path_dir+"telemetry.json")
        intf_packet =thrift_conn.do_register_read("MyIngress.interface_packet_length %s"%(intf))
        thrift_conn.do_register_write("MyIngress.interface_packet_length %s 0"%(intf))
        load=255*((intf_packet/time)/bw)
        conn=sqlite3.connect("../db/telemetry.db")
        cursor = conn.cursor()
        cursor.execute("select total_delay from metric_list where src='%s' and dst='%s'"%(src,dst))
        values=cursor.fetchall()
        sum_delay=0
        for tmp in values:
            sum_delay=sum_delay+tmp[0]
    
        cursor.close()
        conn.close()
        delay =sum_delay/float(len(values))
        weight_tuple_list=list()
        for data in Compute_Topology.k_values:
            weight=int(256*((data[0]*bw)+((data[1]*bw)/(256-load))+(data[2]*delay)))
            weight_tuple_list.append((src,dst,weight))
        return weight_tuple_list
    def compute_path(self,time=300.0):
        
        # time.sleep(5)
        graph_list=list()
        [graph_list.append([]) for count in range(len(Compute_Topology.k_values))]
        for src,data in Compute_Topology.peer.items():
            # print(data)
            # print(Compute_Topology.peer)
            for key in data.keys():
                graph_tuple_list=self.generate_tuple(src,data[key][0],key,time)
                for serial in range(len(graph_list)):
                    graph_list[serial].append(graph_tuple_list[serial])

        conn=sqlite3.connect("../db/telemetry.db")
        cursor = conn.cursor()
        cursor.execute("delete from metric_list")
        conn.commit()
        cursor.close()
        conn.close()
        path_dict=dict()
        for serial in range(len(graph_list)):
            G = nx.Graph()
            G.add_node(Compute_Topology.src)
            G.add_weighted_edges_from(graph_list[serial])
            path=nx.dijkstra_path(G, source=Compute_Topology.src, target=Compute_Topology.dst)
            path1=nx.all_simple_paths(G,source=Compute_Topology.src, target=Compute_Topology.dst)
            for tmp in path1:
                print(tmp)
            path_dict[Compute_Topology.k_values[serial]] = path
        
        print(path_dict)
    def regular_compute(self):
        while True:
            time.sleep(30)
            if self.trigger_time!=0:
                time.sleep(self.trigger_time)
                self.trigger_time=0
            self.start_time=datetime.datetime.now()
            path=self.compute_path()
            print(path)
    def trigger_compute(self):
        while True:
            pass
    class MyHandler(FileSystemEventHandler):
        def __init__(self,path_dir):
            self.path_dir=path_dir
        def on_modified(self, event):
            if event.src_path==self.path_dir+"peer.json":
                print("peer change")
                Compute_Topology.share_data_peer(self.path_dir)
            elif event.src_path==self.path_dir+"config.json":
                print("config change")
                Compute_Topology.share_data(self.path_dir)
            print("文件 change %s"%event.src_path)
    
        def on_created(self, event):
            pass
        def on_deleted(self, event):
            pass
    def moniter_file(self):
        path_peer_json = self.path_dir+"peer.json"
        path_config_json=self.path_dir+"config.json"
        event_handler = self.MyHandler(self.path_dir)
        observer_config_json = Observer()
        observer_config_json.schedule(event_handler, path_config_json, recursive=True)
        observer_config_json.start()
        observer_peer_json=Observer()
        observer_peer_json.schedule(event_handler, path_peer_json, recursive=True)
        observer_peer_json.start()
        while True:
            pass  
if __name__ == "__main__":
    obj1=Compute_Topology("../build/")
    obj1.compute_path()
   
    

    