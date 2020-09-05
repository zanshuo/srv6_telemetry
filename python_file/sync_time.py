#!/usr/bin/python
import os
import sys

sys.path.insert(0,"../behavioral-model/tools/")
sys.path.insert(1,"../behavioral-model/targets/simple_switch")
import runtime_CLI
import datetime
from sswitch_CLI import SimpleSwitchAPI
from concurrent.futures import ThreadPoolExecutor
from sswitch_runtime.ttypes import *
import json


def thrift_connect(port,json_path=None):
    pre = runtime_CLI.PreType.SimplePreLAG
    services = runtime_CLI.RuntimeAPI.get_thrift_services(pre)
    services.extend(SimpleSwitchAPI.get_thrift_services())
    standard_client, mc_client, sswitch_client = runtime_CLI.thrift_connect(
        "127.0.0.1", port, services
        )
    if json_path != None:
        runtime_CLI.load_json_config(standard_client, json_path)
    tmp=SimpleSwitchAPI(pre, standard_client, mc_client, sswitch_client)
    return tmp
def time_elapsed(ob):
    start_time = datetime.datetime.now()
    tmp = ob.do_get_time_elapsed("get_time_elapsed")
    end_time = datetime.datetime.now()
    return end_time,tmp
def main_delta(switch_json_path,switch_p4_path,route_json_path=None):
    f1=open("build/config.json",mode="r")
    list_switch =json.load(f1)
    f1.close()
    time_dict=dict()
    first_node=thrift_connect(str(list_switch[0]["thrift_port"]))
    time_dict[list_switch[0]["thrift_port"]] = 0
    for x in range(1,len(list_switch)-1):
        second_node = thrift_connect(str(list_switch[x]["thrift_port"]))
        p1 = ThreadPoolExecutor(2)
        t1 = p1.submit(time_elapsed, first_node)
        t2 = p1.submit(time_elapsed, second_node)
        tmp1=t2.result()[0]-t1.result()[0]
        tmp2 = tmp1.seconds*10**6 + tmp1.microseconds
        time_dict[list_switch[x]["thrift_port"]] = t1.result()[1] - (t2.result()[1] - tmp2)
        p1.shutdown()
    # for x,y in time_dict.items():
    #     f_temp = open("./thrift_command/%s.txt"%(x),mode="a")
    #     f_temp.write("\ntable_add export_timestamp_t export_timestamp => %s"%(str(y)))
    #     f_temp.close()
    f2=open("build/time_delta.json",mode="w")
    json.dump(time_dict,f2,indent=1)
    f2.close()
    
    for port, data in time_dict.items():
        obj_temp = thrift_connect(port,route_json_path)
        # obj_temp.do_load_new_config_file("build/telemetry.json")
        # obj_temp.do_load_new_config_file(route_json_path)
        # obj_temp.do_swap_configs("")
        obj_temp.do_table_add("MyEgress.export_timestamp_t MyEgress.export_timestamp => %s"%(str(data)))
    os.popen("p4c-bm2-ss --p4v 16 -o %s %s"%(switch_json_path,switch_p4_path))
    obj_switch = thrift_connect(str(list_switch[-1]["thrift_port"]))
    obj_switch.do_load_new_config_file(switch_json_path)
    obj_switch.do_swap_configs("")
    
