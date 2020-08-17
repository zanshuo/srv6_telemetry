#!/usr/bin/python
from os import sep
import sys
from multiprocessing import Pool
sys.path.insert(0,"../behavioral-model/tools/")
sys.path.insert(1,"../behavioral-model/targets/simple_switch")
import runtime_CLI
import datetime
from sswitch_CLI import SimpleSwitchAPI
from concurrent.futures import ThreadPoolExecutor,ProcessPoolExecutor
from sswitch_runtime.ttypes import *
import json
import os
import time
# from gevent import monkey;monkey.patch_all()
# import gevent

def thrift_connect(port):
    pre = runtime_CLI.PreType.SimplePreLAG
    services = runtime_CLI.RuntimeAPI.get_thrift_services(pre)
    services.extend(SimpleSwitchAPI.get_thrift_services())
    standard_client, mc_client, sswitch_client = runtime_CLI.thrift_connect(
        "127.0.0.1", port, services
        )
    tmp=SimpleSwitchAPI(pre, standard_client, mc_client, sswitch_client)
    return tmp
def time_elapsed(ob):
    start_time = datetime.datetime.now()
    tmp = ob.do_get_time_elapsed("get_time_elapsed")
    end_time = datetime.datetime.now()
    return end_time,tmp
def main_delta():
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
        print(t1.result(),t2.result())
        tmp1=t2.result()[0]-t1.result()[0]
        tmp2 = tmp1.seconds*10**6 + tmp1.microseconds
        # print(t1.result())
        time_dict[list_switch[x]["thrift_port"]] = t1.result()[1] - (t2.result()[1] - tmp2)
        p1.shutdown()
    # for x,y in time_dict.items():
    #     f_temp = open("./thrift_command/%s.txt"%(x),mode="a")
    #     f_temp.write("\ntable_add export_timestamp_t export_timestamp => %s"%(str(y)))
    #     f_temp.close()
    f2=open("build/time_delta.json",mode="w")
    json.dump(time_dict,f2,indent=1)
    f2.close()
    for x, y in time_dict.items():
        obj_temp = thrift_connect(x)
        obj_temp.do_load_new_config_file("build/telemetry.json")
        obj_temp.do_swap_configs("")
        obj_temp.do_table_add("MyEgress.export_timestamp_t MyEgress.export_timestamp => %s"%(str(y)))
    obj_switch = thrift_connect(str(list_switch[-1]["thrift_port"]))
    obj_switch.do_load_new_config_file("thrift_command/out_of_bandswitch.json")
    obj_switch.do_swap_configs("")
if __name__ == '__main__':

    # # for x,y in time_dict.items():
    # #     f_temp = open("./thrift_command/%s.txt"%(x),mode="a")
    # #     f_temp.write("\ntable_add export_timestamp_t export_timestamp => %s"%(str(y)))
    # #     f_temp.close()
    # f2 = open("../build/time_delta.json", mode="w")
    # json.dump(time_dict, f2, indent=1)
    # f2.close()
    obj_temp = thrift_connect(9090)
    obj_temp2 = thrift_connect(9091)
    r1= time_elapsed(obj_temp)
    end_time_1 = r1[0]
    r2= time_elapsed(obj_temp)
    end_time_2= r2[0]
    print(end_time_2-end_time_1)

    # p1 = gevent.spawn(time_elapsed, obj_temp)
    # p2 = gevent.spawn(time_elapsed, obj_temp2)
    # gevent.joinall([p1, p2])
    # print(p1.value[0])
    # print(p2.value[0])








