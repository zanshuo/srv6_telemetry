#!/usr/bin/python3
import datetime
import json
from python_file import entry_control_thrift_shell
import os
import re
import bitstring
from ipaddr import IPv4Address, IPv6Address, AddressValueError

list1=list()
list2=list()
with open("build/time.json",mode="r") as f1:
    for line in f1:
        tmp1=json.loads(line)
        for x in tmp1.keys():
            tmp1[x] = datetime.datetime.strptime(tmp1[x],'%Y-%m-%d %H:%M:%S.%f')
        list1.append(tmp1)

for x in range(1,6):
    tmp1=list(list1[x].values())[0] - list(list1[0].values())[0]
    list2.append(tmp1)
f1.close()
# for x in list1[0].values():
#     print(datetime.datetime.strptime(x,'%Y-%m-%d %H:%M:%S.%f'))
# list2=[list1[x].values-list1[0] for x in range(1,6)]
# print(list2)
# s1=datetime.datetime.strptime('14:20:10.809','%H:%M:%S.%f')
# s2=datetime.datetime.strptime('14:20:21.822','%H:%M:%S.%f')
# print((s2-s1).microseconds)
# table_name,action_name,port,**kwargs
port = 9091
for x in list2:
    print(str(x.seconds * 10 ** 6 + x.microseconds))
    # entry_control_thrift_shell.table_add("export_timestamp_t","export_timestamp",port,match_field="",action=[x.seconds*10**6+x.microseconds,])
    # port=port+1
