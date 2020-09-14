#!/usr/bin/python
import sqlite3

# list1=[]
# list2=[1,2,3,4]
# flag =[tmp in list2 for tmp in list1]
# if False not in flag:
#     print("success")
# else:
#     print("fail")
conn=sqlite3.connect("../db/telemetry.db")
cursor = conn.cursor()
cursor.execute("select src,export_timestap,export_transit_delay,export_packet_length from data_list where namespace_id=%d and sequencenumber=%d and flowid=%d"%(10,20,20))
values=cursor.fetchall()
print(values)