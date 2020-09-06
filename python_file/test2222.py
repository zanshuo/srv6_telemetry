#!/usr/bin/python
import shelve
from multiprocessing import Process,Queue
from concurrent.futures import ThreadPoolExecutor
import json
from goto import with_goto
import sqlite3
def shengchan(queue):
    sequence =1
    flow_id = 1
    for i in range(0,10):
        sequence+=1
        flow_id+=1
        queue.put([sequence,flow_id])

if __name__ == "__main__":
    # conn=sqlite3.connect("./db/telemetry.db")
    # cursor = conn.cursor()
    # cursor.execute("select COUNT(*) from metric_list")
    # # cursor.execute("create table data_list(src varchar(40),tracetype varchar(40),namespace_id smallint,reserved tinyint,sequencenumber int,flowid int,flags smallint,\
    # #                 export_ingress_port smallint,export_egress_port smallint,export_timestap bigint,export_transit_delay bigint,export_dequene_length int,export_enquene_length int,export_packet_length int)")
    # # cursor.execute("create table metric_list(src varchar(40),dst varchar(40),total_delay bigint)")
    # # cursor.execute("insert into metric_list values('%s','%s','%d')"%("r1","r2",3111))
    # # cursor.execute("select src,export_timestap,export_transit_delay from data_list where namespace_id = 0 and sequencenumber=1")
    # values=cursor.fetchall()

    # print(values)
    # cursor.close()
    # # conn.commit()
    list1=[1,2]
    list2=list1[:]
    list2[0]=11
    print(list1,list2)    