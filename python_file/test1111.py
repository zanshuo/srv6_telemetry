#!/usr/bin/python
# encoding: utf-8
import json
import os
import sys
from watchdog.observers import Observer
from watchdog.events import *
import time
# print(sys.path)
# f=open("../build/namespaceid_for_path.json",mode="w")
# dict1={0:["2001::1","2002::2","2004::4","2006::6"]}
# json.dump(dict1,f)
# f.close

# # f1=open("../build/namespaceid_for_path.json",mode="r")
# # dict2=json.load(f1)
# # print(dict2[str(0)])
from threading import Thread,Event
a = "../build/peer.json"
b="../build/config.json"
class test:
    def start(self):
            path = "../build/peer.json"
            path1="../build/config.json"
            event_handler = self.MyHandler()
            observer = Observer()
            observer.schedule(event_handler, path, recursive=True)
            observer.start()
            observer1=Observer()
            observer1.schedule(event_handler, path1, recursive=True)
            observer1.start()
            while True:
                pass
    
    class MyHandler(FileSystemEventHandler):
        def on_modified(self, event):
            print("文件 change %s"%event.src_path)
    
        def on_created(self, event):
            print("file create %s" % event.src_path)
        
 
if __name__ == "__main__":
    obj1=test()
    obj1.start()