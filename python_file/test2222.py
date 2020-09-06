#!/usr/bin/python
from re import L
import shelve
from multiprocessing import Process
import Queue
from concurrent.futures import ThreadPoolExecutor
import json
from goto import with_goto
import sqlite3
import test1111
def test1(queue):
    while True:
        queue.get()
        print("get data")
def test2(queue):
    for x in range(10):
        queue.put(x)
        print(x)
    
if __name__ == "__main__":
    # test1111.set_var("hahha")
    while True:
        print(test1111.get_var())