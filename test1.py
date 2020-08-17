#!/usr/bin/python3
import time
from concurrent.futures import ThreadPoolExecutor
# from gevent import monkey;monkey.patch_all()
import gevent
from multiprocessing import Pool,Process
import os
import subprocess
index = 0

f1=open("./thrift_command/r1.txt")
for line in f1:
    if "export"