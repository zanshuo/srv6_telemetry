#!/usr/bin/python

import json
import os
import sys
# print(sys.path)
f=open("../build/namespaceid_for_path.json",mode="w")
dict1={0:["2001::1","2002::2","2004::4","2006::6"]}
json.dump(dict1,f)
f.close

# f1=open("../build/namespaceid_for_path.json",mode="r")
# dict2=json.load(f1)
# print(dict2[str(0)])


# print(2**48/1000/1000/60/60/24/365)