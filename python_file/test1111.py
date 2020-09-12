#!/usr/bin/python

import json
import os
print(os.getcwd())
f=open("../build/namespaceid_for_path.json",mode="w")
dict1={1:["2001::1","2002::2","2004::4","2006::6"]}
json.dump(dict1,f)
f.close