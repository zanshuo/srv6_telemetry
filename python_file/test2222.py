#!/usr/bin/python
from datetime import datetime


import datetime
from os import remove
import sqlite3
import json
import networkx as nx

# G = nx.Graph()                 
# G.add_node("r1")                                           
# G.add_weighted_edges_from([("r1","r2",12),("r2","r3",17),("r1","r3",14),("r2","r4",16),("r3","r4",20)])
# print(G.node)
# print(G._adj)
# path=nx.dijkstra_path(G, source="r1", target="r4")
# print(path)
s1=datetime.datetime.now()
print(s1,s1.second,s1.microsecond/1000000.0)