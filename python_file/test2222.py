#!/usr/bin/python
from os import remove
import sqlite3

# list1=[]
# list2=[1,2,3,4]
# flag =[tmp in list2 for tmp in list1]
# if False not in flag:
#     print("success")
# else:
#     print("fail")
list1=[1029, 1004, 1220, 1327, 999, 9649, 1420, 2968, 1559, 2708, 1860, 1043, 1572, 976, 1043, 1380, 1341, 1466, 1552, 1173, 1219, 1246, 826, 2063, 2084, 1531, 1791, 1096, 1340, 1210, 2973, 1365, 2082, 1281, 2005, 951, 1051, 1816, 'loss_packet', 'loss_packet', 'loss_packet', 'loss_packet', 'loss_packet', 'loss_packet', 'loss_packet']
list2=[577, 955, 779, 872, 667, 9775, 1270, 1445, 1480, 509, 806, 612, 915, 642, 620, 1638, 986, 700, 603, 782, 777, 687, 561, 3690, 1029, 779, 1135, 1311, 607, 516, 1037, 1077, 732, 660, 1002, 857, 731, 780, 514, 799, 826, 877, 883, 764, 852, 958, 759, 1103, 957, 685, 675, 1124]
# for tmp in list1:
#     if tmp == "loss_packet":
#         list1.remove(tmp)
print(len(list2))