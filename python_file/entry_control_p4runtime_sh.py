#!/usr/bin/python3
import json
from .p4runtime_sh import shell as sh
# from p4runtime_sh.bytes_utils import parse_value
#
# print(parse_value("1.1.1.1",32))
# sh.setup(
#     device_id=0,
#     grpc_addr='192.168.50.15:50051',
#     config=sh.FwdPipeConfig('build/telemetry.p4.p4info.txt', 'build/telemetry.json')
#     # (high, low)
#
# )
"""

"""


class Control_entry:
    def __init__(self,**kwargs):
        self.kwargs = kwargs
        # self.table_name=table_name
        # self.action_name=action_name
        try:
            self.connect=sh.TableEntry(self.kwargs["table_name"])(action=self.kwargs["action_name"])
        except:
            print("链接error")

    def table_insert(self):
        try:
            for match_field,match_field_value in self.kwargs["match"].items():
                self.connect.match[match_field] = match_field_value
            for action_field,action_value in self.kwargs["action"].items():
                self.connect.action[action_field] = action_value
            if self.kwargs["priority"] != None:
                self.connect.priority =self.kwargs["priority"]
            self.connect.insert()
        except :
            print("插入error")

    def table_modify(self,**kwargs):

            try:
                if kwargs["action"] != None:
                    for action_field, action_value in kwargs["action"].items():
                        self.connect.action[action_field] = action_value
                    self.connect.modify()
            except:
                print("修改error")


    def table_delete(self):
        try:
            self.connect.delete()
        except :
            print("删除error")


# te = sh.TableEntry('match_flow_ipv4').read()
# print(te)
# te.match['hdr.ip.ipv4.srcAddr'] = '0x0a010101&&&0xffff0000'
# te.match['hdr.ip.ipv4.dstAddr'] = '10.2.0.0/16'
# te.action['Namespaceid'] = '0x0000'
# te.action['trace_type'] = '0x6a0800'
# te.action['Flowid'] = '0x00000010'
# te.priority = 10

# te.match['hdr.ip.ipv4.srcAddr'] = '0x01010101&&&0xffff0000'
# te.match['hdr.ip.ipv4.dstAddr'] = '10.1.0.0/16'

# te.insert()
# te = sh.TableEntry('match_flow_ipv4')(action='insert_srh_dex')
# te.match['hdr.ip.ipv4.srcAddr'] = '0x0a020101&&&0xffff0000'
# te.match['hdr.ip.ipv4.dstAddr'] = '10.3.0.0/16'
# te.action['Namespaceid'] = '0x0000'
# te.action['trace_type'] = '0x6a0800'
# te.action['Flowid'] = '0x00000010'
# te.priority = 10



# temp = sh.TableEntry('match_flow_ipv4')(action='insert_srh_header')
# print(temp.action["Flag"])
# ts = sh.TableEntry("match_flow_ipv4")(action="insert_srh_header")
# ts.match['hdr.ip.ipv4.srcAddr'] = '0x010100000&&&0xffff0000'
# ts.match['hdr.ip.ipv4.dstAddr'] = '2.2.0.0/16'
# ts.action['Flag'] = '0x00'
# ts.action['num_segments'] = '3'
# ts.priority = 10
# ts.insert()
# ti = sh.TableEntry('match_flow_ipv4')(action='insert_srh_dex')
# ti.match['hdr.ip.ipv4.srcAddr'] = '0x0a010101&&&0xffff0000'
# ti.match['hdr.ip.ipv4.dstAddr'] = '10.2.0.0/16'
# ti.action['Namespaceid'] = '0x0000'
# ti.action['trace_type'] = '0x6a0800'
# ti.action['Flowid'] = '0x00000010'
# ti.priority = 100
# ti.modify()

# sh.TableEntry("MyIngress.match_flow_ipv4").read(lambda x:print(x))
# for x in sh.TableEntry("match_flow_ipv4").read():
#     print(x)
# te.match['hdr.ip.ipv4.srcAddr'] = '0x0a010101&&&0xffff0000'
# te.match['hdr.ip.ipv4.dstAddr'] = '10.2.0.0/16'
# te.action['Namespaceid'] = '0x0000'
# te.action['trace_type'] = '0x6a0800'
# te.action['Flowid'] = '0x00000010'
# te.priority = 10

# for y in sh.TableEntry("match_flow_ipv4").read():
#     print(y)
if __name__ == "__main__":
    dict1 = dict(table_name=None, action_name=None, match=None, action=None, priority=None)
    dict1['match'] = {"hdr.ip.ipv4.srcAddr":'0x0a010101&&&0xffff0000','hdr.ip.ipv4.dstAddr':'10.2.0.0/16'}
    dict1['action'] ={'Namespaceid':'0x0000','trace_type':'0x6a0800','Flowid':'0x00000010'}
    dict1['priority'] = 10
    dict1['table_name'] ="MyIngress.match_flow_ipv4"
    dict1['action_name']="insert_srh_dex"

    sh.setup(
        device_id=0,
        grpc_addr='192.168.50.15:50051',
        config=sh.FwdPipeConfig('build/telemetry.p4.p4info.txt', 'build/telemetry.json')

    )
    t1=Control_entry(**dict1)
    t1.table_insert()
    dict2={"action":None}
    t1.table_modify(**dict2)
    for x in sh.TableEntry("match_flow_ipv4").read():
        print(x)

    dict1["object"]=t1
    with open("entry.json",encoding="utf-8",mode="a") as f1:
        f1.write(json.dumps(dict1)+"\n")
    f1.close()


    sh.teardown()