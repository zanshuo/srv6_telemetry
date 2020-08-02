#!/usr/bin/python3


import os
import re


def table_add(table_name,action_name,port,**kwargs):
    if "match_field" not in kwargs.keys() or "action" not in kwargs.keys():
        print("参数错误")
        return False,"参数错误"
    match_field=""
    action=""
    for temp in kwargs["match_field"]:
        match_field =match_field+" "+str(temp)
    for temp in kwargs["action"]:
        action = action+" "+str(temp)
    command="table_add {0} {1} {2} => {3}".format(table_name,action_name,match_field,action)
    echo_display=os.popen("""simple_switch_CLI --thrift-port {0} <<EOF
                              {1}
                             EOF""".format(port,command)).read()
    if "Invalid runtime data" in echo_display:
        print("传入参数格式错误，插入entry失败")
        return False,"传入参数格式错误，插入entry失败"
    elif "Error" in echo_display:
        print("传入参数错误,插入entry失败")
        return False,"传入参数错误,插入entry失败"

    elif "DUPLICATE_ENTRY" in echo_display:
        print("entry已经存在,插入entry失败")
        return False,"entry已经存在,插入entry失败"
    elif "Entry has been added" in echo_display:
        temp=re.match(".*Entry has been added with handle\s*(\d*)",echo_display.split("\n")[-3]).groups()
        return True,temp[0]
    else:
        return False,"未知错误"
def table_delete(port,table_name,entry_number):
    command = "table_delete {0} {1}".format(table_name, entry_number)
    echo_display = os.popen("""simple_switch_CLI --thrift-port {0} <<EOF
                                  {1}
                                 EOF""".format(port, command)).read()
    if "INVALID_HANDLE" in echo_display:
        print("无此entry")
        return False,"无此entry项"
    if "Error: Bad format for entry handle" in echo_display:
        print("entry序号格式错误")
        return  False,"entry序号格式错误"
    if "Error: Invalid table name" in echo_display:
        print("table名称错误")
        return  False,"table名称错误"
    if "Deleting entry" in echo_display:
        print("删除entry成功")
        return True,"成功"
    else:
        print("未知错误")
        return False,"未知错误"
def table_modify(port,table_name,table_action,entry_number,*action):
    temp=""
    for x in action:
        temp=temp+x
    command = "table_modify {0} {1} {2} => {3}".format(table_name,table_action,entry_number,temp)
    echo_display = os.popen("""simple_switch_CLI --thrift-port {0} <<EOF
                                     {1}
                                    EOF""".format(port, command)).read()

    if "Error" in echo_display:
        print("传入参数错误，修改entry失败")
        return False,"传入参数错误，修改entry失败"
    if "INVALID_HANDLE" in echo_display:
        print("无此entry")
        return False,"无此entry"
    if "Modifying entry" in echo_display:
        print("修改entry成功")
        return True,"修改entry成功"
    else:
        return False,"未知错误"
def table_search(port,table_name):
    echo_display = os.popen("""simple_switch_CLI --thrift-port {0} <<EOF
                                        {1}
                                       EOF""".format(port, table_name)).read()


# table_add drop_pkt drop =>
table_add("drop_pkt","drop",9090,**dict1)
# def table_modify():
#     pass
# def table_delete():
#     pass
# def table_search():
#
# def entry_search():

