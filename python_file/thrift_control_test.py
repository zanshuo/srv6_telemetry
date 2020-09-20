#!/usr/bin/python
import sys
# sys.path.insert(0,"../behavioral-model/tools/")
# sys.path.insert(1,"../behavioral-model/targets/simple_switch")
from sync_time import thrift_connect

# from sync_time import thrift_connect


if __name__ == "__main__":
        obj1=thrift_connect(9090,"../build/telemetry.json")
        #register_read MyIngress.interface_packet_length 2
        obj1.do_register_read("MyIngress.interface_packet_length 2")
        obj1.do_register_write("MyIngress.link_status 0 0")
        # mc_mgrp_create 2
        # obj1.do_mc_mgrp_create("1")
        # # mc_node_create 0 2 3
        # obj1.do_mc_node_create("0 2 3")
        # # mc_node_associate 1 0
        # obj1.do_mc_node_associate("1 0")
        # # mirroring_add 233 255
        # obj1.do_mirroring_add ("233 255")
        # # table_dump("MyIngress.ipv6_forward_t")
        # obj1.do_table_dump ("MyIngress.ipv6_forward_t")
        # #table_add insert_ipv6_forward_t insert_ipv6_forward 2002::2/128 => 2
        # obj1.do_table_add("insert_ipv6_forward_t insert_ipv6_forward 2002::2/128 => 2")