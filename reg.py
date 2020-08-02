import os
import re


def get_register(thrift_port,flow_id):
    ss=os.popen("""
    simple_switch_CLI --thrift-port {0} <<EOF \n 
           register_read MyIngress.dex_sequencenumber {1} \n 
     EOF
    """.format(thrift_port,flow_id))
    for line in ss:
        if "=" in line:
            temp=re.search('.*=\s*([0-9]*)',line).groups()[0]
            return temp


def set_mirror(thrift_port):
    os.system("""
    simple_switch_CLI --thrift-port {0} <<EOF \n
      mirroring_add 233 255 \n
      EOF
    """.format(thrift_port))



