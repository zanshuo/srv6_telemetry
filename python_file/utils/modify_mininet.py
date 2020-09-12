#!/usr/bin/env python2
from mininet.link import TCLink
class Modify_Mininet:
    def __init__(self,net):
        self.net=net
    def handle(self,command):
        pass
    #modify_link_bw r1-eth2 r2-eth1 100
    def modify_link_bw(self,command):
        command_list = command.split()
        if len(command_list) != 4:
            return "wrong number of argument"
        else:
            try:
                link=self.net.linksBetween(self.net.get(command_list[1].split("-")[0]),self.net.get(command_list[2].split("-")[0]))
            except Exception as e:
                return "no this node:"+str(e)
                
            if len(link) == 1:
                link[0].intf1.config(bw=command_list[3])
                link[0].intf2.config(bw=command_list[3])
            elif len(link) >1:
                for temp in link:
                    if command_list[1] in [temp.intf1.name,temp.intf2.name] and command_list[2] in [temp.intf1.name,temp.intf2.name]:
                        temp.intf1.config(bw=command_list[3])
                        temp.intf2.config(bw=command_list[3])
                return "success"
            else:
                return "no link"
    #del_link r1-eth2 r2-eth1          
    def del_link(self,command):
        command_list = command.split()
        if len(command_list) != 3:
            return "wrong number of argument"
        else:
            try:
                link=self.net.linksBetween(self.net.get(command_list[1].split("-")[0]),self.net.get(command_list[2].split("-")[0]))
            except Exception as e:
                return "no this node:"+str(e)
            if len(link) == 1:
                self.net.delLink(link[0])
            elif len(link) >1:
                for temp in link:
                    if command_list[1] in [temp.intf1.name,temp.intf2.name] and command_list[2] in [temp.intf1.name,temp.intf2.name]:
                        self.net.delLink(temp)
                return "success"
            else:
                return "no link"
    #del_node r2
    def del_node(self,command):
        command_list = command.split()
        if len(command_list) != 2:
            return "wrong number of argument"
        else:
            try:
                self.net.delSwitch(self.net.get(command_list[1]))
            except Exception as e:
                return "no this node:"+str(e)
    #modify_link_status r1-eth1 r2-eth2 up
    def modify_link_status(self,command):
        command_list = command.split()
        if len(command_list) != 4:
            return "wrong number of argument"
        else:
            try:
                link=self.net.linksBetween(self.net.get(command_list[1].split("-")[0]),self.net.get(command_list[2].split("-")[0]))
            except Exception as e:
                return "no this node:"+str(e)
            if len(link) == 1:
                link[0].intf1.ifconfig(command_list[3])
                link[0].intf2.ifconfig(command_list[3])
            elif len(link) >1:
                for temp in link:
                    if command_list[1] in [temp.intf1.name,temp.intf2.name] and command_list[2] in [temp.intf1.name,temp.intf2.name]:
                       temp.intf1.ifconfig(command_list[3])
                       temp.intf2.ifconfig(command_list[3]) 
                return "success"
            else:
                return "no link"
    
    def add_link(self,command):
        #add_link r1-eth1 r2-eth2 bw=1000 delay=12ms
        command_list = command.split()
        if len(command_list)<4 or len(command_list)>5:
            return "wrong number of argument"
        elif command_list[3].split("=")[0] !="bw":
            return "need to set bw"
        elif len(command_list) == 4:
            self.net.addLink(self.net.get(command_list[1].split("-")[0]),self.net.get(command_list[2].split("-")[0]),int(command_list[1].split("-")[1][3:]),
            int(command_list[2].split("-")[1][3:]),cls=TCLink,bw=int(command_list[3].split("=")[1]))
            return "success add link(bw)"
        elif len(command_list) == 5:
            self.net.addLink(self.net.get(command_list[1].split("-")[0]),self.net.get(command_list[2].split("-")[0]),int(command_list[1].split("-")[1][3:]),
            int(command_list[2].split("-")[1][3:]),cls=TCLink,bw=int(command_list[3].split("=")[1]),delay=command_list[4].split("=")[1])  
            return "success add link(bw,delay)"    
        # self.addLink(sw1_name, sw2_name,
        #                 port1=sw1_port, port2=sw2_port,max_queue_size=link['max_queue_size'],
        #                 delay=link['latency'], bw=int(link['bandwidth'])
    def add_node(self):
        pass                    