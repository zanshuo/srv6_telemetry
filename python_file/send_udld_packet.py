#!/usr/bin/python3
from os import stat_result
from re import T
from scapy.all import *
import bitstring
from time import sleep
import time
from  parse_packet import Parse
from gevent import monkey;monkey.patch_all()
import gevent
from parse_packet import Parse

class Send_Udld_Packet:
    def __init__(self,sequence=None,flag=None):
        assert (isinstance(sequence,int )or sequence == None),"sequence参数类型错误"
        assert (isinstance(flag,int )or flag == None),"flag参数类型错误"
        self.sequence = sequence
        self.flag=flag
        self.sequence= 1
    
    @staticmethod
    def send_udld_packet(sequence,flag):
        """
            sequence:int range:0 < sequence < 2**32-1
            flag:int 0 or 2 
        """
        assert (isinstance(sequence,int )),"sequence参数类型错误"
        assert (isinstance(flag,int )),"flag参数类型错误"
        s = bitstring.pack('uintbe:32', sequence)
        str1=""
        for tmp in [0,8,16,24]:
            temp=s[tmp:tmp+8]
            str1=str1+chr(int(temp.hex,16))
        str2=chr(flag)
        pkt = Ether(type=0x8870)/LLC()/SNAP(OUI=0x00000C,code=0x0111)/Raw(load=" {1}\0\0\0\a\0\b{0}".format(str1,str2))
        sendp(pkt, iface="con-eth0",verbose=False)

   
    def send_udld_request(self):
        while True:
            if self.sequence == 2**32-1:
                self.sequence == 1 
            if self.sequence == 1:
                Send_Udld_Packet.send_udld_packet(1,2)
                sleep(0.3)
                self.sequence+=self.sequence
                Send_Udld_Packet.send_udld_packet(self.sequence,2)
                sleep(0.3)
                self.sequence += self.sequence
                Send_Udld_Packet.send_udld_packet(self.sequence,2)
                sleep(0.3)

                self.sequence +=self.sequence 
            elif self.sequence >= 4:
                Send_Udld_Packet.send_udld_packet(self.sequence,0)
                sleep(0.3)
                
                self.sequence +=1
            else:
                print("error")
                break
            
    
if __name__ == "__main__":
    parse_packet = Parse()
    send_packet = Send_Packet()
    p1=gevent.spawn(parse_packet.start)
    p2=gevent.spawn(send_packet.send_udld_request)

    # while True:
    #     if sequence == 2**32-1:
    #         sequence == 1      
    #     if sequence == 1:
    #         Send_Packet.send_udld_packet(1,2)
    #         sleep(0.3)
    #         Send_Packet.send_udld_packet(2,2)
    #         sleep(0.3)
    #         Send_Packet.send_udld_packet(3,2)
    #         sleep(0.3)
    #         sequence = 4
    #     elif sequence >= 4:
    #         Send_Packet.send_udld_packet(sequence,0)
    #         sleep(0.3)
    #         sequence +=1
    #     else:
    #         print("error")
    #         break

    Send_Packet.send_oam_probe_packet(["2006::6","2005::5","2003::3","2001::1","0001:0000:6800:0000:0000:0000:0000:0001"],1)
