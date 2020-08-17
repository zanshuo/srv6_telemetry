#!/usr/bin/python3
from scapy.all import *
import bitstring
from time import sleep
class Send_Packet:
    def __init__(self,sequence=None,flag=None,address_list=None):
        assert (type(sequence) != None and type(sequence)!=int),"sequence参数类型错误"
        assert (type(flag) != None and type(sequence) != int), "flag参数类型错误"
        assert (type(address_list) != None and type(sequence) != list), "address_list参数类型错误"
        self.sequence = sequence
        self.flag=flag
        self.address_list=address_list

    @staticmethod
    def send_udld_packet(sequence,flag):
        """
            sequence:int range-> 0 < sequence < 2**32-1
            flag:int 0 or 2
        """
        assert (type(sequence) != None and type(sequence) != int), "sequence参数类型错误"
        assert (type(flag) != None and type(sequence) != int), "flag参数类型错误"
        s = bitstring.pack('uintbe:32', sequence)
        str1=""
        for tmp in [0,8,16,24]:
            temp=s[tmp:tmp+8]
            str1=str1+chr(int(temp.hex,16))
        str2=chr(flag)
        pkt = Ether()/LLC()/SNAP(OUI=0x00000C,code=0x0111)/Raw(load=" {1}\0\0\0\a\0\b{0}".format(str1,str2))
        sendp(pkt, iface="con-eth0",verbose=False)

    @staticmethod
    def send_oam_probe_packet(address_list):
        """
            address_list:segment list

        """
        assert (type(address_list) != None and type(address_list) != list), "address_list参数类型错误"
        pkt = Ether()/ IPv6(plen=48+16*len(address_list), src="2555::255", dst="2001::1") / \
            IPv6ExtHdrSegmentRouting(nh=41,len=len(address_list)*2, segleft=len(address_list)-2, lastentry=len(address_list)-1, oam=1,
             addresses=address_list)/\
            IPv6(plen=0,  fl=1,src="2555::255", dst="2555::255")
        sendp(pkt, iface="con-eth0",verbose=False)
    def send_packet(self):
        if type(self.sequence) == int and type(self.flag) == int:
            while True:
                self.send_udld_packet(self.sequence,self.flag)
        elif type(self.address_list) == list :
            while True:
                self.send_oam_probe_packet(self.address_list)

if __name__ == "__main__":
    sequence = 1
    while True:
        if sequence == 1:
            Send_Packet.send_udld_packet(1,2)
            sleep(0.3)
            Send_Packet.send_udld_packet(2,2)
            sleep(0.3)
            Send_Packet.send_udld_packet(3,2)
            sleep(0.3)
            sequence = 4
        elif sequence >= 4:
            Send_Packet.send_udld_packet(sequence,0)
            sleep(0.3)
            sequence +=1
        else:
            print("error")
            break

