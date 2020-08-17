#!/usr/bin/python3
from scapy.all import *
import bitstring
from time import sleep
def send_udld_func(sequence,flag):
    s = bitstring.pack('uintbe:32', sequence)
    str1=""
    for x in [0,8,16,24]:
        temp=s[x:x+8]
        str1=str1+chr(int(temp.hex,16))

    # s1 = bitstring.pack('uintbe:8', flag)
    str2=chr(flag)
    pkt = Ether()/LLC()/SNAP(OUI=0x00000C,code=0x0111)/Raw(load=" {1}\0\0\0\a\0\b{0}".format(str1,str2))
    sendp(pkt, iface="con-eth0",verbose=False)


if __name__ == "__main__":
    sequence = 1
    while(True):
        if sequence == 1:
            send_udld_func(1,2)
            sleep(0.1)
            send_udld_func(2,2)
            sleep(0.1)
            send_udld_func(3,2)
            sequence = 4
            sleep(0.1)

        else:
            send_udld_func(sequence,0)
            sequence=sequence+1
