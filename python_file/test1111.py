#!/usr/bin/python
import os
import bitstring
def generate_address_list(address_list,namespace_id,sequence):
        namespace_id = bitstring.pack('uintbe:16',namespace_id).hex
        sequence = bitstring.pack('uintbe:32',sequence).hex
        dex = "%s:0000:6a08:0100:0000:0000:%s:%s"%(namespace_id,sequence[:4],sequence[4:])
        address_list.append(dex)
        print(address_list)
generate_address_list(["2002::2","2001::1"],12,12)
