#include<core.p4>
#include<v1model.p4>
typedef bit<48> EthernetAddress;
typedef bit<128> IPv6Address;
header Ethernet{
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16> ethernetType;
}
header UDLD_Header{
    bit<8> DSAP;
    bit<8> SSAP;
    bit<8> cntl;
    bit<24> org_code;
    bit<16> protocol_type;
    bit<3> version;
    bit<5> Opcode;
    bit<8> Flags;
    bit<16> checksum;
}
header IPv6{
    bit<4> version;
    bit<8> class;
    bit<20> flowlabel;
    bit<16> payloadlength;
    bit<8> nextheader;
    bit<8> hoplimit;
    IPv6Address srcAddr;
    IPv6Address dstAddr;
}
struct headers{
    Ethernet ethernet;
    UDLD_Header udld_header;
    IPv6 ipv6;

}
struct metadata{

}
parser MyParser(packet_in pkt,out headers hdr,inout metadata meta,inout standard_metadata_t stdmeta){
    state start{
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethernetType){
            0x86dd:parse_ipv6;
            default:parse_udld;

        }

    }
        state parse_udld{
        bit<24> code= pkt.lookahead<UDLD_Header>().org_code;
        bit<16> p_type = pkt.lookahead<UDLD_Header>().protocol_type;
        transition select(code,p_type){
            (0x00000c,0x0111):parse_udld_header;
            (_,_):reject;
        }
    }
     state parse_udld_header{
        pkt.extract(hdr.udld_header);
        transition accept;
    }
    state parse_ipv6{
        pkt.extract(hdr.ipv6);
        transition accept;
    }
}
control MyIngress(inout headers hdr,inout metadata meta,inout standard_metadata_t stdmeta){
      action origin_ip_forward(bit<9> port){
        stdmeta.egress_spec = port;

    }
    action udld_forward(bit<16> group)
    {
        stdmeta.mcast_grp = group;
    }

    action drop(){
        mark_to_drop(stdmeta);
    }
     table ipv6_forward_t{
        key = {
            hdr.ipv6.dstAddr:lpm;
        }
        actions = {
            drop;
            origin_ip_forward;
        }
    }
    table udld_forward_t{
        key = {
                hdr.udld_header.Opcode:exact;

        }
        actions={
            origin_ip_forward;
            udld_forward;
        }
    }
    apply{
        if (hdr.udld_header.isValid()){
            udld_forward_t.apply();

        }
        ipv6_forward_t.apply();
    }
}
control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t stdmeta){
        apply{
        }
}
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {


    }
}


control MyUpdateChecksum(inout headers hdr, inout metadata meta) {
    apply {


    }
}

control MyDeparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.udld_header);
        pkt.emit(hdr.ipv6);

    }

}

V1Switch<headers, metadata>(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyUpdateChecksum(),MyDeparser()) main;
