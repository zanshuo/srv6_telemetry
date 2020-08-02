#include<core.p4>
#include<v1model.p4>
typedef bit<48> EthernetAddress;
typedef bit<128> IPv6Address;
header Ethernet{
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16> ethernetType;
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
    IPv6 ipv6;


}
struct metadata{

}
parser MyParser(packet_in pkt,out headers hdr,inout metadata meta,inout standard_metadata_t stdmeta){
    state start{
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethernetType){
            0x86dd:parse_ipv6;
            default:accept;

        }

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
    apply{
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
        pkt.emit(hdr.ipv6);

    }

}

V1Switch<headers, metadata>(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyUpdateChecksum(),MyDeparser()) main;
