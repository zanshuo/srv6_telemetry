/**
version:1.0
date:2020-7-3
author:wangshuo
*/

/**限制
1.clone_to_cpu只能出现一次
2.所以去除头部应该在egress中进行
3.lpm只能出现一次*/
#include<core.p4>
#include<v1model.p4>
#define ex_udp_srcPort 55555
#define ex_udp_dstPort 55551
#define Max_Hop 10
#define CPU_PORT 255

typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address;
typedef bit<128> IPv6Address;


header Ethernet{
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16> ethernetType;
}

header IPv4{
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    IPv4Address srcAddr;
    IPv4Address dstAddr;
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
header SRH_h{
    bit<8> nextheader;
    bit<8> hdrextlen;
    bit<8> routingtype;
    bit<8> segmentleft;
    bit<8> lastentry;
    bit<8> flags;
    bit<16> tag;
}

header UDP_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udplength;
    bit<16> checksum;
}
header DEX_h {
    bit<16> namespace_id;
    bit<16> flags;
    bit<24> tracetype;
    bit<8> reserved;
    bit<32> flowid;
    bit<32> sequencenumber;
}
header segment{
    bit<128> data;
}
header_union IP{
    IPv4 ipv4;
    IPv6 ipv6;
}
header Data_list_h{
    bit<32> data;
}


struct headers{
    Ethernet ethernet;
    IPv6 insert_ipv6;
    UDP_h export_udp;
    SRH_h insert_srh;
    segment[Max_Hop] segment_list;
    DEX_h dex;
    Data_list_h[24] data_list_h;
    IP ip;

}

struct required_meta{

    bit<9> ingress_port;
    bit<9> egress_port;

}
struct metadata{
    required_meta user_mata;



}
parser MyParser(packet_in pkt,out headers hdr,inout metadata meta,inout standard_metadata_t stdmeta){
    state start{
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethernetType){
            0x0800:parse_ipv4;
            0x86dd:parse_ipv6;
            default:accept;
        }
    }
    state parse_ipv4{
        pkt.extract(hdr.ip.ipv4);
        transition accept;
    }
    state parse_ipv6{

        bit<8> nexthdr = pkt.lookahead<IPv6>().nextheader;
        transition select(nexthdr){
            43:parse_insert_ipv6;
            default:parse_origion_ipv6;
        }
    }
    state parse_insert_ipv6{
        pkt.extract(hdr.insert_ipv6);
        transition parse_srh;
    }
    state parse_origion_ipv6{
        pkt.extract(hdr.ip.ipv6);
        transition accept;
    }
    state parse_srh{
        pkt.extract(hdr.insert_srh);
        transition select(hdr.insert_srh.flags){
            0x20 &&& 0x20:parse_srh_list;
            default:parse_origion_srh_list;
        }

    }
    state parse_srh_list{
        pkt.extract(hdr.segment_list.next);
        bool flag=(bit<32>) hdr.segment_list.lastIndex == (bit<32>)( hdr.insert_srh.lastentry - 1);
        transition select(flag){
            true:parse_srh_dex;
            default:parse_srh_list;

        }
    }
    state parse_origion_srh_list{
        pkt.extract(hdr.segment_list.next);
        bool flag = (bit<32>) hdr.segment_list.lastIndex == (bit<32>)hdr.insert_srh.lastentry;
        transition select(flag){
            true:parse_upperlay;
            default:parse_origion_srh_list;
        }
    }
    state parse_srh_dex{
        pkt.extract(hdr.dex);
        transition parse_upperlay;
    }
    state parse_upperlay{
        transition select(hdr.insert_srh.nextheader){
            4:parse_ipv4;
            41:parse_ipv6;
            default:accept;
        }
    }
}

control MyIngress(inout headers hdr,inout metadata meta,inout standard_metadata_t stdmeta){
     register<bit<32>>(512) dex_sequencenumber;

    /**插入的IPV6转发*/

    action insert_ipv6_forward(bit<9> port){
        stdmeta.egress_spec = port;
        hdr.insert_ipv6.hoplimit = hdr.insert_ipv6.hoplimit - 1;
        meta.user_mata.ingress_port = stdmeta.ingress_port;
        meta.user_mata.egress_port = port;

    }
//    /**原始IPV4转发*/
//    action ipv4_forward(bit<9> port){
//        stdmeta.egress_spec = port;
//
//    }
// 原始数据包的转发
    action origin_ip_forward(bit<9> port){
        stdmeta.egress_spec = port;
        meta.user_mata.ingress_port = stdmeta.ingress_port;
        meta.user_mata.egress_port = port;

    }
//    /**原始IPV6转发*/
//    action ipv6_forward(bit<9> port){
//        stdmeta.egress_spec = port;
//
//    }

    /**丢弃包*/
    action drop(){
        mark_to_drop(stdmeta);
    }

    /**插入ipv6头部*/
    action insert_ipv6_header(IPv6Address src){

        hdr.insert_ipv6.setValid();
        hdr.ethernet.ethernetType = 0x86dd;
        hdr.insert_ipv6.version =  6;
        hdr.insert_ipv6.class = 0;
        hdr.insert_ipv6.flowlabel = 0;
        if (hdr.ip.ipv4.isValid()){
           hdr.insert_ipv6.payloadlength = hdr.ip.ipv4.totalLen ;
        }
        else{
            hdr.insert_ipv6.payloadlength = hdr.ip.ipv6.payloadlength + 40;
        }
        hdr.insert_ipv6.nextheader = 43;
        hdr.insert_ipv6.hoplimit = 255;
        hdr.insert_ipv6.srcAddr=src;

    }

    /**插入SRH*/
    action insert_srh_header(bit<8> Flag,bit<8> num_segments){

        hdr.insert_srh.setValid();
        if (hdr.ip.ipv4.isValid())
        {
            hdr.insert_srh.nextheader = 4;
        }
        else{
            hdr.insert_srh.nextheader = 41;
        }
        //不包括前面的8字节，且是8的整数倍，所以是num_segemnt*16/8
        hdr.insert_srh.hdrextlen =  num_segments * 2;
        hdr.insert_srh.routingtype = 4;
        //flag来标记该包是否包含dex
        if(Flag[5:5] == 1)
        {
            hdr.insert_srh.segmentleft = num_segments - 2;
        }
        else
        {
            hdr.insert_srh.segmentleft = num_segments -1;
        }
        hdr.insert_srh.lastentry = num_segments - 1;
        hdr.insert_srh.flags = Flag;
        hdr.insert_srh.tag = 0;
        hdr.insert_ipv6.payloadlength = hdr.insert_ipv6.payloadlength + (bit<16>)(hdr.insert_srh.hdrextlen*8)+8;

    }
    /**插入1到6个segment*/
       action insert_srh_1(IPv6Address s1){
       hdr.insert_ipv6.dstAddr = s1;
       hdr.segment_list[0].setValid();
       hdr.segment_list[0].data = s1;

      }
      action insert_srh_2(IPv6Address s1,IPv6Address s2){
       hdr.insert_ipv6.dstAddr = s1;
       hdr.segment_list[0].setValid();
       hdr.segment_list[0].data = s2;
       hdr.segment_list[1].setValid();
       hdr.segment_list[1].data = s1;
      }
     action insert_srh_3(IPv6Address s1,IPv6Address s2,IPv6Address s3){
       hdr.insert_ipv6.dstAddr = s1;
       hdr.segment_list[0].setValid();
       hdr.segment_list[0].data = s3;
       hdr.segment_list[1].setValid();
       hdr.segment_list[1].data = s2;
       hdr.segment_list[2].setValid();
       hdr.segment_list[2].data = s1;
    }


    action insert_srh_4(IPv6Address s1,IPv6Address s2,IPv6Address s3,IPv6Address s4){
       hdr.insert_ipv6.dstAddr = s1;
       hdr.segment_list[0].setValid();
       hdr.segment_list[0].data = s4;
       hdr.segment_list[1].setValid();
       hdr.segment_list[1].data = s3;
       hdr.segment_list[2].setValid();
       hdr.segment_list[2].data = s2;
       hdr.segment_list[3].setValid();
       hdr.segment_list[3].data = s1;

    }
    action insert_srh_5(IPv6Address s1,IPv6Address s2,IPv6Address s3,IPv6Address s4,IPv6Address s5){
           hdr.insert_ipv6.dstAddr = s1;
           hdr.segment_list[0].setValid();
           hdr.segment_list[0].data = s5;
           hdr.segment_list[1].setValid();
           hdr.segment_list[1].data = s4;
           hdr.segment_list[2].setValid();
           hdr.segment_list[2].data = s3;
           hdr.segment_list[3].setValid();
           hdr.segment_list[3].data = s2;
           hdr.segment_list[4].setValid();
           hdr.segment_list[4].data = s1;

    }
    action insert_srh_6(IPv6Address s1,IPv6Address s2,IPv6Address s3,IPv6Address s4,IPv6Address s5,IPv6Address s6){
           hdr.insert_ipv6.dstAddr = s1;
           hdr.segment_list[0].setValid();
           hdr.segment_list[0].data = s6;
           hdr.segment_list[1].setValid();
           hdr.segment_list[1].data = s5;
           hdr.segment_list[2].setValid();
           hdr.segment_list[2].data = s4;
           hdr.segment_list[3].setValid();
           hdr.segment_list[3].data = s3;
           hdr.segment_list[4].setValid();
           hdr.segment_list[4].data = s2;
           hdr.segment_list[5].setValid();
           hdr.segment_list[5].data = s1;

    }

    /**插入DEX
        namespaceid:用来标记一组数据路径，控制器通过这个namespaceid能唯一标识一组路径，比如1对应路径是s1-s2-s4-s5.
        trace_type:感兴趣流需要采集的信息,协议标准
        flowid:用来标记流，该取值应该是0到511，这样通过flowid来读取register dex_sequencenumber里的信息
        sequencenumber:使用register类型来设置，flow-id作为index,假设flow-id为1，那么dex_sequencenumber[1]里存的就是该flow的包的数量
                       每当匹配一个感兴趣流，该数值就会加一，并赋值给hdr.dex.sequencenumber，同时写入dex_sequencenumber中
                       控制器应该监视该值是否会overflow,必要时候在控制层面清零。
    */
    action insert_srh_dex(bit<16> Namespaceid,bit<24> trace_type, bit<32> Flowid){
           hdr.dex.setValid();
           hdr.dex.namespace_id= Namespaceid;
           hdr.dex.flags = 0;
           hdr.dex.tracetype = trace_type;
           hdr.dex.reserved = 0;
           hdr.dex.flowid=Flowid;
           bit<32> temp;
           dex_sequencenumber.read(temp,Flowid);
           hdr.dex.sequencenumber = temp+1;
           dex_sequencenumber.write(Flowid,temp+1);

    }



    /**transit节点转发动作*/
    action transit_srh(){
        if(hdr.insert_ipv6.hoplimit != 255)
        {
            hdr.insert_srh.segmentleft = hdr.insert_srh.segmentleft - 1;
            bit<8> SL = hdr.insert_srh.segmentleft;
            hdr.insert_ipv6.dstAddr = hdr.segment_list [SL].data;
        }
    }

//弹出insert_ipv6和insert_srh
    action pop_srh(){
        hdr.insert_ipv6.setInvalid();
        hdr.insert_srh.setInvalid();
        hdr.ethernet.ethernetType=0x0800;
        hdr.segment_list[0].setInvalid();
        hdr.segment_list[1].setInvalid();
        hdr.segment_list[2].setInvalid();
        hdr.segment_list[3].setInvalid();
        hdr.segment_list[4].setInvalid();
        hdr.segment_list[5].setInvalid();
        hdr.dex.setInvalid();
    }
    /**发到控制器，IOAM数据*/
    action clone_to_cpu(){

        clone3<metadata>(CloneType.I2E, 233, meta);
    }
    /**匹配外层ipv6地址，进行转发*/
    table insert_ipv6_forward_t{
        key = {
            hdr.insert_ipv6.dstAddr:lpm;
        }
        actions = {
        drop;
        insert_ipv6_forward;
        }
    }
    /**匹配原始ipv4地址，进行转发*/
    table ipv4_forward_t{
        key = {
            hdr.ip.ipv4.dstAddr:lpm;
        }
        actions = {
            drop;
            origin_ip_forward;
        }
    }
    /**匹配原始ipv6地址，进行转发*/
    table ipv6_forward_t{
        key = {
            hdr.ip.ipv6.dstAddr:lpm;
        }
        actions = {
            drop;
            origin_ip_forward;
        }
    }
    /**丢弃包*/
    table drop_pkt{
        actions = {drop;}
    }
    /**查找原始ipv4目的地址，匹配后进如sr domain进行插入ipv6和srh动作*/
    table ipv4_insert_match{
        key = {
            hdr.ip.ipv4.dstAddr:lpm;
        }
        actions = {
            insert_ipv6_header;
            NoAction;
        }

    }
     /**查找原始ipv6目的地址，匹配后进如sr domain进行插入ipv6和srh动作*/
    table ipv6_insert_match{
        key = {
            hdr.ip.ipv6.dstAddr:lpm;
        }
        actions = {
            insert_ipv6_header;
            NoAction;
        }

    }
    table srv6_control_match{
        key = {
            hdr.insert_ipv6.dstAddr:exact;
        }
        actions = {
              NoAction;

        }
    }
    /**定义需要上传oam信息的流，一旦匹配感兴趣流，生成dex数据使用insert_srh_dex这个动作，里面包含namespace-id,flow-id,trace-type
    当只是修改感兴趣流的路径时候，使用insert_srh_header这个动作*/
    direct_counter(CounterType.packets_and_bytes) match_flow_ipv4_counter;
    table match_flow_ipv4{
        key = {
            hdr.ip.ipv4.srcAddr:ternary;
            hdr.ip.ipv4.dstAddr:lpm;

        }
        actions = {
            insert_srh_dex;
            insert_srh_header;

        }
        counters = match_flow_ipv4_counter;
    }

    direct_counter(CounterType.packets_and_bytes) match_flow_ipv6_counter;
    table match_flow_ipv6{
        key = {
            hdr.ip.ipv6.srcAddr:ternary;
            hdr.ip.ipv6.dstAddr:lpm;


        }
        actions = {
            insert_srh_dex;
            insert_srh_header;

        }
        counters=match_flow_ipv6_counter;
    }
     /**插入srh头部，分为两种插入普通srh头部和带dex的srh头部，这两个区别在于flag和segmentleft*/
    table insert_srh_header_t{
        key = {
            hdr.dex.isValid():exact;
            hdr.dex.namespace_id:optional;//optional


        }
        actions = {
            insert_srh_header;
        }

    }
    /**当只是修改path而不需要添加dex时候使用以下两个table*/
    table insert_segment_list_change_path_ipv6{
        key = {
            hdr.ip.ipv6.srcAddr:ternary;
            hdr.ip.ipv6.dstAddr:lpm;

        }
        actions ={
               insert_srh_1;
               insert_srh_2;
               insert_srh_3;
               insert_srh_4;
               insert_srh_5;
               insert_srh_6;
        }

    }
      table insert_segment_list_change_path_ipv4{
        key = {
            hdr.ip.ipv4.srcAddr:ternary;
            hdr.ip.ipv4.dstAddr:lpm;

        }
        actions ={
               insert_srh_1;
               insert_srh_2;
               insert_srh_3;
               insert_srh_4;
               insert_srh_5;
               insert_srh_6;
        }

    }
    /**根据namespace_id来插入相应路径对应的segment_list,默认如果无dex区域，走控制器设定的全局默认路径*/
    table insert_segment_list{
        key = {
            hdr.dex.isValid():exact;
            hdr.dex.namespace_id:optional;//optional

        }
        actions = {
               insert_srh_2;
               insert_srh_3;
               insert_srh_4;
               insert_srh_5;
               insert_srh_6;
        }
    }
    /**复制到controller*/
    table clone_to_cpu_t{
        actions = {clone_to_cpu;}
    }

    /**transit节点操作*/
    table transit_srh_t{
        actions = {transit_srh;}
    }
    /**末节点弹出srh操作*/
    table pop_srh_t{
        actions = {pop_srh;}
    }
    table drop_pkt1{
        actions ={
            drop;
        }
    }
//    table default_forward{
//        actions = {
//          origin_ip_forward;
//        }
//    }

    apply{
         /**这是头结点的插入操作*/
        if(!hdr.insert_ipv6.isValid() && !hdr.insert_srh.isValid()){
          if (hdr.ip.ipv4.isValid() || hdr.ip.ipv6.isValid() ){
                ipv4_insert_match.apply();
                ipv6_insert_match.apply();
                if(hdr.insert_ipv6.isValid())
                {
                   match_flow_ipv4.apply();
                   match_flow_ipv6.apply();
                   if(hdr.insert_srh.isValid())
                   {
                      insert_segment_list_change_path_ipv6.apply();
                      insert_segment_list_change_path_ipv4.apply();
                   }
                   else
                   {
                     insert_srh_header_t.apply();
                     insert_segment_list.apply();
                   }

//                   insert_ipv6_forward_t.apply();
               }
               else{
                     drop_pkt.apply();
               }
          }
          else{
                drop_pkt.apply();
          }
        }

//         default_forward.apply();


//        /**复制数据包*/
//        if(hdr.dex.isValid())
//        {
//           clone_to_cpu_t.apply();
//        }
       /**进行srv6的转发和pop操作*/
        if(hdr.insert_ipv6.isValid() && hdr.insert_srh.isValid()){
            if(srv6_control_match.apply().hit ){
               if(hdr.dex.isValid()){
                clone_to_cpu_t.apply();
               }
            /**这是pop操作*/
                if (hdr.insert_srh.segmentleft == 0){
                //等于255说明是刚插入的头部，不需要进行pop操作
                        if(hdr.insert_ipv6.hoplimit != 255){
                                 pop_srh_t.apply();
                              if(hdr.ip.ipv4.isValid() )
                              {
                                ipv4_forward_t.apply();
                              }
                              else if (hdr.ip.ipv6.isValid() ){
                                 ipv6_forward_t.apply();

                              }
                              else{
                                  drop_pkt1.apply();

                             }
                        }
                        else{
                            insert_ipv6_forward_t.apply();
                        }

                  }

                  else{
                           if(hdr.insert_srh.lastentry >(hdr.insert_srh.hdrextlen/2)-1 ||
                           hdr.insert_srh.segmentleft > hdr.insert_srh.lastentry+1 )
                            {
                                     drop_pkt1.apply();

                            }
                            else{

                                if(hdr.insert_ipv6.hoplimit <= 1){
                                    drop_pkt1.apply();
                                }
                                else{
                                   transit_srh_t.apply();
                                   insert_ipv6_forward_t.apply();
                                }
                             }
                      }

            }
            else{
                insert_ipv6_forward_t.apply();
            }
        }


    }

}
control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t stdmeta)
{
       /**入队时间戳：stdmeta.enq_timestamp
         节点转发延迟：stdmeta.deq_timedelta
        入队时队列长度： stdmeta.enq_qdepth
        出队时队列长度：stdmeta.deq_qdepth
        出接口：stdmeta.egress_port;
        入接口：stdmeta.ingress_port
        */



//    action insert_ipv6_forward(bit<9> port){
//        stdmeta.egress_spec = port;
//        hdr.insert_ipv6.hoplimit = hdr.insert_ipv6.hoplimit - 1;
//
//    }
    /**原始IPV4转发*/
//    action ipv4_forward(bit<9> port){
//        stdmeta.egress_spec = port;
//
//    }
//    action origin_ip_forward(bit<9> port ){
//        stdmeta.egress_spec = port;
//    }
    /**原始IPV6转发*/
//    action ipv6_forward(bit<9> port){
//        stdmeta.egress_spec = port;
//
//    }
  action clone_to_cpu(){

        clone3<metadata>(CloneType.E2E, 233, meta);
    }
    table clone_to_cpu_t{
        actions ={clone_to_cpu;}
    }
    /**丢弃包*/
    action drop(){
        mark_to_drop(stdmeta);
    }
     //报告入接口 出接口
    action export_port(){
        hdr.data_list_h[0].setValid();
        hdr.data_list_h[0].data = 7w0 ++ meta.user_mata.ingress_port ++ 7w0 ++ meta.user_mata.egress_port;
        hdr.insert_ipv6.payloadlength = hdr.insert_ipv6.payloadlength + 4;
        hdr.export_udp.udplength = hdr.export_udp.udplength + 4;

    }
    //报告入队时间戳 单位微秒
    action export_timestamp(){
        hdr.data_list_h[1].setValid();
        hdr.data_list_h[1].data = stdmeta.enq_timestamp;
        hdr.insert_ipv6.payloadlength = hdr.insert_ipv6.payloadlength + 4;
        hdr.export_udp.udplength=hdr.export_udp.udplength + 4;

    }
    //报告节点转发延迟
    action export_transit_delay(){
        hdr.data_list_h[2].setValid();
        hdr.data_list_h[2].data = stdmeta.deq_timedelta;
        hdr.insert_ipv6.payloadlength = hdr.insert_ipv6.payloadlength + 4;
        hdr.export_udp.udplength=hdr.export_udp.udplength + 4;

    }
    //报告出队队列长度
    action export_dequene_length(){
          hdr.data_list_h[3].setValid();
          hdr.data_list_h[3].data=13w0 ++ stdmeta.deq_qdepth;
          hdr.insert_ipv6.payloadlength = hdr.insert_ipv6.payloadlength + 4;
          hdr.export_udp.udplength=hdr.export_udp.udplength + 4;

    }
    //报告入队队列长度
    action export_enquene_length(){
          hdr.data_list_h[4].setValid();
          hdr.data_list_h[4].data = 13w0 ++ stdmeta.enq_qdepth;
          hdr.insert_ipv6.payloadlength = hdr.insert_ipv6.payloadlength + 4;
          hdr.export_udp.udplength=hdr.export_udp.udplength + 4;

    }
    table export_port_t{
        actions = {export_port;}
    }
    table export_timestamp_t{
        actions = {export_timestamp;}
    }
    table export_transit_delay_t{
        actions = {export_transit_delay;}
    }
    table export_dequene_length_t{
        actions = {export_dequene_length;}
    }
    table export_enquene_length_t{
        actions = {export_enquene_length;}
    }

    action update_header(bit<128> switch_ipv6_address,bit<128> controller_ipv6_address){
        hdr.insert_ipv6.dstAddr = controller_ipv6_address;
        hdr.insert_ipv6.srcAddr = switch_ipv6_address;
        hdr.insert_ipv6.nextheader = 17;
        hdr.insert_ipv6.payloadlength = 8;
        hdr.insert_srh.setInvalid();
        hdr.segment_list[0].setInvalid();
        hdr.segment_list[1].setInvalid();
        hdr.segment_list[2].setInvalid();
        hdr.segment_list[3].setInvalid();
        hdr.segment_list[4].setInvalid();
        hdr.segment_list[5].setInvalid();
        hdr.export_udp.setValid();
        hdr.export_udp.srcPort = ex_udp_srcPort;
        hdr.export_udp.dstPort = ex_udp_dstPort;
        hdr.export_udp.checksum = 0;
        hdr.export_udp.udplength =8;
        hdr.ip.ipv4.setInvalid();
        hdr.ip.ipv6.setInvalid();

    }
    /**transit节点转发动作*/
//    action transit_srh(){
//
//        if(hdr.insert_ipv6.hoplimit != 255)
//        {
//            hdr.insert_srh.segmentleft = hdr.insert_srh.segmentleft - 1;
//
//        bit<8> SL = hdr.insert_srh.segmentleft;
//        hdr.insert_ipv6.dstAddr = hdr.segment_list [SL].data;
//        }
//    }

//弹出insert_ipv6和insert_srh
//    action pop_srh(){
//        hdr.insert_ipv6.setInvalid();
//        hdr.insert_srh.setInvalid();
//        hdr.segment_list[0].setInvalid();
//        hdr.segment_list[1].setInvalid();
//        hdr.segment_list[2].setInvalid();
//        hdr.segment_list[3].setInvalid();
//        hdr.segment_list[4].setInvalid();
//        hdr.segment_list[5].setInvalid();
//        hdr.dex.setInvalid();
//    }
//    table transit_srh_t{
//        actions = {
//            transit_srh;
//        }
//    }
//    table pop_srh_t{
//        actions = {
//            pop_srh;
//        }
//    }

    table update_header_t{
        actions = {

           update_header;
        }

    }
//    table drop_pkt{
//        actions ={drop;}
//    }
    //外层ipv6转发
//    table insert_ipv6_forward_t{
//        key = {
//            hdr.insert_ipv6.dstAddr:lpm;
//        }
//        actions = {
//            insert_ipv6_forward;
//        }
//    }
    //内层ipv4转发
//    table ipv4_forward_t{
//        key = {
//            hdr.ip.ipv4.dstAddr:lpm;
//        }
//        actions = {
//            origin_ip_forward;
//        }
//    }
//    //内层ipv6转发
//    table ipv6_forward_t{
//        key = {
//            hdr.ip.ipv6.dstAddr:lpm;
//        }
//        actions = {
//            origin_ip_forward;
//        }
//    }

    apply{
            if(hdr.dex.isValid() && hdr.insert_ipv6.hoplimit ==254 && stdmeta.egress_port!=255){
                clone_to_cpu_t.apply();
                }
            //出接口是255代表发给controller的包
            if (stdmeta.egress_port == CPU_PORT){
                 update_header_t.apply();
                 //报告入接口和出接口
                if(hdr.dex.tracetype[22:22] == 1){
                   export_port_t.apply();
                }
                //报告入队时间戳 单位微秒
                if(hdr.dex.tracetype[21:21] == 1){
                   export_timestamp_t.apply();
                }
                //报告节点转发延迟
                if(hdr.dex.tracetype[19:19] == 1){
                  export_transit_delay_t.apply();
                }
                //报告出队队列长度
                if(hdr.dex.tracetype[17:17] == 1){
                  export_dequene_length_t.apply();
                }
                //报告入队队列长度
                if(hdr.dex.tracetype[11:11] == 1){
                  export_enquene_length_t.apply();
                }
           }




     }

}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true,
        {   hdr.ip.ipv4.version,
            hdr.ip.ipv4.ihl,
            hdr.ip.ipv4.diffserv,
            hdr.ip.ipv4.totalLen,
            hdr.ip.ipv4.identification,
            hdr.ip.ipv4.flags,
            hdr.ip.ipv4.fragOffset,
            hdr.ip.ipv4.ttl,
            hdr.ip.ipv4.protocol,
            hdr.ip.ipv4.srcAddr,
            hdr.ip.ipv4.dstAddr//,hdr.ip.ipv4.options
        }   ,hdr.ip.ipv4.hdrChecksum, HashAlgorithm.csum16);

    }
}


control MyUpdateChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true,
        {   hdr.ip.ipv4.version,
            hdr.ip.ipv4.ihl,
            hdr.ip.ipv4.diffserv,
            hdr.ip.ipv4.totalLen,
            hdr.ip.ipv4.identification,
            hdr.ip.ipv4.flags,
            hdr.ip.ipv4.fragOffset,
            hdr.ip.ipv4.ttl,
            hdr.ip.ipv4.protocol,
            hdr.ip.ipv4.srcAddr,
            hdr.ip.ipv4.dstAddr//,hdr.ip.ipv4.options
        },hdr.ip.ipv4.hdrChecksum, HashAlgorithm.csum16);

    }
}

control MyDeparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.insert_ipv6);
        pkt.emit(hdr.export_udp);
        pkt.emit(hdr.insert_srh);
        pkt.emit(hdr.segment_list);
        pkt.emit(hdr.dex);
        pkt.emit(hdr.data_list_h);
        pkt.emit(hdr.ip);
    }

}

V1Switch<headers, metadata>(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyUpdateChecksum(),MyDeparser()) main;
