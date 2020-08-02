import os
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import RemoteController

from p4_mininet import P4Switch, P4Host

import argparse
from time import sleep

parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", required=True)
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
parser.add_argument('--num-hosts', help='Number of hosts to connect to switch',
                    type=int, action="store", default=2)
parser.add_argument('--mode', choices=['l2', 'l3'], type=str, default='l3')
parser.add_argument('--json', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    type=str, action="store", required=False, default=False)


args = parser.parse_args()


class SingleSwitchTopo(Topo):
    def __init__(self, sw_path, json_path, thrift_port, pcap_dump, **opts):
        Topo.__init__(self, **opts)

        switch1 = self.addSwitch('s1', sw_path = sw_path, json_path = json_path, thrift_port = thrift_port,cls = P4Switch ,pcap_dump = pcap_dump)
        switch2 = self.addSwitch('s2', sw_path = sw_path, json_path = json_path, thrift_port = thrift_port + 1,cls = P4Switch ,pcap_dump = pcap_dump)
        switch3 = self.addSwitch('s3', sw_path = sw_path, json_path = json_path, thrift_port = thrift_port + 2,cls = P4Switch ,pcap_dump = pcap_dump)
        switch4 = self.addSwitch('s4', sw_path = sw_path, json_path = json_path, thrift_port = thrift_port + 3,cls = P4Switch ,pcap_dump = pcap_dump)
        
        host1 = self.addHost('h1', ip = '10.0.0.1', mac = '00:00:00:00:00:01')
        host2 = self.addHost('h2', ip = '10.0.0.2', mac = '00:00:00:00:00:02')
        

        controller = self.addHost('controller', ip = '10.0.1.1')



        self.addLink(host1, switch1, port1 = 0, port2 = 1)
        self.addLink(host2, switch4, port1 = 0, port2 = 1)
        self.addLink(switch1, switch2)
        self.addLink(switch2, switch3)
        self.addLink(switch3, switch4)

        self.addLink(controller, switch1, port1 = 0, port2 = 255)
        self.addLink(controller, switch2, port1 = 1, port2 = 255)
        self.addLink(controller, switch3, port1 = 2, port2 = 255)
        self.addLink(controller, switch4, port1 = 3, port2 = 255)
        



def main():
    topo = SingleSwitchTopo(args.behavioral_exe, args.json, args.thrift_port, args.pcap_dump)
    #controller1 = RemoteController('controller1', ip = '10.108.148.148')
    net = Mininet(topo = topo, host = P4Host, controller = None)
    net.start()
    net.get('h1').cmd('ip addr add 2001::1/64 dev eth0')
    net.get('h1').cmd('ip -6 route add 2002::1 dev eth0')

    net.get('h2').cmd('ip addr add 2002::1/64 dev eth0')
    net.get('h2').cmd('ip -6 route add 2001::1 dev eth0')

    #net.get('controller').cmd('ip addr add 20ff::1/64 dev eth0')
    
    net.get('controller').setIP('10.0.1.1', intf = 'controller-eth0')
    net.get('controller').setMAC('00:00:00:00:00:f1', intf = 'controller-eth0')
    net.get('controller').cmd('ip addr add 20ff::1/64 dev eth0')

    net.get('controller').setIP('10.0.1.2', intf = 'controller-eth1')
    net.get('controller').setMAC('00:00:00:00:00:f2', intf = 'controller-eth1')
    net.get('controller').cmd('ip addr add 20ff::2/64 dev controller-eth1')

    net.get('controller').setIP('10.0.1.3', intf = 'controller-eth2')
    net.get('controller').setMAC('00:00:00:00:00:f3', intf = 'controller-eth2')
    net.get('controller').cmd('ip addr add 20ff::3/64 dev controller-eth2')

    net.get('controller').setIP('10.0.1.4', intf = 'controller-eth3')
    net.get('controller').setMAC('00:00:00:00:00:f4', intf = 'controller-eth3')
    net.get('controller').cmd('ip addr add 20ff::4/64 dev controller-eth3')

    sleep(1)

    print('\033[0;32m'),
    print "Gotcha!"
    print('\033[0m')

    CLI(net)
    try:
        net.stop()
    except:
        print('\033[0;31m'),
        print('Stop error! Trying sudo mn -c')
        print('\033[0m')
        os.system('sudo mn -c')
        print('\033[0;32m'),
        print ('Stop successfully!')
        print('\033[0m')

if __name__ == '__main__':
    setLogLevel('info')
    main()

    


