#!/bin/bash
cd /root/p4/telemetry
make clean
ip link add con-eth0 type bridge
ip link set con-eth0 up
ip link add con-eth1 type bridge
ip link set con-eth1 up
ip link add con-eth2 type bridge
ip link set con-eth2 up

make
