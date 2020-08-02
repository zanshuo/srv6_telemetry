#!/bin/bash

ip link add con-eth0 type bridge up
ip link add con-eth1 type bridge up
ip link add con-eth2 type bridge up
ip link set con-eth0 up
ip link set con-eth1 up
ip link set con-eth2 up
