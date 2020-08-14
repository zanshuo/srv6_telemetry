#!/bin/bash
make clean
ip link add con-eth0 type bridge
ip link set con-eth0 up
make
