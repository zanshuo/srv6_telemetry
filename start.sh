#!/bin/bash

p4c --target bmv2 --arch v1model --p4runtime-files telemetryinfo.txt telemetry.p4
sudo python topology1.py --behavioral-exe ../behavioral-model/targets/simple_switch/simple_switch --json ./telemetry.json --pcap-dump true