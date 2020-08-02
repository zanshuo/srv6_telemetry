#!/bin/bash

set -x
# 在有错误输出时停止.
set -e

cd behavioral-model
./autogen.sh
./configure --enable-debugger --with-pi
make
sudo make install
sudo ldconfig
# Simple_switch_grpc target
cd targets/simple_switch_grpc
./autogen.sh
./configure --with-thrift
make
sudo make install
sudo ldconfig
cd ..
cd ..
cd ..
