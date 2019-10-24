#!/bin/sh
sudo apt-get install build-essential -y
sudo apt-get install autoconf autotools-dev libtool texinfo -y
sudo apt-get install cmake git m4 autogen automake -y
sudo apt-get install libboost-container-dev libboost-program-options-dev -y

git submodule init > /dev/null 2>&1
git submodule update > /dev/null 2>&1
git submodule foreach git submodule init > /dev/null 2>&1
git submodule foreach git submodule update > /dev/null 2>&1

mkdir build
cd build

mkdir release
cd release
cmake -DBUILD_SHARED_LIBS=FALSE -DCMAKE_BUILD_TYPE=Release ../../
make -j$(nproc) consensus_primitive