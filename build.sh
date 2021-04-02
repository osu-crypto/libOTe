#!/bin/bash

mkdir -p out
mkdir -p out/build
mkdir -p out/build/linux

cd out/build/linux


#if [ ! -f ./Makefile ] || [ "$#" -ne 0 ]; then
#fi
    cmake ../../.. $@


make -j


cd ../../..