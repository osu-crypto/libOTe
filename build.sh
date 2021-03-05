#!/bin/bash

mkdir -p out
mkdir -p out/build
mkdir -p out/build/linux

cd out/build/linux

cmake ../../.. $@
make -j


cd ../../..