cmake_minimum_required(VERSION 3.28)
project(Ppcg)

set(CMAKE_CXX_STANDARD 17)

add_executable(Ppcg main.cpp
        BlockConstructionEnumerator.h
        Tools.h)
