 cmake_minimum_required(VERSION 3.15)
project(cmakeTest)

add_executable(main main.cpp)

find_package(libOTe REQUIRED HINTS ${LIBOTE_HINT})

target_link_libraries(main oc::libOTe)