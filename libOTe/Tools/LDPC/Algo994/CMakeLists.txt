# CMakeList.txt : CMake project for LDPC, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable
file(GLOB_RECURSE SRCS *.cpp *.c)
add_library(algo994 STATIC ${SRCS})


target_include_directories(algo994 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/..") 

if(MSVC)
	target_compile_options(algo994 PUBLIC "-openmp:experimental")
endif()