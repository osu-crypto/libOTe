cmake_minimum_required (VERSION 3.6)

project("libOTe")


#############################################
#            Flag and #defines              #
#############################################
add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")
set(CMAKE_C_FLAGS "-ffunction-sections -O3 -Wall  -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread")
set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++14")


include_directories(${CMAKE_SOURCE_DIR}/thirdparty/linux/miracl)



#############################################
#    Build cryptoTools (common utilities)   #
#############################################
add_subdirectory(cryptoTools)
include_directories(cryptoTools)



#############################################
#               Build libOTe                #
#############################################
add_subdirectory(libOTe)
include_directories(libOTe)



#############################################
#           Build libOTe Tests              #
#############################################
add_subdirectory(libOTe_Tests)
include_directories(libOTe_Tests)


#############################################
#              Build Frontend               #
#############################################
#add_subdirectory(frontend)
file(GLOB_RECURSE SRC_FRONTEND ${CMAKE_SOURCE_DIR}/frontend/*.cpp)
add_executable(frontend_exe  ${SRC_FRONTEND})


#############################################
#            Link our libraries             #
#############################################
target_link_libraries(frontend_exe libOTe_Tests)
