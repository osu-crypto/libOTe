cmake_minimum_required (VERSION 3.6)

project(libOTe)

set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin)
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)

############################################
#           Flag and #defines              #
############################################
add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")
set(CMAKE_C_FLAGS "-ffunction-sections -Wall  -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread")
set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++14")

# Set a default build type for single-configuration
# CMake generators if no build type is set.
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE Release)
endif()

if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Release")
  message(WARNING "\nConfiguration NOT set to Release. Please call cmake with CMAKE_BUILD_TYPE=Release")

    IF(CMAKE_BUILD_TYPE MATCHES Debug)
      #message("Debug build.")
    ELSEIF(CMAKE_BUILD_TYPE MATCHES Release)
      #message("Release build.")
    ELSEIF(CMAKE_BUILD_TYPE MATCHES RELWITHDEBINFO)
      #message("Release with debug info build.")
    ELSE()
      message(ERROR "Unknown build type: ${CMAKE_BUILD_TYPE}  Please use one of Debug, Release, or RELWITHDEBINFO" )
    ENDIF()
endif()

# Select flags.
SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")
SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g")

 

#############################################
#       Library/includes locations          #
#############################################

# default location for miracl
set(Miracl_Dirs "${CMAKE_SOURCE_DIR}/thirdparty/linux/miracl/")
include_directories("${Miracl_Dirs}") 
link_directories("${Miracl_Dirs}/miracl/source/")

# default location for Boost
set(BOOST_ROOT "${CMAKE_SOURCE_DIR}/thirdparty/linux/boost/")


#############################################
#    Build cryptoTools (common utilities)   #
#############################################
add_subdirectory(cryptoTools)
#include_directories(cryptoTools)

#############################################
#               Build libOTe                #
#############################################
add_subdirectory(libOTe)
# include_directories(libOTe)

#############################################
#           Build libOTe Tests              #
#############################################
add_subdirectory(libOTe_Tests)
#include_directories(libOTe_Tests)

#############################################
#              Build Frontend               #
#############################################
#add_subdirectory(frontend)
include_directories(${CMAKE_SOURCE_DIR})
file(GLOB_RECURSE SRC_FRONTEND ${CMAKE_SOURCE_DIR}/frontend/*.cpp)
add_executable(frontend.exe ${SRC_FRONTEND})

#############################################
#            Link our libraries             #
#############################################

target_link_libraries(frontend.exe libOTe_Tests)

# install library
file(GLOB_RECURSE SOURCES libOTe/*.cpp)
add_library(OTe SHARED ${SOURCES})
install(TARGETS OTe DESTINATION lib/${PROJECT_NAME})
install(FILES ${HEADERS} DESTINATION include/${PROJECT_NAME})

# install (TARGETS frontend.exe DESTINATION bin)
file(GLOB_RECURSE HEADERS libOTe/*.cpp)
