cmake_minimum_required (VERSION 3.4)

project(libOTe)


if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")

	############################################
	#          If top level cmake              #
	############################################

	set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin)
	set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)
	set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)

	############################################
	#           Flag and #defines              #
	############################################
	add_definitions(-DSOLUTION_DIR='${CMAKE_SOURCE_DIR}')
	set(CMAKE_C_FLAGS "-ffunction-sections -Wall  -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread -Wno-strict-overflow  -fPIC -Wno-ignored-attributes -Wno-parentheses")
	set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++14")
	
	# Select flags.
	SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native  -DNDEBUG") 
	SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb -rdynamic")
	SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g -ggdb -rdynamic")
	

	############################################
	#           Build mode checks              #
	############################################
	
	# Set a default build type for single-configuration
	# CMake generators if no build type is set.
	if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
	   SET(CMAKE_BUILD_TYPE Release)
	endif()

	if(    NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Release"
       AND NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" 
       AND NOT "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo" )
		  
        message(FATAL_ERROR ": Unknown build type - \${CMAKE_BUILD_TYPE}=${CMAKE_BUILD_TYPE}.  Please use one of Debug, Release, or RelWithDebInfo. e.g. call\n\tcmake . -DCMAKE_BUILD_TYPE=Release\n" )        
	endif()

    message(STATUS "Option: CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}\n\tRelease\n\tDebug\n\tRelWithDebInfo")

endif()
 
 
#############################################
#                CONFIGURE                  #
#############################################



option(ENABLE_SIMPLESTOT "Build the assembly based SimplestOT library" OFF)
message(STATUS "Option: ENABLE_SIMPLESTOT = ${ENABLE_SIMPLESTOT}")

option(ENABLE_KYBEROT "Build the Kyber (LWE based) library" OFF)
message(STATUS "Option: ENABLE_KYBEROT    = ${ENABLE_KYBEROT}")



set(OTE_KOS_HASH "OTE_DAVIE_MEYER_AES" CACHE STRING "Hashing technique for KOS ")
message(STATUS "Option: KOS hashing (current = ${OTE_KOS_HASH}):\n")
message(STATUS "      OTE_KOS_HASH=OTE_RANDOM_ORACLE         use the random oracle (slower)")
message(STATUS "      OTE_KOS_HASH=OTE_DAVIE_MEYER_AES       use AES in the Davie Meyer compression function\n")


option(OTE_KOS_FIAT_SHAMIR "Build the library withing Fiat Shamir for KOS" OFF)
message(STATUS "Option: OTE_KOS_FIAT_SHAMIR = ${OTE_KOS_FIAT_SHAMIR}")


option(ENABLE_SILENTOT   "Build the Slient OT protocol." OFF)
message(STATUS "Option: ENABLE_SILENTOT   = ${ENABLE_SILENTOT}")


configure_file(libOTe/config.h.in libOTe/config.h)

#############################################
#    Build cryptoTools (common utilities)   #
#############################################
#include_directories(cryptoTools)
add_subdirectory(cryptoTools)


#############################################
#               Build libOTe                #
#############################################

if(ENABLE_SIMPLESTOT)
	add_subdirectory(SimplestOT)
endif(ENABLE_SIMPLESTOT)

if(ENABLE_KYBEROT)
	add_subdirectory(KyberOT)
endif(ENABLE_KYBEROT)

add_subdirectory(libOTe)
add_subdirectory(libOTe_Tests)

#############################################
#              Build Frontend               #
#############################################
add_subdirectory(frontend)


