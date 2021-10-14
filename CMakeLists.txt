
cmake_minimum_required (VERSION 3.15)
if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif (POLICY CMP0048)

project(libOTe VERSION 1.5.1)


if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")

	############################################
	#          If top level cmake              #
	############################################
	
	############################################
	#           Flag and #defines              #
	############################################
	add_definitions(-DSOLUTION_DIR='${CMAKE_SOURCE_DIR}')
	if(MSVC)

		# optionally add the following to CMAKE_PREFIX_PATH
		if(NOT DEFINED CMAKE_PREFIX_PATH AND NOT DEFINED NO_OC_DEFAULT_PREFIX)
			set(CMAKE_PREFIX_PATH 
				"c:/libs"
				"${CMAKE_CURRENT_LIST_DIR}/..;"
				)
		endif()

	else()
		set(COMMON_FLAGS "-Wall -march=native -Wfatal-errors")
		SET(CMAKE_CXX_FLAGS_RELEASE "-O3  -DNDEBUG")
		SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb")
		SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g -ggdb")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -std=c++17")
	endif()

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMMON_FLAGS}")
	

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

        message(WARNING ": Unknown build type - \${CMAKE_BUILD_TYPE}=${CMAKE_BUILD_TYPE}.  Please use one of Debug, Release, or RelWithDebInfo. e.g. call\n\tcmake . -DCMAKE_BUILD_TYPE=Release\n" )
	endif()


endif()


#############################################
#    Build cryptoTools (common utilities)   #
#############################################
include(cmake/libOTePreample.cmake)
add_subdirectory(cryptoTools)


#############################################
#                CONFIGURE                  #
#############################################
include(cmake/buildOptions.cmake)
include(cmake/libOTeDepHelper.cmake)

file(REMOVE ${CMAKE_CURRENT_LIST_DIR}/libOTe/config.h)
configure_file(libOTe/config.h.in libOTe/config.h)


#############################################
#               Build libOTe                #
#############################################

if(ENABLE_SIMPLESTOT_ASM AND (NOT MSVC))
	add_subdirectory(thirdparty/SimplestOT)
endif()

if(ENABLE_MR_KYBER AND (NOT MSVC))
	add_subdirectory(thirdparty/KyberOT)
endif()

add_subdirectory(libOTe)
add_subdirectory(libOTe_Tests)

#############################################
#              Build Frontend               #
#############################################
add_subdirectory(frontend)



#############################################
#              install                      #
#############################################

include("${CMAKE_CURRENT_LIST_DIR}/cmake/install.cmake")
