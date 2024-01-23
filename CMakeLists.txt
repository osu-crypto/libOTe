
cmake_minimum_required (VERSION 3.15)
if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif (POLICY CMP0048)

project(libOTe VERSION 2.2.0)

include(cmake/libOTePreamble.cmake)

if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")

	############################################
	#          If top level cmake              #
	############################################

	############################################
	#           Flag and #defines              #
	############################################
	add_definitions(-DSOLUTION_DIR='${CMAKE_SOURCE_DIR}')
	if(MSVC)
	else()
		set(COMMON_FLAGS "-Wall -Wfatal-errors")
		SET(CMAKE_CXX_FLAGS_RELEASE "-O3  -DNDEBUG")
		SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb")
		SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g -ggdb")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ")
	endif()
	#set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)

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


if(DEFINED LIBOTE_CPP_VER)
    message("warning: setting LIBOTE_STD_VER as LIBOTE_CPP_VER=${LIBOTE_CPP_VER}")
    set(LIBOTE_STD_VER ${LIBOTE_CPP_VER})
    unset(LIBOTE_CPP_VER CACHE )
endif()
if(NOT DEFINED LIBOTE_STD_VER)
	set(LIBOTE_STD_VER 17)
endif()
if(NOT LIBOTE_STD_VER EQUAL 20 AND
	NOT LIBOTE_STD_VER EQUAL 17)
	message(FATAL_ERROR "Unknown c++ version. LIBOTE_STD_VER=${LIBOTE_STD_VER}")
endif()
set(CRYPTO_TOOLS_STD_VER ${LIBOTE_STD_VER})
if(NOT DEFINED ENABLE_COPROTO)
    set(ENABLE_COPROTO true)
endif()
if(NOT ENABLE_COPROTO)
    message("warning: setting ENABLE_BOOST as true")
    set(ENABLE_COPROTO true)
endif()


#############################################
#    Build cryptoTools (common utilities)   #
#############################################
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
