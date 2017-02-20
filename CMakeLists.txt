cmake_minimum_required (VERSION 2.8)

project(libOTe)

if(hasParent)
else()

	############################################
	#          If top level cmake              #
	############################################

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
	  message(WARNING "\nConfiguration NOT set to Release. Please call cmake with -DCMAKE_BUILD_TYPE=Release  instead of ${CMAKE_BUILD_TYPE}")

		if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
		  #message(WARNING "Debug build.")
		elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Release") 
		  #message(WARNING "Release build.")
		elseif("${CMAKE_BUILD_TYPE}" STREQUAL  "RELWITHDEBINFO")
		  #message(WARNING "RELWITHDEBINFO=Release with debug info build.")
		else()
		  message(ERROR ": Unknown build type - ${CMAKE_BUILD_TYPE}  Please use one of Debug, Release, or RELWITHDEBINFO\n\n" )
		endif()
	endif()

	# Select flags.
	SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG") 
	SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb -rdynamic")
	SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g -ggdb -rdynamic")

endif()
 

#############################################
#       Library/includes locations          #
#############################################

# default location for miracl
set(Miracl_Dirs "${CMAKE_SOURCE_DIR}/thirdparty/linux/miracl/")
include_directories("${Miracl_Dirs}") 
link_directories("${Miracl_Dirs}/miracl/source/")
install(FILES "${Miracl_Dirs}/miracl/source/libmiracl.a" DESTINATION lib)

# default location for Boost
set(BOOST_ROOT "${CMAKE_SOURCE_DIR}/thirdparty/linux/boost/")



#############################################
#    Build cryptoTools (common utilities)   #
#############################################
include_directories(cryptoTools)
add_subdirectory(cryptoTools)

#############################################
#               Build libOTe                #
#############################################
add_subdirectory(libOTe)

#############################################
#           Build libOTe Tests              #
#############################################
add_subdirectory(libOTe_Tests)

#############################################
#              Build Frontend               #
#############################################
add_subdirectory(frontend)
#include_directories(${CMAKE_SOURCE_DIR})
#file(GLOB_RECURSE SRC_FRONTEND ${CMAKE_SOURCE_DIR}/frontend/*.cpp)
#add_executable(frontend.exe ${SRC_FRONTEND})

#############################################
#            Install Frontend               #
#############################################
#install (TARGETS frontend.exe DESTINATION bin)

#############################################
#            Link our libraries             #
#############################################
#target_link_libraries(frontend.exe libOTe_Tests tests_cryptoTools)
# other libs implicitly linked with libOTe_Tests tests_cryptoTools


