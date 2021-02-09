# CMakeList.txt : CMake project for LDPC, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable
file(GLOB_RECURSE SRCS *.cpp *.c)
add_library(ldpc STATIC ${SRCS})



target_link_libraries(ldpc PUBLIC algo994)
target_include_directories(ldpc PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/..") 



##############################################
#              cryptoTools
   
 

set(cryptoToolsDir "${CMAKE_CURRENT_SOURCE_DIR}/../../cryptoTools")

if(NOT EXISTS ${cryptoToolsDir})
      message(FATAL_ERROR "Failed to find cryptoTools at " ${cryptoToolsDir})
endif()


target_include_directories(ldpc PUBLIC "${cryptoToolsDir}") 

if(MSVC)
    target_include_directories(ldpc PUBLIC "c:/libs/eigen") 
    
    if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        target_link_libraries(ldpc PUBLIC "${cryptoToolsDir}/x64/Debug_DLLRT/cryptoTools.lib")
    else()
        target_link_libraries(ldpc PUBLIC "${cryptoToolsDir}/x64/Release_DLLRT/cryptoTools.lib")
    endif()

    
else()
    target_link_libraries(ldpc PUBLIC "${cryptoToolsDir}/lib/libcryptoTools.a")
endif()

# TODO: Add tests and install targets if needed.
