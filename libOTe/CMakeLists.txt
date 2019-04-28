
#project(libOTe)
enable_language(ASM)

file(GLOB_RECURSE SRCS *.cpp)

set(SRCS "${SRCS}")

#include_directories(${CMAKE_SOURCE_DIR})
add_library(libOTe STATIC ${SRCS})

target_include_directories(libOTe PUBLIC ${CMAKE_SOURCE_DIR}) 
target_link_libraries(libOTe cryptoTools)


if(ENABLE_SIMPLESTOT)
	target_link_libraries(libOTe SimplestOT)
endif()


set(bitPolyMulDir "${CMAKE_SOURCE_DIR}/../bitpolymul2/")
set(bitPolyMulLib "${bitPolyMulDir}/lib/${CMAKE_BUILD_TYPE}/libbitpolymul2.a")

if(NOT EXISTS "${bitPolyMulDir}")
    message(FATAL_ERROR "failed to find bitpolymul2 at ${bitPolyMulDir}")
endif()
if(NOT EXISTS "${bitPolyMulLib}")
    message(FATAL_ERROR "failed to find lib bitpolymul2 at ${bitPolyMulLib}")
endif()


target_include_directories(libOTe PUBLIC "${bitPolyMulDir}") 
target_link_libraries(libOTe "${bitPolyMulLib}")

#############################################
#            Install                        #
#############################################

# install library
install(TARGETS libOTe DESTINATION lib)

# install headers
install(DIRECTORY . DESTINATION include/libOTe FILES_MATCHING PATTERN "*.h")
