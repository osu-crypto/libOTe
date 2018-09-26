
#project(libOTe)

if(EnableSimplestOT)
	add_compile_definitions(WITH_OPENCV2)
endif()

file(GLOB_RECURSE SRCS *.cpp)
#include_directories(${CMAKE_SOURCE_DIR})
add_library(libOTe STATIC ${SRCS})

target_include_directories(libOTe PUBLIC ${CMAKE_SOURCE_DIR}) 
target_link_libraries(libOTe cryptoTools)


if(EnableSimplestOT)
	target_link_libraries(SimplestOT)
endif()

#############################################
#            Install                        #
#############################################

# install library
install(TARGETS libOTe DESTINATION lib)

# install headers
install(DIRECTORY . DESTINATION include/libOTe FILES_MATCHING PATTERN "*.h")
