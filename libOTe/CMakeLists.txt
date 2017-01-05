
#project(libOTe)

file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR})

add_library(libOTe ${SRCS})

target_link_libraries(libOTe cryptoTools)
