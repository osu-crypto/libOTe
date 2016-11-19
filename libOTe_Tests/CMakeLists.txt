
#project(libOTe_Tests)

file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR}/libOTe_Tests)


add_library(libOTe_Tests ${SRCS})

target_link_libraries(libOTe_Tests libOTe)
