
#project(libOTe_Tests)

file(GLOB_RECURSE SRCS *.cpp)
add_library(libOTe_Tests STATIC ${SRCS})

target_include_directories(libOTe_Tests PUBLIC ${CMAKE_SOURCE_DIR}) 
target_link_libraries(libOTe_Tests libOTe)
