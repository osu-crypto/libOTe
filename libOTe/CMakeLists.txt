
#project(libOTe)

file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR})

add_library(libOTe STATIC ${SRCS})

target_link_libraries(libOTe cryptoTools)

#############################################
#            Install                        #
#############################################

# install library
install(TARGETS libOTe DESTINATION lib/${PROJECT_NAME})

# install headers
install(DIRECTORY . DESTINATION include/libOTe FILES_MATCHING PATTERN "*.h")
