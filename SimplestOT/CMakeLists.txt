#project(SimplestOT  C C++ ASM)

enable_language(ASM)

file(GLOB_RECURSE SRC_SIMPLE_LIB 
	${CMAKE_SOURCE_DIR}/SimplestOT/*.c
	${CMAKE_SOURCE_DIR}/SimplestOT/*.s)

	

add_library(SimplestOT STATIC ${SRC_SIMPLE_LIB})
target_link_libraries(SimplestOT PUBLIC cryptoTools)


#############################################
#            Install                        #
#############################################

# install library
install(TARGETS SimplestOT DESTINATION lib)

# install headers
install(DIRECTORY . DESTINATION include/SimplestOT FILES_MATCHING PATTERN "*.h")
