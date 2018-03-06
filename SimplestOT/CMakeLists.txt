#project(SimplestOT  C C++ ASM)

enable_language(ASM)

file(GLOB_RECURSE SRC_SIMPLE_LIB 
	#${CMAKE_SOURCE_DIR}/SimplestOT/*.cpp
	${CMAKE_SOURCE_DIR}/SimplestOT/*.c
	${CMAKE_SOURCE_DIR}/SimplestOT/*.s)

	
set(SRC_SIMPLE_MAIN ${CMAKE_SOURCE_DIR}/SimplestOT/mains.cpp)


add_library(SimplestOT STATIC ${SRC_SIMPLE_LIB})
target_link_libraries(SimplestOT PUBLIC cryptoTools)

add_executable(simple.exe ${SRC_SIMPLE_MAIN})
target_link_libraries(simple.exe SimplestOT)


#############################################
#            Install                        #
#############################################

# install library
install(TARGETS SimplestOT DESTINATION lib)

# install headers
install(DIRECTORY . DESTINATION include/SimplestOT FILES_MATCHING PATTERN "*.h")
