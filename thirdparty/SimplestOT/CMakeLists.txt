#project(SimplestOT  C C++ ASM)

enable_language(ASM)

file(GLOB_RECURSE SRC_SIMPLE_LIB 
	${CMAKE_CURRENT_SOURCE_DIR}/*.c
	${CMAKE_CURRENT_SOURCE_DIR}/*.s)

add_library(SimplestOT STATIC ${SRC_SIMPLE_LIB})
target_link_libraries(SimplestOT PUBLIC cryptoTools)
#target_compile_options(SimplestOT PUBLIC -fPIC -no-pie)
target_link_options(SimplestOT PUBLIC -fPIC -no-pie)



# make projects that include libOTe use this as an include folder
target_include_directories(SimplestOT PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 
target_include_directories(SimplestOT PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 



#############################################
#            Install                        #
#############################################

# install library
#install(TARGETS SimplestOT DESTINATION lib)

# install headers
#install(DIRECTORY . DESTINATION include/SimplestOT FILES_MATCHING PATTERN "*.h")
