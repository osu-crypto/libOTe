enable_language(ASM)

file(GLOB_RECURSE SRCS *.cpp)

set(SRCS "${SRCS}")

add_library(libOTe STATIC ${SRCS})

target_include_directories(libOTe PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..) 
target_link_libraries(libOTe cryptoTools)


if(ENABLE_SIMPLESTOT_ASM)
	target_link_libraries(libOTe SimplestOT)
endif()

if(ENABLE_MR_KYBER)
	target_link_libraries(libOTe KyberOT)
endif(ENABLE_MR_KYBER)


#############################################
#            Install                        #
#############################################

# install library
install(TARGETS libOTe DESTINATION lib)

# install headers
install(DIRECTORY . DESTINATION include/libOTe FILES_MATCHING PATTERN "*.h")
