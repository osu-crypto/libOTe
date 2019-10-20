
#project(libOTe)
enable_language(ASM)

file(GLOB_RECURSE SRCS *.cpp)

set(SRCS "${SRCS}")

#include_directories(${CMAKE_SOURCE_DIR})
add_library(libOTe STATIC ${SRCS})

target_include_directories(libOTe PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..) 

target_compile_options(libOTe 
               PRIVATE -Wall -Wfatal-errors -Wno-strict-overflow -Wno-ignored-attributes -Wno-parentheses
               PUBLIC -ffunction-sections -maes -msse2 -msse4.1 -mpclmul -pthread)

target_compile_features(libOTe PRIVATE cxx_std_14)

target_link_libraries(libOTe cryptoTools)


if(ENABLE_SIMPLESTOT)
	target_link_libraries(libOTe SimplestOT)
endif()

if(ENABLE_KYBEROT)
	target_link_libraries(libOTe KyberOT)
endif(ENABLE_KYBEROT)

#############################################
#            Install                        #
#############################################

# install library
install(TARGETS libOTe DESTINATION lib)

# install headers
install(DIRECTORY . DESTINATION include/libOTe FILES_MATCHING PATTERN "*.h")
