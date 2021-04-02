enable_language(ASM)

file(GLOB_RECURSE SRCS *.cpp *.c)

set(SRCS "${SRCS}")

add_library(libOTe STATIC ${SRCS})

target_include_directories(libOTe PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/..")
target_include_directories(libOTe PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..) 


find_package(OpenMP REQUIRED)
target_link_libraries(libOTe OpenMP::OpenMP_CXX)

target_link_libraries(libOTe cryptoTools)

if(MSVC)
    target_compile_options(libOTe PRIVATE -openmp:experimental)
endif()

if(ENABLE_SSE AND NOT MSVC)
    target_compile_options(libOTe PRIVATE -maes -msse2 -msse3 -msse4.1 -mpclmul)
endif()

if(ENABLE_SIMPLESTOT_ASM)
	target_link_libraries(libOTe SimplestOT)
    #target_compile_options(libOTe PRIVATE -fPIC -no-pie)
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
