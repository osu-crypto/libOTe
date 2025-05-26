enable_language(ASM)

file(GLOB_RECURSE SRCS *.cpp *.c)

set(SRCS "${SRCS}")

add_library(libOTe STATIC ${SRCS} )



# make projects that include libOTe use this as an include folder
target_include_directories(libOTe PUBLIC
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>)
target_include_directories(libOTe PUBLIC
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>)
                    
target_link_libraries(libOTe cryptoTools)

if(MSVC)
    target_compile_options(libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBOTE_STD_VER}>)
else()
    target_compile_options(libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER}>)

    if(ENABLE_SSE)
        target_compile_options(libOTe PRIVATE -maes -msse2 -msse3 -msse4.1 -mpclmul)
    endif()
    if(ENABLE_AVX)
        target_compile_options(libOTe PRIVATE -mavx2)
    endif()
endif()
if (ENABLE_BITPOLYMUL)
	target_link_libraries(libOTe bitpolymul)
endif ()
if(ENABLE_SIMPLESTOT_ASM)
	target_link_libraries(libOTe SimplestOT)
endif()

if(ENABLE_MR_KYBER)
	target_link_libraries(libOTe KyberOT)
endif()


if(LIBOTE_SHARED)
    
    add_library(libOTeShared SHARED ${SRCS} )
    target_link_libraries(libOTeShared libOTe)
    if(MSVC)
        target_compile_options(libOTeShared PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBOTE_STD_VER}>)
    else()
        target_compile_options(libOTeShared PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER}>)

        if(ENABLE_SSE)
            target_compile_options(libOTeShared PRIVATE -maes -msse2 -msse3 -msse4.1 -mpclmul)
        endif()
        if(ENABLE_AVX)
            target_compile_options(libOTeShared PRIVATE -mavx2)
        endif()
    endif()
endif()

#############################################
#            Install                        #
#############################################

# install library
#install(TARGETS libOTe DESTINATION lib)

# install headers
#install(DIRECTORY . DESTINATION include/libOTe FILES_MATCHING PATTERN "*.h")
