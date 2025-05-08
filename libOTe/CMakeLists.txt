enable_language(ASM)



file(GLOB_RECURSE SRCS *.cpp *.c)
add_library(libOTe STATIC ${SRCS})

if (ENCABLE_CUDA)
    find_package(CUDA REQUIRED)
    # or use newer CMake
    enable_language(CUDA)
    # Add CUDA-specific targets or compile options

    find_package(CUDAToolkit REQUIRED)
    set(CUDA_SRCS Tools/Tungsten/ParallelSyndromeDecoding.cu)
    set_source_files_properties(${CUDA_SRCS} PROPERTIES LANGUAGE CUDA)
    add_library(libOTeCUDA STATIC ${CUDA_SRCS})
    
    if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
        set(CMAKE_CUDA_ARCHITECTURES 86)
    endif()
    set_target_properties(libOTeCUDA PROPERTIES
        CUDA_ARCHITECTURES "86"
    )
    set_property(TARGET libOTeCUDA PROPERTY CUDA_STANDARD ${LIBOTE_STD_VER})
     
    target_link_libraries(libOTeCUDA macoro)
    target_link_libraries(libOTe libOTeCUDA)

endif()

find_package(OpenMP REQUIRED)
target_link_libraries(libOTe OpenMP::OpenMP_CXX)

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
        #target_compile_options(libOTe PRIVATE -maes -msse2 -msse3 -msse4.1 -mpclmul)
        target_compile_options(libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-maes -msse2 -msse3 -msse4.1 -mpclmul>)
    endif()
    if(ENABLE_AVX)
        #target_compile_options(libOTe PRIVATE -mavx2)
        target_compile_options(libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-mavx2>)
    endif()
endif()

# Ensure consistent CUDA standard
#set(CMAKE_CUDA_STANDARD ${LIBOTE_STD_VER})
#set(CMAKE_CUDA_STANDARD_REQUIRED ON)

if (ENABLE_BITPOLYMUL)
	target_link_libraries(libOTe bitpolymul)
endif ()
if(ENABLE_SIMPLESTOT_ASM)
	target_link_libraries(libOTe SimplestOT)
    #target_compile_options(libOTe PRIVATE -fPIC -no-pie)
endif()

if(ENABLE_MR_KYBER)
	target_link_libraries(libOTe KyberOT)
endif()



#############################################
#            Install                        #
#############################################

# install library
#install(TARGETS libOTe DESTINATION lib)

# install headers
#install(DIRECTORY . DESTINATION include/libOTe FILES_MATCHING PATTERN "*.h")
