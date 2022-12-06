
#project(libOTe_Tests)

file(GLOB SRCS *.cpp) 
add_library(libOTe_Tests STATIC ${SRCS})

target_link_libraries(libOTe_Tests libOTe)


# make projects that include libOTe_Tests use this as an include folder
target_include_directories(libOTe_Tests PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 
target_include_directories(libOTe_Tests PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 


if(MSVC)
    target_compile_options(libOTe_Tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBOTE_STD_VER}>)
    
else()
    target_compile_options(libOTe_Tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER}>)
endif()