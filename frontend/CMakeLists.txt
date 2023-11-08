
#project(frontend)


file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR})


add_executable(frontend_libOTe  ${SRCS})

target_link_libraries(frontend_libOTe libOTe_Tests tests_cryptoTools)


if(MSVC)
    target_compile_options(frontend_libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBOTE_STD_VER}>)
    

    target_compile_options(frontend_libOTe PRIVATE "/bigobj")
else()
    target_compile_options(frontend_libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER}>)
endif()