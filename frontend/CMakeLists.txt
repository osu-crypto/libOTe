
#project(frontend)


file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR})


add_executable(frontend_libOTe  ${SRCS} "ExampleTriples.h")

target_compile_definitions(frontend_libOTe PRIVATE
    $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:NDEBUG>
)

target_link_libraries(frontend_libOTe libOTe_Tests tests_cryptoTools)


if(MSVC)
    target_compile_options(frontend_libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBOTE_STD_VER}>)
    

    target_compile_options(frontend_libOTe PRIVATE "/bigobj")
else()
    target_compile_options(frontend_libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER}>)
    
    if(NOT APPLE)

        # no-subobject-linkage =  GCC bug complaining about coroutines capturing lambdas
        # which only have internal linkage. But this is expected.
        target_compile_options(frontend_libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Wno-subobject-linkage>)
    endif()    
endif()