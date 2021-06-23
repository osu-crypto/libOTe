cmake_policy(PUSH)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0045 NEW)
cmake_policy(SET CMP0074 NEW)


set(LIBOTE_INSOURCE_FIND_DEPS (EXISTS ${CMAKE_CURRENT_LIST_DIR}/libOTeFindBuildDir.cmake))

if(NOT DEFINED LIBOTE_THIRDPARTY_HINT)
    if(LIBOTE_INSOURCE_FIND_DEPS)
        # we currenty are in the libOTe source tree, libOTe/cmake
        if(MSVC)
            set(LIBOTE_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/win")
        else()
            set(LIBOTE_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/unix")
        endif()
    else()
        # we currenty are in install tree, <install-prefix>/lib/cmake/libOTe
        set(LIBOTE_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../../..")
    endif()
endif()

set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};${LIBOTE_THIRDPARTY_HINT}")


## bitpolymul
###########################################################################

if (ENABLE_BITPOLYMUL)
    find_package(bitpolymul)

    if(NOT TARGET bitpolymul)
        message(FATAL_ERROR "failed to find bitpolymul. Looked at LIBOTE_THIRDPARTY_HINT=${LIBOTE_THIRDPARTY_HINT}")
    endif()
endif ()

# resort the previous prefix path
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})
cmake_policy(POP)