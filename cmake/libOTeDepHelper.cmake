cmake_policy(PUSH)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0045 NEW)
cmake_policy(SET CMP0074 NEW)


if(NOT DEFINED LIBOTE_THIRDPARTY_HINT)
    # this is for installed packages, moves up lib/cmake/libOTe
    set(LIBOTE_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../../..")
endif()
message(STATUS "LIBOTE_THIRDPARTY_HINT=${LIBOTE_THIRDPARTY_HINT}")
set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};${LIBOTE_THIRDPARTY_HINT}")


## bitpolymul
###########################################################################

if (ENABLE_BITPOLYMUL)
    find_package(bitpolymul)
endif ()

# resort the previous prefix path
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})
cmake_policy(POP)