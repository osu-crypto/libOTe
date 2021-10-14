cmake_policy(PUSH)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0045 NEW)
cmake_policy(SET CMP0074 NEW)



set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
set(CMAKE_PREFIX_PATH "${OC_THIRDPARTY_HINT};${CMAKE_PREFIX_PATH}")


## bitpolymul
###########################################################################

macro(FIND_BITPOLYMUL)
    if(FETCH_BITPOLYMUL_IMPL)
        set(BITPOLYMUL_DP NO_DEFAULT_PATH PATHS ${OC_THIRDPARTY_HINT})
    else()
        unset(BITPOLYMUL_DP)
    endif()
    
    find_package(bitpolymul ${BITPOLYMUL_DP} ${ARGN})
    if(TARGET bitpolymul)
        set(BITPOLYMUL_FOUND ON)
    else()
        set(BITPOLYMUL_FOUND OFF)
    endif()
endmacro()

if(FETCH_BITPOLYMUL_IMPL)
    FIND_BITPOLYMUL(QUIET)

    include("${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getBitpolymul.cmake")
endif()

if (ENABLE_BITPOLYMUL)
    FIND_BITPOLYMUL()

    if(NOT TARGET bitpolymul)
        message(FATAL_ERROR "failed to find bitpolymul. Looked at OC_THIRDPARTY_HINT=${OC_THIRDPARTY_HINT}")
    endif()
endif ()


# resort the previous prefix path
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})
cmake_policy(POP)