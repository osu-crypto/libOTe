include_guard(GLOBAL)

cmake_policy(PUSH)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0045 NEW)
cmake_policy(SET CMP0074 NEW)



set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
set(CMAKE_PREFIX_PATH "${OC_THIRDPARTY_HINT};${CMAKE_PREFIX_PATH}")

#if(LIBOTE_BUILD)
#    include(${CMAKE_CURRENT_LIST_DIR}/../cryptoTools/cmake/cryptoToolsDepHelper.cmake)
#endif()

## bitpolymul
###########################################################################

macro(FIND_BITPOLYMUL)
    if(FETCH_BITPOLYMUL)
        set(BITPOLYMUL_DP NO_DEFAULT_PATH PATHS ${OC_THIRDPARTY_HINT})
    elseif(${NO_CMAKE_SYSTEM_PATH})
        list(APPEND ARGS NO_DEFAULT_PATH PATHS ${CMAKE_PREFIX_PATH})
    else()
        unset(BITPOLYMUL_DP)
    endif()
    
    set(BOTPOLYMUL_OPTIONS )
    if(ENABLE_ASAN)
        set(BOTPOLYMUL_OPTIONS ${BOTPOLYMUL_OPTIONS} asan)
    else()
        set(BOTPOLYMUL_OPTIONS ${BOTPOLYMUL_OPTIONS} no_asan)
    endif()
    if(ENABLE_PIC)
        set(BOTPOLYMUL_OPTIONS ${BOTPOLYMUL_OPTIONS} pic)
    else()
        set(BOTPOLYMUL_OPTIONS ${BOTPOLYMUL_OPTIONS} no_pic)
    endif()


    find_package(bitpolymul ${BITPOLYMUL_DP} ${ARGN} COMPONENTS ${BOTPOLYMUL_OPTIONS})
    if(TARGET bitpolymul)
        set(BITPOLYMUL_FOUND ON)
    else()
        set(BITPOLYMUL_FOUND OFF)
    endif()
endmacro()

if(FETCH_BITPOLYMUL_IMPL)
    FIND_BITPOLYMUL(QUIET)

    include(${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getBitpolymul.cmake)
endif()

if (ENABLE_BITPOLYMUL)
    FIND_BITPOLYMUL()

    if(NOT TARGET bitpolymul)
        message(FATAL_ERROR "failed to find bitpolymul. Looked at OC_THIRDPARTY_HINT=${OC_THIRDPARTY_HINT}")
    endif()
endif()



# resort the previous prefix path
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})
cmake_policy(POP)