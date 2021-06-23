cmake_policy(PUSH)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0045 NEW)
cmake_policy(SET CMP0074 NEW)


if(NOT DEFINED OC_THIRDPARTY_HINT)

    if(MSVC)
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/win/")
    else()
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/unix/")
    endif()

    if(NOT EXISTS ${OC_THIRDPARTY_HINT})
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../../..")
    endif()
endif()

set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};${OC_THIRDPARTY_HINT}")


## bitpolymul
###########################################################################

if (ENABLE_BITPOLYMUL)
    find_package(bitpolymul)
endif ()

# resort the previous prefix path
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})
cmake_policy(POP)