# these are just pass through config file for the ones that are placed in the build directory.


include("${CMAKE_CURRENT_LIST_DIR}/libOTeFindBuildDir.cmake")

if(NOT DEFINED OC_THIRDPARTY_HINT)
    if(MSVC)
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../cryptoTools/thirdparty/win/")
    else()
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../cryptoTools/thirdparty/unix/")
    endif()
endif()
if(NOT DEFINED LIBOTE_THIRDPARTY_HINT)
    if(MSVC)
        set(LIBOTE_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/win/")
    else()
        set(LIBOTE_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/unix/")
    endif()
endif()


include("${LIBOTE_BUILD_DIR}/libOTeConfig.cmake")
