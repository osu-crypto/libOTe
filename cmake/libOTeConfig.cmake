# these are just pass through config file for the ones that are placed in the build directory.

if(MSVC)
    set(LIBOTE_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/win")
else()
    set(LIBOTE_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/unix")
endif()
include("${CMAKE_CURRENT_LIST_DIR}/libOTeFindBuildDir.cmake")
include("${LIBOTE_BUILD_DIR}/libOTeConfig.cmake")
 