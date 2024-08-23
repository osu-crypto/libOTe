# these are just pass through config file for the ones that are placed in the build directory.

set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})

#used to find coproto, macoro
include("${CMAKE_CURRENT_LIST_DIR}/libOTePreamble.cmake")
set(CMAKE_PREFIX_PATH "${LIBOTE_BUILD_DIR}/macoro;${CMAKE_PREFIX_PATH}")
set(CMAKE_PREFIX_PATH "${LIBOTE_BUILD_DIR}/coproto;${CMAKE_PREFIX_PATH}")

include("${LIBOTE_BUILD_DIR}/libOTeConfig.cmake")
 
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})