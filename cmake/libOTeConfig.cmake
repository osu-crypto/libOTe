# these are just pass through config file for the ones that are placed in the build directory.



#used to find coproto, macoro
set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
set(CMAKE_PREFIX_PATH "${COPROTO_BUILD_DIR}/macoro;${CMAKE_PREFIX_PATH}")
set(CMAKE_PREFIX_PATH "${COPROTO_BUILD_DIR}/coproto;${CMAKE_PREFIX_PATH}")
#message("\n\nhere ${CMAKE_CURRENT_LIST_FILE}\nCMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH}\n\n")

include("${CMAKE_CURRENT_LIST_DIR}/libOTePreamble.cmake")
include("${LIBOTE_BUILD_DIR}/libOTeConfig.cmake")
 
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})