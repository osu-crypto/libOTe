
include("${CMAKE_CURRENT_LIST_DIR}/libOTeFindBuildDir.cmake")


if(NOT EXISTS "${libOTe_BIN_DIR}/CMakeCache.txt")
    message(FATAL_ERROR "cache file does not exist at ${libOTe_BIN_DIR}")
endif()


LOAD_CACHE("${libOTe_BIN_DIR}/" INCLUDE_INTERNALS 
    ENABLE_BOOST 
    ENABLE_RELIC
    ENABLE_CIRCUITS
    ENABLE_SIMPLESTOT_ASM
    ENABLE_MR_KYBER
    )

