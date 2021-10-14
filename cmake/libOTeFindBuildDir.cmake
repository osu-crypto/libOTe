include(${CMAKE_CURRENT_LIST_DIR}/libOTePreample.cmake)


if(NOT CRYPTOTOOLS_BUILD_DIR)
    set(CRYPTOTOOLS_BUILD_DIR "${LIBOTE_BUILD_DIR}/cryptoTools/")
endif()

if(NOT EXISTS "${LIBOTE_BUILD_DIR}")
    message(FATAL_ERROR "failed to find the libOTe build directory. Looked at LIBOTE_BUILD_DIR: ${LIBOTE_BUILD_DIR}")
endif()