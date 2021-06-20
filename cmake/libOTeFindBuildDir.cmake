

if(NOT DEFINED LIBOTE_BUILD_TYPE)
	if(DEFINED CMAKE_BUILD_TYPE)
		set(LIBOTE_BUILD_TYPE ${CMAKE_BUILD_TYPE})
	else()
		set(LIBOTE_BUILD_TYPE "Release")
	endif()
endif()

if(NOT LIBOTE_BUILD_DIR)
    if(MSVC)

        set(LIBOTE_CONFIG_NAME "${LIBOTE_BUILD_TYPE}")
        if("${LIBOTE_CONFIG_NAME}" STREQUAL "RelWithDebInfo" )
            set(LIBOTE_CONFIG_NAME "Release")
	    endif()


        set(LIBOTE_BUILD_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/build/x64-${LIBOTE_CONFIG_NAME}")
    else()
        set(LIBOTE_BUILD_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/build/linux")
    endif()
else()
    message(STATUS "LIBOTE_BUILD_DIR preset to ${LIBOTE_BUILD_DIR}")
endif()


if(NOT CRYPTOTOOLS_BUILD_DIR)
    set(CRYPTOTOOLS_BUILD_DIR "${LIBOTE_BUILD_DIR}/cryptoTools/")
endif()

if(NOT EXISTS "${LIBOTE_BUILD_DIR}")
    message(FATAL_ERROR "failed to find the libOTe build directory. Looked at LIBOTE_BUILD_DIR: ${LIBOTE_BUILD_DIR}")
endif()