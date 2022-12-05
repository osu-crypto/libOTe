
if(MSVC)
    set(OC_CONFIG "x64-${CMAKE_BUILD_TYPE}")
elseif(APPLE)
    set(OC_CONFIG "osx")
else()
    set(OC_CONFIG "linux")
endif()


if(NOT DEFINED LIBOTE_BUILD_TYPE)
	if(DEFINED CMAKE_BUILD_TYPE)
		set(LIBOTE_BUILD_TYPE ${CMAKE_BUILD_TYPE})
	else()
		set(LIBOTE_BUILD_TYPE "Release")
	endif()
endif()

if(MSVC)
    set(LIBOTE_CONFIG_NAME "${LIBOTE_BUILD_TYPE}")
    if("${LIBOTE_CONFIG_NAME}" STREQUAL "RelWithDebInfo" )
        set(LIBOTE_CONFIG_NAME "Release")
	endif()
    set(OC_CONFIG "x64-${LIBOTE_CONFIG_NAME}")
elseif(APPLE)
    set(OC_CONFIG "osx")
else()
    set(OC_CONFIG "linux")
endif()

if(NOT LIBOTE_BUILD_DIR)
    set(LIBOTE_BUILD_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/build/${OC_CONFIG}")
else()
    message(STATUS "LIBOTE_BUILD_DIR preset to ${LIBOTE_BUILD_DIR}")
endif()


set(LIBOTE_INSOURCE_FIND_DEPS (EXISTS ${CMAKE_CURRENT_LIST_DIR}/libOTeFindBuildDir.cmake))
if(NOT DEFINED OC_THIRDPARTY_HINT)
    if(LIBOTE_INSOURCE_FIND_DEPS)
        # we currenty are in the libOTe source tree, libOTe/cmake
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../out/install/${OC_CONFIG}")

        if(NOT DEFINED OC_THIRDPARTY_INSTALL_PREFIX)
            set(OC_THIRDPARTY_INSTALL_PREFIX ${OC_THIRDPARTY_HINT})
        endif()
    else()
        # we currenty are in install tree, <install-prefix>/lib/cmake/libOTe
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../../..")
    endif()
endif()


if(NOT OC_THIRDPARTY_CLONE_DIR)
    set(OC_THIRDPARTY_CLONE_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/")
endif()


if(NOT CRYPTOTOOLS_BUILD_DIR)
    set(CRYPTOTOOLS_BUILD_DIR "${LIBOTE_BUILD_DIR}/cryptoTools/")
endif()

if(NOT EXISTS "${LIBOTE_BUILD_DIR}")
    message(FATAL_ERROR "failed to find the libOTe build directory. Looked at LIBOTE_BUILD_DIR: ${LIBOTE_BUILD_DIR}")
endif()