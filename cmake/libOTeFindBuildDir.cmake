

if(NOT libOTe_BIN_DIR)
    if(MSVC)
        set(CONFIG_NAME "${CMAKE_BUILD_TYPE}")
        if("${CONFIG_NAME}" STREQUAL "RelWithDebInfo" )
            set(CONFIG_NAME "Release")
	    endif()


        set(libOTe_BIN_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/build/x64-${CONFIG_NAME}")
    else()
        set(libOTe_BIN_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/build/linux")

        if(NOT EXISTS "${libOTe_BIN_DIR}")
            set(libOTe_BIN_DIR "${CMAKE_CURRENT_LIST_DIR}/../")
        endif()
    endif()
endif()