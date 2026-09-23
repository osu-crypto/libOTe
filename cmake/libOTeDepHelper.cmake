include_guard(GLOBAL)

cmake_policy(PUSH)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0045 NEW)
cmake_policy(SET CMP0074 NEW)



set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
set(CMAKE_PREFIX_PATH "${OC_THIRDPARTY_HINT};${CMAKE_PREFIX_PATH}")

#if(LIBOTE_BUILD)
#    include(${CMAKE_CURRENT_LIST_DIR}/../cryptoTools/cmake/cryptoToolsDepHelper.cmake)
#endif()

## bitpolymul
###########################################################################

macro(FIND_BITPOLYMUL)
    if(FETCH_BITPOLYMUL)
        set(BITPOLYMUL_DP NO_DEFAULT_PATH PATHS ${OC_THIRDPARTY_HINT})
    elseif(${NO_CMAKE_SYSTEM_PATH})
        list(APPEND ARGS NO_DEFAULT_PATH PATHS ${CMAKE_PREFIX_PATH})
    else()
        unset(BITPOLYMUL_DP)
    endif()
    
    set(BOTPOLYMUL_OPTIONS )
    if(ENABLE_ASAN)
        set(BOTPOLYMUL_OPTIONS ${BOTPOLYMUL_OPTIONS} asan)
    else()
        set(BOTPOLYMUL_OPTIONS ${BOTPOLYMUL_OPTIONS} no_asan)
    endif()
    if(ENABLE_PIC)
        set(BOTPOLYMUL_OPTIONS ${BOTPOLYMUL_OPTIONS} pic)
    else()
        set(BOTPOLYMUL_OPTIONS ${BOTPOLYMUL_OPTIONS} no_pic)
    endif()


    find_package(bitpolymul ${BITPOLYMUL_DP} ${ARGN} COMPONENTS ${BOTPOLYMUL_OPTIONS})
    if(TARGET bitpolymul)
        set(BITPOLYMUL_FOUND ON)
    else()
        set(BITPOLYMUL_FOUND OFF)
    endif()
endmacro()

if(FETCH_BITPOLYMUL_IMPL)
    FIND_BITPOLYMUL(QUIET)

    include(${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getBitpolymul.cmake)
endif()

if (ENABLE_BITPOLYMUL)
    FIND_BITPOLYMUL()

    if(NOT TARGET bitpolymul)
        message(FATAL_ERROR "failed to find bitpolymul. Looked at OC_THIRDPARTY_HINT=${OC_THIRDPARTY_HINT}")
    endif()
endif()

## SEAL
###########################################################################

function(CONFIGURE_SEAL_IMPORTED_CONFIGS)
    if(NOT TARGET SEAL::seal)
        return()
    endif()

    get_target_property(SEAL_IMPORTED_CONFIGS SEAL::seal IMPORTED_CONFIGURATIONS)
    if(NOT SEAL_IMPORTED_CONFIGS)
        return()
    endif()

    if(RELWITHDEBINFO IN_LIST SEAL_IMPORTED_CONFIGS)
        set(SEAL_IMPORTED_FALLBACK RELWITHDEBINFO)
    elseif(RELEASE IN_LIST SEAL_IMPORTED_CONFIGS)
        set(SEAL_IMPORTED_FALLBACK RELEASE)
    else()
        list(GET SEAL_IMPORTED_CONFIGS 0 SEAL_IMPORTED_FALLBACK)
    endif()

    foreach(SEAL_CONFIG DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
        if(NOT SEAL_CONFIG IN_LIST SEAL_IMPORTED_CONFIGS)
            set_property(TARGET SEAL::seal PROPERTY
                MAP_IMPORTED_CONFIG_${SEAL_CONFIG} ${SEAL_IMPORTED_FALLBACK})

            foreach(SEAL_PROPERTY
                    IMPORTED_LOCATION
                    IMPORTED_IMPLIB
                    IMPORTED_LINK_INTERFACE_LANGUAGES)
                get_target_property(SEAL_PROPERTY_VALUE SEAL::seal
                    ${SEAL_PROPERTY}_${SEAL_IMPORTED_FALLBACK})

                if(NOT SEAL_PROPERTY_VALUE STREQUAL "SEAL_PROPERTY_VALUE-NOTFOUND")
                    set_property(TARGET SEAL::seal PROPERTY
                        ${SEAL_PROPERTY}_${SEAL_CONFIG} "${SEAL_PROPERTY_VALUE}")
                endif()
            endforeach()

            set_property(TARGET SEAL::seal APPEND PROPERTY
                IMPORTED_CONFIGURATIONS ${SEAL_CONFIG})
        endif()
    endforeach()
endfunction()

macro(FIND_SEAL)
    if(FETCH_SEAL)
        set(SEAL_DP NO_DEFAULT_PATH PATHS ${OC_THIRDPARTY_HINT})
    elseif(${NO_CMAKE_SYSTEM_PATH})
        set(SEAL_DP NO_DEFAULT_PATH PATHS ${CMAKE_PREFIX_PATH})
    else()
        unset(SEAL_DP)
    endif()

    find_package(SEAL 4.1.1 EXACT ${SEAL_DP} ${ARGN})

    CONFIGURE_SEAL_IMPORTED_CONFIGS()
endmacro()

if(FETCH_SEAL_IMPL)
    FIND_SEAL(QUIET)

    include(${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getSeal.cmake)
endif()

if(ENABLE_LOGVOLE)
    FIND_SEAL(REQUIRED)

    if(NOT TARGET SEAL::seal)
        message(FATAL_ERROR "ENABLE_LOGVOLE requires stock Microsoft SEAL target SEAL::seal")
    endif()
endif()



## SPIN (source override, installed package, or pinned shallow fetch)
###########################################################################
if(ENABLE_SPIN AND NOT TARGET spin::spin)
    if(LIBOTE_BUILD AND LIBOTE_SPIN_SOURCE)
        add_subdirectory("${LIBOTE_SPIN_SOURCE}" "${CMAKE_CURRENT_BINARY_DIR}/spin")
    else()
        if(FETCH_SPIN)
            set(SPIN_DP NO_DEFAULT_PATH PATHS ${OC_THIRDPARTY_HINT})
        elseif(NO_CMAKE_SYSTEM_PATH)
            set(SPIN_DP NO_DEFAULT_PATH PATHS ${CMAKE_PREFIX_PATH})
        else()
            unset(SPIN_DP)
        endif()
        set(SPIN_REFRESH_MANAGED OFF)
        if(LIBOTE_BUILD AND FETCH_SPIN_IMPL AND LIBOTE_SPIN_FETCH_INSTALL_DIR AND
           (spin_DIR STREQUAL "${LIBOTE_SPIN_FETCH_INSTALL_DIR}/lib/cmake/spin" OR
            spin_DIR STREQUAL "${LIBOTE_SPIN_FETCH_INSTALL_DIR}/lib64/cmake/spin"))
            # Re-evaluate the pin and toolchain key before importing our own cache.
            # The dependency build is incremental when neither has changed.
            unset(spin_DIR CACHE)
            unset(spin_DIR)
            set(SPIN_REFRESH_MANAGED ON)
        endif()
        if(NOT SPIN_REFRESH_MANAGED)
            find_package(spin 0.2 CONFIG QUIET ${SPIN_DP})
        endif()
        if(LIBOTE_BUILD AND (FETCH_SPIN_IMPL OR
           (TARGET spin::spin AND LIBOTE_SPIN_FETCH_INSTALL_DIR)))
            include("${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getSpin.cmake")
        endif()
        if(NOT TARGET spin::spin)
            message(FATAL_ERROR "SPIN 0.2 (PreparedEncoder API) was not found. Install spin 0.2, set LIBOTE_SPIN_SOURCE, or enable FETCH_SPIN/FETCH_AUTO. Set ENABLE_SPIN=OFF to omit it.")
        endif()
    endif()
endif()

# restore the previous prefix path
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})
cmake_policy(POP)
