
set(DEP_NAME            seal)
set(GIT_REPOSITORY      https://github.com/microsoft/SEAL.git)
set(GIT_TAG             "206648d0e4634e5c61dcf9370676630268290b59")

set(CLONE_DIR "${OC_THIRDPARTY_CLONE_DIR}/${DEP_NAME}-4.1.1")
set(BUILD_DIR "${CLONE_DIR}/out/build/${OC_CONFIG}")
set(LOG_FILE  "${CMAKE_CURRENT_LIST_DIR}/log-${DEP_NAME}.txt")
set(CONFIG    --config ${CMAKE_BUILD_TYPE})

function(GET_SEAL_INSTALL_CONFIG OUT_VAR)
    set(SEAL_INSTALL_CONFIG "${CMAKE_BUILD_TYPE}")
    set(SEAL_CACHE_FILE "${BUILD_DIR}/CMakeCache.txt")

    if(EXISTS "${SEAL_CACHE_FILE}")
        file(STRINGS "${SEAL_CACHE_FILE}" SEAL_CACHE_BUILD_TYPE
            REGEX "^CMAKE_BUILD_TYPE:[^=]*=")

        if(SEAL_CACHE_BUILD_TYPE)
            string(REGEX REPLACE "^CMAKE_BUILD_TYPE:[^=]*=" ""
                SEAL_INSTALL_CONFIG "${SEAL_CACHE_BUILD_TYPE}")
        endif()
    endif()

    if(SEAL_INSTALL_CONFIG)
        set(${OUT_VAR} --config ${SEAL_INSTALL_CONFIG} PARENT_SCOPE)
    else()
        set(${OUT_VAR} PARENT_SCOPE)
    endif()
endfunction()

include("${CMAKE_CURRENT_LIST_DIR}/fetch.cmake")

set(SEAL_FETCH_BUILD_AVAILABLE OFF)

if(NOT TARGET SEAL::seal AND (NOT EXISTS ${BUILD_DIR} OR NOT SEAL_FOUND))
    find_program(GIT git REQUIRED)
    set(DOWNLOAD_CMD  ${GIT} clone ${GIT_REPOSITORY} ${CLONE_DIR})
    set(CHECKOUT_CMD  ${GIT} checkout ${GIT_TAG})
    set(CONFIGURE_CMD ${CMAKE_COMMAND} -S ${CLONE_DIR} -B ${BUILD_DIR}
                       -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
                       -DCMAKE_INSTALL_PREFIX=${OC_THIRDPARTY_INSTALL_PREFIX}
                       -DBUILD_SHARED_LIBS=OFF
                       -DSEAL_BUILD_BENCH=OFF
                       -DSEAL_BUILD_EXAMPLES=OFF
                       -DSEAL_BUILD_SEAL_C=OFF
                       -DSEAL_BUILD_TESTS=OFF
                       -DSEAL_USE_ZLIB=OFF
                       -DSEAL_USE_ZSTD=OFF
                       -DSEAL_USE_INTEL_HEXL=OFF)
    set(BUILD_CMD     ${CMAKE_COMMAND} --build ${BUILD_DIR} ${CONFIG} --parallel ${PARALLEL_FETCH})
    set(INSTALL_CMD   ${CMAKE_COMMAND} --install ${BUILD_DIR} ${CONFIG} --prefix ${OC_THIRDPARTY_INSTALL_PREFIX})

    message("============= Building ${DEP_NAME} =============")
    if(NOT EXISTS ${CLONE_DIR})
        run(NAME "Cloning ${GIT_REPOSITORY}" CMD ${DOWNLOAD_CMD} WD ${OC_THIRDPARTY_CLONE_DIR})
    endif()

    run(NAME "Checkout ${GIT_TAG} " CMD ${CHECKOUT_CMD}  WD ${CLONE_DIR})
    run(NAME "Configure"       CMD ${CONFIGURE_CMD} WD ${CLONE_DIR})
    run(NAME "Build"           CMD ${BUILD_CMD}     WD ${CLONE_DIR})
    run(NAME "Install"         CMD ${INSTALL_CMD}   WD ${CLONE_DIR})

    set(SEAL_FETCH_BUILD_AVAILABLE ON)
    message("log ${LOG_FILE}\n==========================================")
else()
    if(EXISTS ${BUILD_DIR})
        set(SEAL_FETCH_BUILD_AVAILABLE ON)
    endif()
    message("${DEP_NAME} already available.")
endif()

if(SEAL_FETCH_BUILD_AVAILABLE)
    get_seal_install_config(SEAL_INSTALL_CONFIG)

    install(CODE "
        if(NOT CMAKE_INSTALL_PREFIX STREQUAL \"${OC_THIRDPARTY_INSTALL_PREFIX}\")
            execute_process(
                COMMAND ${SUDO} \${CMAKE_COMMAND} --install \"${BUILD_DIR}\" ${SEAL_INSTALL_CONFIG} --prefix \${CMAKE_INSTALL_PREFIX}
                WORKING_DIRECTORY ${CLONE_DIR}
                RESULT_VARIABLE RESULT
                COMMAND_ECHO STDOUT
            )
            if(NOT RESULT EQUAL 0)
                message(FATAL_ERROR \"Installing ${DEP_NAME} failed: \${RESULT}\")
            endif()
        endif()
    ")
endif()
