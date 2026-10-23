set(GIT_REPOSITORY https://github.com/ladnir/spin_codes.git)
set(GIT_TAG "f2010e03d2dbe5003e90c89ba346c743793536a6")
set(CLONE_DIR "${OC_THIRDPARTY_CLONE_DIR}/spin")
set(BUILD_DIR "${CLONE_DIR}/out/build/${OC_CONFIG}")
set(LOG_FILE "${CMAKE_CURRENT_LIST_DIR}/log-spin.txt")
set(CONFIG --config ${CMAKE_BUILD_TYPE})

include("${CMAKE_CURRENT_LIST_DIR}/fetch.cmake")

if(NOT TARGET spin::spin AND (NOT EXISTS "${BUILD_DIR}" OR NOT spin_FOUND))
    find_program(GIT git REQUIRED)
    # Fetch only the pinned snapshot, not the repository's research history.
    file(MAKE_DIRECTORY "${OC_THIRDPARTY_CLONE_DIR}")
    if(NOT EXISTS "${CLONE_DIR}")
        run(NAME "Initialize SPIN" CMD ${GIT} init "${CLONE_DIR}"
            WD "${OC_THIRDPARTY_CLONE_DIR}")
        run(NAME "Enable long paths" CMD ${GIT} config core.longpaths true WD "${CLONE_DIR}")
    endif()
    run(NAME "Fetch SPIN" CMD ${GIT} fetch --depth 1 --no-tags ${GIT_REPOSITORY} ${GIT_TAG}
        WD "${CLONE_DIR}")
    run(NAME "Checkout ${GIT_TAG}" CMD ${GIT} checkout --detach ${GIT_TAG} WD "${CLONE_DIR}")

    set(CONFIGURE_CMD ${CMAKE_COMMAND} -S "${CLONE_DIR}/spin" -B "${BUILD_DIR}"
        -G "${CMAKE_GENERATOR}"
        "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
        "-DCMAKE_INSTALL_PREFIX=${OC_THIRDPARTY_INSTALL_PREFIX}"
        "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}" -DSPIN_BUILD_TESTS=OFF)
    if(CMAKE_TOOLCHAIN_FILE)
        list(APPEND CONFIGURE_CMD "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}")
    endif()
    if(CMAKE_GENERATOR_PLATFORM)
        list(APPEND CONFIGURE_CMD -A "${CMAKE_GENERATOR_PLATFORM}")
    endif()
    if(CMAKE_GENERATOR_TOOLSET)
        list(APPEND CONFIGURE_CMD -T "${CMAKE_GENERATOR_TOOLSET}")
    endif()
    set(BUILD_CMD ${CMAKE_COMMAND} --build "${BUILD_DIR}" ${CONFIG} --parallel ${PARALLEL_FETCH})
    set(INSTALL_CMD ${CMAKE_COMMAND} --install "${BUILD_DIR}" ${CONFIG}
        --prefix "${OC_THIRDPARTY_INSTALL_PREFIX}")
    run(NAME "Configure SPIN" CMD ${CONFIGURE_CMD} WD "${CLONE_DIR}")
    run(NAME "Build SPIN" CMD ${BUILD_CMD} WD "${CLONE_DIR}")
    run(NAME "Install SPIN" CMD ${INSTALL_CMD} WD "${CLONE_DIR}")
endif()

if(EXISTS "${BUILD_DIR}")
    install(CODE "
        if(NOT CMAKE_INSTALL_PREFIX STREQUAL \"${OC_THIRDPARTY_INSTALL_PREFIX}\")
            execute_process(
                COMMAND ${SUDO} \${CMAKE_COMMAND} --install \"${BUILD_DIR}\" ${CONFIG}
                    --prefix \"\${CMAKE_INSTALL_PREFIX}\"
                RESULT_VARIABLE RESULT
                COMMAND_ECHO STDOUT)
            if(NOT RESULT EQUAL 0)
                message(FATAL_ERROR \"Installing SPIN failed: \${RESULT}\")
            endif()
        endif()
    ")
endif()
