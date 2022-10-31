
set(USER_NAME           )      
set(TOKEN               )      
set(GIT_REPOSITORY      "https://github.com/Visa-Research/coproto.git")
set(GIT_TAG             "a362b3bc783cffe3ffb375a61741607e9f13c219" )

set(CLONE_DIR "${CMAKE_CURRENT_LIST_DIR}/coproto")
set(BUILD_DIR "${CLONE_DIR}/out/build/${OC_CONFIG}")
set(LOG_FILE  "${CMAKE_CURRENT_LIST_DIR}/log-coproto.txt")

include("${CMAKE_CURRENT_LIST_DIR}/fetch.cmake")

if(NOT COPROTO_FOUND)
    find_program(GIT git REQUIRED)
    set(DOWNLOAD_CMD  ${GIT} clone ${GIT_REPOSITORY})
    set(CHECKOUT_CMD  ${GIT} checkout ${GIT_TAG})
    set(CONFIGURE_CMD ${CMAKE_COMMAND} -S ${CLONE_DIR} -B ${BUILD_DIR} -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
                       -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE} -DVERBOSE_FETCH=${VERBOSE_FETCH}
                       -DCOPROTO_FETCH_AUTO=true
                       -DCOPROTO_ENABLE_BOOST=${COPROTO_ENABLE_BOOST}
                       -DCOPROTO_ENABLE_OPENSSL=${COPROTO_ENABLE_OPENSSL}
                       -DCOPROTO_CPP_VER=${LIBOTE_CPP_VER}
                       -DCOPROTO_PIC=${OC_PIC}
                       )
    set(BUILD_CMD     ${CMAKE_COMMAND} --build ${BUILD_DIR} --config ${CMAKE_BUILD_TYPE})
    set(INSTALL_CMD   ${CMAKE_COMMAND} --install ${BUILD_DIR} --config ${CMAKE_BUILD_TYPE} --prefix ${OC_THIRDPARTY_INSTALL_PREFIX})


    message("============= Building coproto =============")
    if(NOT EXISTS ${CLONE_DIR})
        run(NAME "Cloning ${GIT_REPOSITORY}" CMD ${DOWNLOAD_CMD} WD ${CMAKE_CURRENT_LIST_DIR})
    endif()

    run(NAME "Checkout ${GIT_TAG} " CMD ${CHECKOUT_CMD}  WD ${CLONE_DIR})
    run(NAME "Configure"       CMD ${CONFIGURE_CMD} WD ${CLONE_DIR})
    run(NAME "Build"           CMD ${BUILD_CMD}     WD ${CLONE_DIR})
    run(NAME "Install"         CMD ${INSTALL_CMD}   WD ${CLONE_DIR})

    message("log ${LOG_FILE}\n==========================================")
else()
    message("coproto already fetched.")
endif()

install(CODE "
    execute_process(
        COMMAND ${SUDO} \${CMAKE_COMMAND} --install ${BUILD_DIR} --config ${CMAKE_BUILD_TYPE} --prefix \${CMAKE_INSTALL_PREFIX}
        WORKING_DIRECTORY ${CLONE_DIR}
        RESULT_VARIABLE RESULT
        COMMAND_ECHO STDOUT
    )
")
