set(DEP_NAME            libdivide)
set(GIT_REPOSITORY      https://github.com/ridiculousfish/libdivide.git)
set(GIT_TAG             "b322221677351ebb11f0a42fe9a9a2794da5bfe5" )

set(CLONE_DIR "${OC_THIRDPARTY_CLONE_DIR}/${DEP_NAME}")
set(BUILD_DIR "${CLONE_DIR}/out/build/${VOLEPSI_CONFIG}")
set(LOG_FILE  "${CMAKE_CURRENT_LIST_DIR}/log-${DEP_NAME}.txt")


include("${CMAKE_CURRENT_LIST_DIR}/fetch.cmake")

if(NOT LIBDIVIDE_FOUND)
    find_program(GIT git REQUIRED)
    set(DOWNLOAD_CMD  ${GIT} clone ${GIT_REPOSITORY})
    set(CHECKOUT_CMD  ${GIT} checkout ${GIT_TAG})
    
    #set(INSTALL_CMD   ${CMAKE_COMMAND} --install ${BUILD_DIR} --prefix ${VOLEPSI_THIRDPARTY_DIR})


    message("============= Building ${DEP_NAME} =============")
    if(NOT EXISTS ${CLONE_DIR})
        run(NAME "Cloning ${GIT_REPOSITORY}" CMD ${DOWNLOAD_CMD} WD ${OC_THIRDPARTY_CLONE_DIR})
    endif()

    run(NAME "Checkout ${GIT_TAG} " CMD ${CHECKOUT_CMD}  WD ${CLONE_DIR})
    message("Install: cp ${CLONE_DIR}/libdivide.h  ${OC_THIRDPARTY_INSTALL_PREFIX}/include/")
    file(COPY ${CLONE_DIR}/libdivide.h DESTINATION ${OC_THIRDPARTY_INSTALL_PREFIX}/include/)
    message("log ${LOG_FILE}\n==========================================")
else()
    message("${DEP_NAME} already fetched.")
endif()

install(CODE "
    if(NOT CMAKE_INSTALL_PREFIX STREQUAL \"${OC_THIRDPARTY_INSTALL_PREFIX}\")
        file(INSTALL ${CLONE_DIR}/libdivide.h DESTINATION \${CMAKE_INSTALL_PREFIX}/include/)
    endif()
")