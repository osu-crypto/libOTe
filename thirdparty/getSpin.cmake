# Use the same configure/build/install pattern as the other libOTe dependencies.
# The source cache contains one pinned commit, not the repository's research history.
function(libote_fetch_spin)
    if(TARGET spin::spin)
        # Keep installation transitive on later CMake runs too, when find_package
        # has already located this build's fetched package.
        if(LIBOTE_SPIN_FETCH_INSTALL_DIR AND
           (spin_DIR STREQUAL "${LIBOTE_SPIN_FETCH_INSTALL_DIR}/lib/cmake/spin" OR
            spin_DIR STREQUAL "${LIBOTE_SPIN_FETCH_INSTALL_DIR}/lib64/cmake/spin"))
            install(DIRECTORY "${LIBOTE_SPIN_FETCH_INSTALL_DIR}/" DESTINATION ".")
        endif()
        return()
    endif()
    set(SPIN_REVISION "5abbb3312a9d02a2f7650d267c357920e041f955")
    set(SPIN_REPOSITORY "https://github.com/ladnir/spin_codes.git")
    set(CLONE_DIR "${OC_THIRDPARTY_CLONE_DIR}/spin-${SPIN_REVISION}")
    set(LOG_FILE "${CMAKE_CURRENT_BINARY_DIR}/log-spin.txt")
    include("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/fetch.cmake")
    find_package(Git REQUIRED)
    file(MAKE_DIRECTORY "${OC_THIRDPARTY_CLONE_DIR}")
    if(NOT EXISTS "${CLONE_DIR}/.git")
        run(NAME "Initialize SPIN source cache" CMD ${GIT_EXECUTABLE} init "${CLONE_DIR}"
            WD "${OC_THIRDPARTY_CLONE_DIR}")
        run(NAME "Enable long paths in the SPIN source cache" CMD ${GIT_EXECUTABLE} config core.longpaths true
            WD "${CLONE_DIR}")
        run(NAME "Fetch pinned SPIN snapshot" CMD ${GIT_EXECUTABLE} fetch --depth 1 --no-tags
            "${SPIN_REPOSITORY}" "${SPIN_REVISION}" WD "${CLONE_DIR}")
        run(NAME "Checkout SPIN snapshot" CMD ${GIT_EXECUTABLE} checkout --detach "${SPIN_REVISION}"
            WD "${CLONE_DIR}")
    endif()
    execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse HEAD WORKING_DIRECTORY "${CLONE_DIR}"
        OUTPUT_VARIABLE SPIN_HEAD OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE SPIN_HEAD_STATUS)
    execute_process(COMMAND ${GIT_EXECUTABLE} status --porcelain WORKING_DIRECTORY "${CLONE_DIR}"
        OUTPUT_VARIABLE SPIN_DIRTY OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE SPIN_STATUS)
    if(NOT SPIN_HEAD_STATUS EQUAL 0 OR NOT SPIN_STATUS EQUAL 0 OR
       NOT SPIN_HEAD STREQUAL SPIN_REVISION OR SPIN_DIRTY)
        message(FATAL_ERROR "SPIN fetch cache is incomplete or modified: ${CLONE_DIR}. Use LIBOTE_SPIN_SOURCE for editable sources, or a fresh OC_THIRDPARTY_CLONE_DIR.")
    endif()

    # Keep build products private to this libOTe build and its toolchain/configuration.
    set(SPIN_TOOLCHAIN_HASH "")
    if(CMAKE_TOOLCHAIN_FILE)
        file(SHA256 "${CMAKE_TOOLCHAIN_FILE}" SPIN_TOOLCHAIN_HASH)
    endif()
    string(SHA256 SPIN_BUILD_KEY "${SPIN_REVISION};${CMAKE_CXX_COMPILER};${CMAKE_CXX_COMPILER_VERSION};${CMAKE_GENERATOR};${CMAKE_GENERATOR_PLATFORM};${CMAKE_GENERATOR_TOOLSET};${CMAKE_BUILD_TYPE};${CMAKE_CXX_FLAGS};${CMAKE_CXX_FLAGS_DEBUG};${CMAKE_CXX_FLAGS_RELEASE};${CMAKE_CXX_FLAGS_RELWITHDEBINFO};${CMAKE_MSVC_RUNTIME_LIBRARY};${SPIN_TOOLCHAIN_HASH};${CMAKE_OSX_ARCHITECTURES};${CMAKE_OSX_DEPLOYMENT_TARGET}")
    set(BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/_deps/spin/${SPIN_BUILD_KEY}/build")
    set(INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/_deps/spin/${SPIN_BUILD_KEY}/install")
    set(SPIN_CONFIG "${CMAKE_BUILD_TYPE}")
    if(NOT SPIN_CONFIG)
        set(SPIN_CONFIG Release)
    endif()
    set(CONFIGURE_CMD ${CMAKE_COMMAND} -S "${CLONE_DIR}/spin" -B "${BUILD_DIR}"
        -G "${CMAKE_GENERATOR}"
        "-DCMAKE_BUILD_TYPE=${SPIN_CONFIG}" "-DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}"
        "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}" -DSPIN_BUILD_TESTS=OFF)
    foreach(SPIN_OPTION CMAKE_TOOLCHAIN_FILE CMAKE_MAKE_PROGRAM CMAKE_GENERATOR_INSTANCE
            CMAKE_CXX_COMPILER_TARGET CMAKE_MSVC_RUNTIME_LIBRARY CMAKE_OSX_ARCHITECTURES
            CMAKE_OSX_DEPLOYMENT_TARGET CMAKE_OSX_SYSROOT CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG
            CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_MINSIZEREL)
        if(DEFINED ${SPIN_OPTION})
            list(APPEND CONFIGURE_CMD "-D${SPIN_OPTION}=${${SPIN_OPTION}}")
        endif()
    endforeach()
    if(CMAKE_GENERATOR_PLATFORM)
        list(APPEND CONFIGURE_CMD -A "${CMAKE_GENERATOR_PLATFORM}")
    endif()
    if(CMAKE_GENERATOR_TOOLSET)
        list(APPEND CONFIGURE_CMD -T "${CMAKE_GENERATOR_TOOLSET}")
    endif()
    run(NAME "Configure SPIN" CMD ${CONFIGURE_CMD} WD "${CLONE_DIR}")
    run(NAME "Build SPIN" CMD ${CMAKE_COMMAND} --build "${BUILD_DIR}" --config "${SPIN_CONFIG}"
        --parallel ${PARALLEL_FETCH} WD "${CLONE_DIR}")
    run(NAME "Install SPIN" CMD ${CMAKE_COMMAND} --install "${BUILD_DIR}" --config "${SPIN_CONFIG}"
        WD "${CLONE_DIR}")
    # A normal installed dependency thereafter; export it transitively with libOTe.
    find_package(spin 0.1 CONFIG REQUIRED PATHS "${INSTALL_DIR}/lib/cmake/spin"
        "${INSTALL_DIR}/lib64/cmake/spin" NO_DEFAULT_PATH)
    set(LIBOTE_SPIN_FETCH_INSTALL_DIR "${INSTALL_DIR}" CACHE INTERNAL "This build's fetched SPIN installation" FORCE)
    install(DIRECTORY "${INSTALL_DIR}/" DESTINATION ".")
endfunction()
libote_fetch_spin()
