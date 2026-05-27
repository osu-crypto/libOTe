

add_library(libOTe_Tests STATIC 

    BaseOT_Tests.cpp
    bitpolymul_Tests.cpp
    Common.cpp
    EACode_Tests.cpp
    ExConvCode_Tests.cpp
    NcoOT_Tests.cpp
    OT_Tests.cpp
    Pprf_Tests.cpp
    Dpf_Tests.cpp
    SilentOT_Tests.cpp
    SoftSpoken_Tests.cpp
    TungstenCode_Tests.cpp
    UnitTests.cpp
    Vole_Tests.cpp
    Foleage_Tests.cpp
    Permutation_Tests.cpp
    BlkAccCode_Tests.cpp)

target_link_libraries(libOTe_Tests libOTe)


# make projects that include libOTe_Tests use this as an include folder
target_include_directories(libOTe_Tests PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 
target_include_directories(libOTe_Tests PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 


if(MSVC)
    target_compile_options(libOTe_Tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBOTE_STD_VER}>)
    
else()
    target_compile_options(libOTe_Tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER}>)
endif()

if(ENABLE_LOGVOLE)
    find_package(GTest CONFIG QUIET)
    if(NOT TARGET GTest::gtest)
        if(FETCH_AUTO)
            include(FetchContent)
            set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
            FetchContent_Declare(
                googletest
                URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
                URL_HASH SHA256=1f357c27ca988c3f7c6b4bf68a9395005ac6761f034046e9dde0896e3aba00e4
                DOWNLOAD_EXTRACT_TIMESTAMP TRUE
            )
            FetchContent_MakeAvailable(googletest)
            if(TARGET gtest AND NOT TARGET GTest::gtest)
                add_library(GTest::gtest ALIAS gtest)
            endif()
        endif()
    endif()

    if(NOT TARGET GTest::gtest)
        message(FATAL_ERROR "ENABLE_LOGVOLE requires GTest for the imported LogVole tests. Enable FETCH_AUTO or provide GTest::gtest.")
    endif()

    enable_testing()

    set(LOGVOLE_TEST_DIR ${CMAKE_CURRENT_LIST_DIR}/LogVole/tests)

    function(add_logvole_gtest target)
        add_executable(${target})
        target_sources(${target} PRIVATE ${ARGN})
        target_link_libraries(${target} PRIVATE libOTe GTest::gtest)
        target_include_directories(${target} PRIVATE ${LOGVOLE_TEST_DIR})
        if(MSVC)
            target_compile_options(${target} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBOTE_STD_VER}>)
        else()
            target_compile_options(${target} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER}>)
        endif()
    endfunction()

    add_logvole_gtest(logvole_comm_tests
        ${LOGVOLE_TEST_DIR}/test_main.cpp
        ${LOGVOLE_TEST_DIR}/test_round_dsl_compile.cpp
        ${LOGVOLE_TEST_DIR}/test_comm_inmemory.cpp
        ${LOGVOLE_TEST_DIR}/test_comm_validation.cpp
        ${LOGVOLE_TEST_DIR}/test_comm_counters.cpp
        ${LOGVOLE_TEST_DIR}/test_comm_uds.cpp
        ${LOGVOLE_TEST_DIR}/test_comm_tcp.cpp
    )
    add_test(NAME LogVoleCommTests COMMAND logvole_comm_tests)
    set_tests_properties(LogVoleCommTests PROPERTIES LABELS "logvole-comm-unit;logvole-comm-flow")

    add_logvole_gtest(logvole_keyderive_tests
        ${LOGVOLE_TEST_DIR}/test_main.cpp
        ${LOGVOLE_TEST_DIR}/test_keyderive.cpp
    )
    add_test(NAME LogVoleKeyderiveTests COMMAND logvole_keyderive_tests)
    set_tests_properties(LogVoleKeyderiveTests PROPERTIES LABELS "logvole-keyderive-unit;logvole-keyderive-flow")

    add_logvole_gtest(logvole_shrinkexpand_tests
        ${LOGVOLE_TEST_DIR}/test_main.cpp
        ${LOGVOLE_TEST_DIR}/test_ring_ops.cpp
        ${LOGVOLE_TEST_DIR}/test_shrinkexpand.cpp
    )
    add_test(NAME LogVoleShrinkExpandTests COMMAND logvole_shrinkexpand_tests)
    set_tests_properties(LogVoleShrinkExpandTests PROPERTIES LABELS "logvole-shrinkexpand-unit;logvole-shrinkexpand-flow")

    add_logvole_gtest(logvole_lenc_tests
        ${LOGVOLE_TEST_DIR}/test_main.cpp
        ${LOGVOLE_TEST_DIR}/test_lenc.cpp
    )
    add_test(NAME LogVoleLencTests COMMAND logvole_lenc_tests)
    set_tests_properties(LogVoleLencTests PROPERTIES LABELS "logvole-lenc-unit;logvole-lenc-flow")
endif()
