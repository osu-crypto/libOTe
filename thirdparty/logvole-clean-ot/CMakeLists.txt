cmake_minimum_required(VERSION 3.16)

project(LogVOLEArtifact LANGUAGES CXX)

option(LOGVOLE_BUILD_TESTS "Build LogVOLE correctness tests" ON)
option(LOGVOLE_BUILD_BENCH "Build LogVOLE benchmarks" ON)
option(LOGVOLE_BUILD_EXAMPLES "Build LogVOLE examples" ON)
set(LOGVOLE_GTEST_SOURCE_DIR "" CACHE PATH "Optional local GoogleTest source directory")
set(LOGVOLE_BENCHMARK_SOURCE_DIR "" CACHE PATH "Optional local Google Benchmark source directory")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(Threads REQUIRED)
find_package(OpenSSL QUIET)
find_package(SEAL 4.1.1 EXACT REQUIRED)

add_library(logvole)
add_library(logvole::logvole ALIAS logvole)

target_sources(logvole
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src/comm/channel.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/comm/codec.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/comm/transport_inmemory.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/comm/transport_socket.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/protocol/seedlabel_backend_seal.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/protocol/seedlabel_shared_ops.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/protocol/civole_protocol.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/protocol/lenc_ops.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/protocol/lhe_ops.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/protocol/logvole_protocol.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/protocol/logvole_shared_ops.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/protocol/ring_ops.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/protocol/shrinkexpand_backend_seal.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/protocol/shrinkexpand_protocol.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/protocol/shrinkexpand_shared_ops.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/protocol/zp_crt_helpers.cpp
)

target_include_directories(logvole
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src/comm
        ${CMAKE_CURRENT_LIST_DIR}/src/protocol
)

target_compile_features(logvole PUBLIC cxx_std_17)
target_link_libraries(logvole PUBLIC Threads::Threads)

if(TARGET SEAL::seal)
    target_link_libraries(logvole PUBLIC SEAL::seal)
elseif(TARGET SEAL::seal_shared)
    target_link_libraries(logvole PUBLIC SEAL::seal_shared)
else()
    message(FATAL_ERROR "Could not find SEAL::seal or SEAL::seal_shared")
endif()

enable_testing()

if(LOGVOLE_BUILD_TESTS)
    if(LOGVOLE_GTEST_SOURCE_DIR)
        set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
        set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
        add_subdirectory("${LOGVOLE_GTEST_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/googletest-build" EXCLUDE_FROM_ALL)
        if(TARGET gtest AND NOT TARGET GTest::gtest)
            add_library(GTest::gtest ALIAS gtest)
        endif()
    else()
        find_package(GTest CONFIG REQUIRED)
    endif()

    add_executable(logvole_correctness_tests
        ${CMAKE_CURRENT_LIST_DIR}/tests/test_main.cpp
        ${CMAKE_CURRENT_LIST_DIR}/tests/test_logvole.cpp
        ${CMAKE_CURRENT_LIST_DIR}/tests/test_logvole_recursive.cpp
    )
    target_link_libraries(logvole_correctness_tests PRIVATE logvole::logvole GTest::gtest)
    target_compile_features(logvole_correctness_tests PRIVATE cxx_std_17)

    add_test(NAME LogVOLECorrectnessTests COMMAND logvole_correctness_tests)
endif()

if(LOGVOLE_BUILD_BENCH)
    if(LOGVOLE_BENCHMARK_SOURCE_DIR)
        set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
        set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
        add_subdirectory("${LOGVOLE_BENCHMARK_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/benchmark-build" EXCLUDE_FROM_ALL)
        if(TARGET benchmark AND NOT TARGET benchmark::benchmark)
            add_library(benchmark::benchmark ALIAS benchmark)
        endif()
    else()
        find_package(benchmark CONFIG REQUIRED)
    endif()

    add_executable(logvole_bench ${CMAKE_CURRENT_LIST_DIR}/bench/bench_logvole.cpp)
    target_link_libraries(logvole_bench PRIVATE logvole::logvole benchmark::benchmark)
    target_compile_features(logvole_bench PRIVATE cxx_std_17)
    target_compile_definitions(logvole_bench
        PRIVATE
            LOGVOLE_HEXL_ENABLED=0
            LOGVOLE_HEXL_ISA="unknown"
    )

    add_test(
        NAME LogVOLEBenchSmoke
        COMMAND logvole_bench "--benchmark_filter=BM_LogVOLE_(2Level|3Level).*" --benchmark_min_time=0.01
    )
endif()

if(LOGVOLE_BUILD_EXAMPLES)
    add_executable(civole_example ${CMAKE_CURRENT_LIST_DIR}/examples/civole_example.cpp)
    target_link_libraries(civole_example PRIVATE logvole::logvole)
    target_compile_features(civole_example PRIVATE cxx_std_17)

    add_executable(civole_socket_example ${CMAKE_CURRENT_LIST_DIR}/examples/civole_socket_example.cpp)
    target_link_libraries(civole_socket_example PRIVATE logvole::logvole)
    target_compile_features(civole_socket_example PRIVATE cxx_std_17)
endif()
