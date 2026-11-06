cmake_minimum_required(VERSION 3.18)

project(LogVoleCudaArithmeticTests LANGUAGES CXX CUDA)

enable_testing()
get_filename_component(LOGVOLE_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

set(arithmetic_tests
    test_fp52_modular_multiply
    test_mul52_wide
    test_pseudo52_reduction
    test_pseudo52_sampling
    test_wide_carry
    test_zk_modular_multiply)

foreach(test IN LISTS arithmetic_tests)
    add_executable(${test} ${test}.cu)
    target_include_directories(${test} PRIVATE "${LOGVOLE_REPO_ROOT}")
    set_target_properties(${test} PROPERTIES
        CUDA_STANDARD 17
        CUDA_STANDARD_REQUIRED ON)
    add_test(NAME ${test} COMMAND ${test})
endforeach()

add_test(NAME test_fp52_modular_multiply_prediv
    COMMAND test_fp52_modular_multiply prediv)
set_tests_properties(${arithmetic_tests} test_fp52_modular_multiply_prediv
    PROPERTIES LABELS "cuda;correctness" RUN_SERIAL TRUE TIMEOUT 120)

add_executable(test_gaussian_transform test_gaussian_transform.cu
    "${LOGVOLE_REPO_ROOT}/libOTe/Vole/LogVole/cuda/LogVoleGpuGaussianKernels.cu")
target_include_directories(test_gaussian_transform PRIVATE "${LOGVOLE_REPO_ROOT}")
set_target_properties(test_gaussian_transform PROPERTIES CUDA_STANDARD 17 CUDA_STANDARD_REQUIRED ON)
add_test(NAME test_gaussian_transform COMMAND test_gaussian_transform)
set_tests_properties(test_gaussian_transform PROPERTIES LABELS "cuda;correctness" RUN_SERIAL TRUE TIMEOUT 180)
