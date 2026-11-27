# Inject with -DCMAKE_PROJECT_INCLUDE=<absolute path to this file>.
if(NOT CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR OR
   NOT PROJECT_NAME STREQUAL "libOTe" OR TARGET logvole_gpu_bench)
    return()
endif()

if(NOT ENABLE_LOGVOLE OR NOT ENABLE_LOGVOLE_CUDA)
    message(FATAL_ERROR "logvole_gpu_bench requires ENABLE_LOGVOLE and ENABLE_LOGVOLE_CUDA")
endif()

add_executable(logvole_gpu_bench
    "${CMAKE_CURRENT_LIST_DIR}/gpu_bench_main.cpp"
    "${PROJECT_SOURCE_DIR}/frontend/ExampleLogVole.cpp")
target_compile_features(logvole_gpu_bench PRIVATE cxx_std_20)
target_include_directories(logvole_gpu_bench PRIVATE "${PROJECT_SOURCE_DIR}")
target_link_libraries(logvole_gpu_bench PRIVATE libOTe)
