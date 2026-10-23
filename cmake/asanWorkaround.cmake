# GCC's ASan stack epilogue can prevent coroutine symmetric transfer from being
# a tail call, causing stack overflow in otherwise bounded-stack await loops.
# Reproduced with GCC 13.3 and 15.2; cover 14 and the next major release as well.
# TODO: retest GCC 17 before extending this range (related GCC PRs 100897/120608).
# Only stack instrumentation is disabled; heap/global ASan checks remain enabled.
set(LIBOTE_ASAN_COMPILE_OPTIONS "")
if(ENABLE_ASAN)
    # Keep the compiler/version test in the exported usage requirement too:
    # downstream translation units instantiate libOTe's coroutine templates.
    set(LIBOTE_ASAN_COMPILE_OPTIONS
        "$<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>,$<VERSION_GREATER_EQUAL:$<CXX_COMPILER_VERSION>,13>,$<VERSION_LESS:$<CXX_COMPILER_VERSION>,17>>:--param=asan-stack=0>")
    add_compile_options("${LIBOTE_ASAN_COMPILE_OPTIONS}")

    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU"
            AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 13
            AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 17)
        message(WARNING
            "GCC ${CMAKE_CXX_COMPILER_VERSION}: disabling ASan stack checks to "
            "avoid coroutine symmetric-transfer stack overflow. Heap/global "
            "ASan checks remain enabled; Clang retains full ASan coverage.")
    endif()
endif()
