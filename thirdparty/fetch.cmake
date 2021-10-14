

function(RUN)
    cmake_parse_arguments(
        PARSED_ARGS # prefix of parameters
        "" # list of names of the boolean arguments (only defined ones will be true)
        "WD" # list of names of mono-valued arguments
        "CMD;NAME" # list of names of multi-valued arguments (output variables are lists)
        ${ARGN} # arguments of the function to parse, here we take the all original ones
    )
    message("${PARSED_ARGS_NAME}")
    file(APPEND ${LOG_FILE}
        "############# ${PARSED_ARGS_NAME} ###########"
        "${PARSED_ARGS_CMD}"
        "#############################################"
    )

    execute_process(
        COMMAND ${PARSED_ARGS_CMD}
        WORKING_DIRECTORY ${PARSED_ARGS_WD}
        RESULT_VARIABLE RESULT
        COMMAND_ECHO STDOUT
        OUTPUT_FILE ${LOG_FILE}
        ERROR_FILE ${LOG_FILE}
        OUTPUT_QUIET
    )
    if(RESULT)
        message(FATAL_ERROR "${PARSED_ARGS_NAME} failed (${RESULT}). See ${LOG_FILE}")
    endif()
endfunction()

if(NOT MSVC AND SUDO_FETCH)
    set(SUDO "sudo ")
endif()

if(NOT DEFINED PARALLEL_FETCH)
    include(ProcessorCount)
    ProcessorCount(NUM_PROCESSORS)
    if(NOT NUM_PROCESSORS EQUAL 0)
        set(PARALLEL_FETCH ${NUM_PROCESSORS})
    else()
        set(PARALLEL_FETCH 1)
    endif()
endif()