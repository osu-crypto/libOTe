include("${CMAKE_CURRENT_LIST_DIR}/libOTeFindBuildDir.cmake")

find_library(
    cryptoTools_LIB
    NAMES cryptoTools
    HINTS "${libOTe_BIN_DIR}/cryptoTools/cryptoTools")
if(NOT cryptoTools_LIB)
    message(FATAL_ERROR "failed to find cryptoTools at ${libOTe_BIN_DIR}/cryptoTools/cryptoTools")
endif()

find_library(
    libOTe_LIB
    NAMES libOTe
    HINTS "${libOTe_BIN_DIR}/libOTe")
if(NOT libOTe_LIB)
    message(FATAL_ERROR "failed to find libOTe at ${libOTe_BIN_DIR}/libOTe")
endif()

    
find_library(
    libOTe_TESTS_LIB
    NAMES libOTe_Tests
    HINTS "${libOTe_BIN_DIR}/libOTe_Tests")
if(NOT libOTe_TESTS_LIB)
    message(FATAL_ERROR "failed to find libOTe_Tests at ${libOTe_BIN_DIR}/libOTe_Tests")
endif()

find_library(
    cryptoTools_TESTS_LIB
    NAMES tests_cryptoTools
    HINTS "${libOTe_BIN_DIR}/cryptoTools/tests_cryptoTools")
    
if(NOT cryptoTools_TESTS_LIB)
    message(FATAL_ERROR "failed to find tests_cryptoTools at ${libOTe_BIN_DIR}/cryptoTools/tests_cryptoTools")
endif()



if(ENABLE_SIMPLESTOT_ASM)

	find_library(
	    SimplestOT_LIB
	    NAMES SimplestOT
	    HINTS "${libOTe_BIN_DIR}/SimplestOT")

    if(NOT SimplestOT_LIB)
      	message(FATAL_ERROR "Failed to find libSimplestOT.a at: ${libOTe_BIN_DIR}")
  	else()
      	#message(STATUS "Found libSimplestOT.a at: ${libOTe_Dirs}/lib/")  	
    endif()
endif()



if(ENABLE_MR_KYBER)

	find_library(
	    KyberOT_LIB
	    NAMES KyberOT
	    HINTS "${libOTe_BIN_DIR}/KyberOT/")

    if(NOT KyberOT_LIB)
      	message(FATAL_ERROR "Failed to find libKyberOT.a at: ${libOTe_BIN_DIR}/")
  	else()
      	#message(STATUS "Found libKyberOT.a at: ${libOTe_Dirs}/lib/")  	
    endif()
    
endif()

include("${CMAKE_CURRENT_LIST_DIR}/../cryptoTools/cmake/cryptoToolsDepHelper.cmake")

list(APPEND libOTe_INC 
    "${CMAKE_CURRENT_LIST_DIR}/.."
    "${CMAKE_CURRENT_LIST_DIR}/../cryptoTools"
    "${libOTe_BIN_DIR}"
    "${libOTe_BIN_DIR}/cryptoTools"
    "${Boost_INCLUDE_DIR}"
    "${WOLFSSL_LIB_INCLUDE_DIRS}"
    "${RLC_INCLUDE_DIR}")



list(APPEND libOTe_LIB 
    "${libOTe_LIB}"
    "${cryptoTools_LIB}"
    "${Boost_LIBRARIES}"
    "${WOLFSSL_LIB}"
    "${RLC_LIBRARY}"
    "${SimplestOT_LIB}"
    "${KyberOT_LIB}")
    
    
list(APPEND libOTe_TESTS_LIB 
    "${libOTe_TESTS_LIB}"
    "${cryptoTools_TESTS_LIB}")
                
if(NOT libOTe_Helper_Quiet)
    message(STATUS "libOTe_INC: ${libOTe_INC}")
    message(STATUS "libOTe_LIB: ${libOTe_LIB}")
    message(STATUS "libOTe_TESTS_LIB: ${libOTe_TESTS_LIB}")
endif()

