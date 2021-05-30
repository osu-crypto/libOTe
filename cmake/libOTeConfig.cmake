



if(MSVC)
    set(libOTe_BIN_DIR "${libOTe_Dirs}/out/build/x64-${CMAKE_BUILD_TYPE}")
else()
    message(FATAL_ERROR "not impl")
endif()




find_library(
    libOTe_LIB
    NAMES libOTe
    HINTS "${libOTe_BIN_DIR}")

find_library(
    cryptoTools_LIB
    NAMES cryptoTools
    HINTS "${libOTe_BIN_DIR}")


if(NOT libOTe_LIB OR NOT cryptoTools_LIB)
    message(FATAL_ERROR "failed to fine libOTe & cryptoTools at ${libOTe_BIN_DIR}")
endif()



if(${ENABLE_SIMPLESTOT_ASM})

	find_library(
	    SimplestOT_LIB
	    NAMES SimplestOT
	    HINTS "${libOTe_Dirs}/lib/")

    if(NOT SimplestOT_LIB)
      	message(FATAL_ERROR "Failed to find libSimplestOT.a at: ${libOTe_Dirs}/lib/")
  	else()
      	message(STATUS "Found libSimplestOT.a at: ${libOTe_Dirs}/lib/")
    endif()

	target_link_libraries(libPSI ${SimplestOT_LIB})

endif()



if(${ENABLE_MR_KYBER})

	find_library(
	    KyberOT_LIB
	    NAMES KyberOT
	    HINTS "${libOTe_Dirs}/lib/")

    if(NOT KyberOT_LIB)
      	message(FATAL_ERROR "Failed to find libKyberOT.a at: ${libOTe_Dirs}/lib/")
  	else()
      	message(STATUS "Found libKyberOT.a at: ${libOTe_Dirs}/lib/")
    endif()

	target_link_libraries(libPSI ${KyberOT_LIB})

endif()


#############################################
#                 Link Boost                #
#############################################



if(NOT BOOST_ROOT OR NOT EXISTS "${BOOST_ROOT}")
    if(MSVC)
        set(BOOST_ROOT_local "${CMAKE_CURRENT_SOURCE_DIR}/../../libOTe/cryptoTools/thirdparty/win/boost/")
        set(BOOST_ROOT_install "c:/libs/boost/")

        if(EXISTS "${BOOST_ROOT_local}")
            set(BOOST_ROOT "${BOOST_ROOT_local}")
        else()
            set(BOOST_ROOT "${BOOST_ROOT_install}")
        endif()
    else()
        set(BOOST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/linux/boost/")
    endif()
endif()


if(MSVC)
    set(Boost_LIB_PREFIX "lib")
endif()

#set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
#set(Boost_USE_STATIC_RUNTIME     OFF)
#set (Boost_DEBUG ON)  #<---------- Real life saver

macro(findBoost)
    if(MSVC)
        find_package(Boost  COMPONENTS system thread regex)
    else()
        find_package(Boost  COMPONENTS system thread)
    endif()
endmacro()

# then look at system dirs
if(NOT Boost_FOUND)
    #set(Boost_NO_SYSTEM_PATHS  OFF)
    findBoost()
endif()


#############################################
#                 Link Miracl               #
#############################################


if (ENABLE_MIRACL)

    find_library(
      MIRACL_LIB
      NAMES miracl
      HINTS "${Miracl_Dirs}/miracl/source/")

    # if we cant find it, throw an error
    if(NOT MIRACL_LIB)
      Message(${MIRACL_LIB})
      message(FATAL_ERROR "Failed to find miracl at " ${Miracl_Dirs})
    else()
      message("Miracl at  ${MIRACL_LIB}")
    endif()

    target_link_libraries(libPSI  ${MIRACL_LIB} )

endif()





## Relic
###########################################################################


if (ENABLE_RELIC)
  find_package(Relic REQUIRED)

  if (NOT Relic_FOUND)
    message(FATAL_ERROR "Failed to find Relic")
  endif (NOT Relic_FOUND)

  message(STATUS "Relic_LIB:  ${RELIC_LIBRARIES} ${RLC_LIBRARY}")
  message(STATUS "Relic_inc:  ${RELIC_INCLUDE_DIR} ${RLC_INCLUDE_DIR}\n")

  target_include_directories(libPSI PUBLIC ${RELIC_INCLUDE_DIR} ${RLC_INCLUDE_DIR})
  target_link_libraries(libPSI ${RELIC_LIBRARIES} ${RLC_LIBRARY})


endif (ENABLE_RELIC)

## WolfSSL
###########################################################################

if(ENABLE_WOLFSSL)

    if(NOT DEFINED WolfSSL_DIR)
        set(WolfSSL_DIR "/usr/local/")
    endif()


    find_library(WOLFSSL_LIB NAMES wolfssl  HINTS "${WolfSSL_DIR}")
    set(WOLFSSL_LIB_INCLUDE_DIRS "${WolfSSL_DIR}include/")

    # if we cant fint it, throw an error
    if(NOT WOLFSSL_LIB)
        message(FATAL_ERROR "Failed to find WolfSSL at " ${WolfSSL_DIR})
    endif()

    message(STATUS "WOLFSSL_LIB:  ${WOLFSSL_LIB}")
    message(STATUS "WOLFSSL_INC:  ${WOLFSSL_LIB_INCLUDE_DIRS}\n")

    target_include_directories(libPSI PUBLIC "${WOLFSSL_LIB_INCLUDE_DIRS}")
    target_link_libraries(libPSI ${WOLFSSL_LIB})

endif(ENABLE_WOLFSSL)
