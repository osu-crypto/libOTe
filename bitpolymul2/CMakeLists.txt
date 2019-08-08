cmake_minimum_required (VERSION 3.8)


include("${CMAKE_CURRENT_SOURCE_DIR}/../msvc_runtime.cmake")
configure_msvc_runtime()



# add the source files 
set(SRCS 
    "bc.cpp" 
    "bitpolymul.cpp" 
    "encode.cpp" 
    "butterfly_net.cpp" 
    "gf2128_cantor_iso.cpp" 
    "btfy.cpp" 
    "trunc_btfy_tab.cpp" 
    "gf264_cantor_iso.cpp" 
    "trunc_btfy_tab_64.cpp")

add_library(bitpolymul2 STATIC ${SRCS})

option(DEBUG "Turn on debugging" OFF)
message(STATUS "Option: DEBUG = ${DEBUG}")

option(SSE "Enable SSE" ON)
message(STATUS "Option: SSE = ${SSE}")

#option(K "Enable K" OFF)
#message(STATUS "Option: K = ${K}")

option(AVX "Enable AVX" ON)
message(STATUS "Option: AVX = ${AVX}")

option(AVX2 "Enable AVX2" ON)
message(STATUS "Option: AVX2 = ${AVX2}")


message(STATUS "Option: CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}\n\tRelease\n\tDebug\n\tRELWITHDEBINFO")


if(DEBUG)
    target_compile_options(bitpolymul2 PUBLIC "-D_DEBUG_")
endif()

if(NOT SSE)
    target_compile_options(bitpolymul2 PUBLIC "-D_NO_SSE_")
endif()

if(AVX)
    target_compile_options(bitpolymul2 PUBLIC "-D_USE_AVX_")
endif()

if(AVX2)
    target_compile_options(bitpolymul2 PUBLIC "-D_USE_AVX2_")
endif()
#ifdef K
#	CFLAGS += -DK=$(K)
#	CXXFLAGS += -DK=$(K)
#endif


#CFLAGS= -O3 -funroll-loops -mavx2 -mpclmul -std=gnu99                            -Wextra -Wall
set(libOTeDir "${CMAKE_CURRENT_SOURCE_DIR}/../../libOTe")
set(cryptoToolsDir "${libOTeDir}/cryptoTools")

if(MSVC)

    target_compile_options(bitpolymul2 PUBLIC  "/arch:AVX2" "/GL" "/LTCG")

    

    if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
        set(cryptoToolsLib "${libOTeDir}/x64/debug/cryptoTools.lib")
    else()
        set(cryptoToolsLib "${libOTeDir}/x64/release/cryptoTools.lib")
        target_compile_options(bitpolymul2 PUBLIC  "/O2")
    endif()

    set(relicLib "${libOTeDir}/../relic/lib/${CMAKE_BUILD_TYPE}/relic_s.lib")

else(MSVC)
    set(cryptoToolsLib "${libOTeDir}/lib/libcryptoTools.a")

    target_compile_options(bitpolymul2 PUBLIC "-mavx2" "-mpclmul" "-march=native")
    if("${CMAKE_BUILD_TYPE}" STREQUAL "Release" OR 
       "${CMAKE_BUILD_TYPE}" STREQUAL "RELWITHDEBINFO" )
        target_compile_options(bitpolymul2 PUBLIC  "-O3" "-funroll-loops" "-fno-rtti")# "-fno-exceptions" 
    endif()
endif(MSVC)



if(NOT EXISTS "${cryptoToolsDir}")
    message(FATAL_ERROR "cryptoTools does not exist at: ${cryptoToolsDir}" )    
endif()

if(NOT EXISTS "${cryptoToolsLib}")
    message(FATAL_ERROR "lib cryptoTools does not exist at: ${cryptoToolsLib}" )    
endif()

# make projects that include bitpolymul2 use this as an include folder
target_include_directories(bitpolymul2 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/..")
target_include_directories(bitpolymul2 PUBLIC "${cryptoToolsDir}")
target_link_libraries(bitpolymul2 PUBLIC "${cryptoToolsLib}" "${relicLib}")

message(STATUS "cryptoToolsLib = ${cryptoToolsLib}")


## Boost
###########################################################################

set(BOOST_ROOT "${libOTeDir}/cryptoTools/thirdparty/linux/boost/")

set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     ON)

find_package(Boost 1.66.0 COMPONENTS system thread)


if(NOT Boost_FOUND)
    message(FATAL_ERROR "Failed to find boost 1.66.0 or newer. Looked at system dirs and: " ${BOOST_ROOT})
endif()


target_include_directories(bitpolymul2 PUBLIC ${Boost_INCLUDE_DIR}) 
target_link_libraries(bitpolymul2 PUBLIC ${Boost_LIBRARIES})

