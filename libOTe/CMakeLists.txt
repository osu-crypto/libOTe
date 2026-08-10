set(SRCS
    Dpf/RevCuckoo/Simulator.cpp
    Tools/EACode/EAChecker.cpp
    Tools/ExConvCode/ExConvChecker.cpp
    Tools/ExConvCode/ExConvCode.cpp
    Tools/ExConvCodeOld/ExConvCodeInstantiations.cpp
    Tools/ExConvCodeOld/ExConvCodeOld.cpp
    Tools/LDPC/Mtx.cpp
    Tools/LDPC/Util.cpp
    Tools/LinearCode.cpp
    Tools/Tools.cpp
    Tools/TungstenCode/TungstenData.cpp
    TwoChooseOne/ConfigureCode.cpp
    TwoChooseOne/OTExtInterface.cpp
)

if(ENABLE_SIMPLESTOT)
    list(APPEND SRCS Base/SimplestOT.cpp)
endif()

if(ENABLE_MR)
    list(APPEND SRCS Base/MasnyRindal.cpp)
endif()

if(ENABLE_MR_KYBER)
    list(APPEND SRCS Base/MasnyRindalKyber.cpp)
endif()

if(ENABLE_OOS OR ENABLE_KKRT)
    list(APPEND SRCS NChooseOne/NcoOtExt.cpp)
endif()

if(ENABLE_OOS)
    list(APPEND SRCS
        NChooseOne/Oos/OosNcoOtReceiver.cpp
        NChooseOne/Oos/OosNcoOtSender.cpp)
endif()

if(ENABLE_KKRT)
    list(APPEND SRCS
        NChooseOne/Kkrt/KkrtNcoOtReceiver.cpp
        NChooseOne/Kkrt/KkrtNcoOtSender.cpp)
endif()

if(ENABLE_KOS)
    list(APPEND SRCS
        TwoChooseOne/Kos/KosOtExtReceiver.cpp
        TwoChooseOne/Kos/KosOtExtSender.cpp)
endif()

if(ENABLE_DELTA_KOS)
    list(APPEND SRCS
        TwoChooseOne/KosDot/KosDotExtReceiver.cpp
        TwoChooseOne/KosDot/KosDotExtSender.cpp)
endif()

if(ENABLE_SOFTSPOKEN_OT)
    list(APPEND SRCS
        TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.cpp
        TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.cpp
        Vole/SoftSpokenOT/SmallFieldVole.cpp)
endif()

if(ENABLE_SILENTOT)
    list(APPEND SRCS
        Triple/SilentOtTriple/SilentOtTriple.cpp
        TwoChooseOne/Silent/SilentOtExtReceiver.cpp
        TwoChooseOne/Silent/SilentOtExtSender.cpp)
endif()

if(ENABLE_FOLEAGE)
    list(APPEND SRCS Triple/Foleage/FoleageTriple.cpp)
endif()

if(ENABLE_RINGLPN)
    list(APPEND SRCS Triple/RingLpn/RingLpnTriple.cpp)
endif()

if(ENABLE_REGULAR_DPF)
    list(APPEND SRCS Dpf/SumDmpf.cpp)
endif()

if(ENABLE_SPARSE_DPF)
    list(APPEND SRCS Dpf/RevCuckoo/BinarySolver.cpp)
endif()

if(ENABLE_PPRF)
    list(APPEND SRCS Tools/Pprf/RegularPprf.cpp)
endif()

if(ENABLE_BITPOLYMUL)
    list(APPEND SRCS Tools/bitpolymul.cpp)
endif()

if(ENABLE_CIRCUITS)
    list(APPEND SRCS Tools/Gmw/Gmw.cpp)
endif()

if(ENABLE_LOGVOLE)
    list(APPEND SRCS
        Vole/LogVole/LogVole.cpp
        Vole/LogVole/LogVoleCore.cpp
        Vole/LogVole/LogVoleEncoding.cpp
        Vole/LogVole/LogVoleLenc.cpp
        Vole/LogVole/LogVoleLhe.cpp
        Vole/LogVole/LogVoleRing.cpp
        Vole/LogVole/LogVoleRingReceiver.cpp
        Vole/LogVole/LogVoleRingSender.cpp
        Vole/LogVole/LogVoleShrinkExpand.cpp)
endif()

set(SRCS "${SRCS}")

add_library(libOTe STATIC ${SRCS})



# make projects that include libOTe use this as an include folder
target_include_directories(libOTe PUBLIC
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>)
target_include_directories(libOTe PUBLIC
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>)

                    
target_link_libraries(libOTe cryptoTools)


target_compile_definitions(libOTe PRIVATE
    $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:NDEBUG>
)


if(MSVC)
    target_compile_options(libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBOTE_STD_VER}> /Zi )
else()

    target_compile_options(libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER}>)
    
    if(NOT APPLE)
        # no-subobject-linkage =  GCC bug complaining about coroutines capturing lambdas
        # which only have internal linkage. But this is expected.
        target_compile_options(libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER} -Wno-subobject-linkage>)
    endif()

    if(ENABLE_SSE)
        target_compile_options(libOTe PRIVATE -maes -msse2 -msse3 -msse4.1 -mpclmul)
    endif()
    if(ENABLE_AVX)
        target_compile_options(libOTe PRIVATE -mavx2)
    endif()
endif()
if (ENABLE_BITPOLYMUL)
	target_link_libraries(libOTe bitpolymul)
endif ()

if(ENABLE_LOGVOLE)
	target_link_libraries(libOTe SEAL::seal)
endif()

if(ENABLE_MR_KYBER)
	target_link_libraries(libOTe KyberOT)
endif()


if(LIBOTE_SHARED)
    
    add_library(libOTeShared SHARED ${SRCS} )
    target_link_libraries(libOTeShared libOTe)
    if(MSVC)
        target_compile_options(libOTeShared PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBOTE_STD_VER}>)
    else()
        target_compile_options(libOTeShared PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER}>)

        if(ENABLE_SSE)
            target_compile_options(libOTeShared PRIVATE -maes -msse2 -msse3 -msse4.1 -mpclmul)
        endif()
        if(ENABLE_AVX)
            target_compile_options(libOTeShared PRIVATE -mavx2)
        endif()
    endif()
endif()

#############################################
#            Install                        #
#############################################

# install library
#install(TARGETS libOTe DESTINATION lib)

# install headers
#install(DIRECTORY . DESTINATION include/libOTe FILES_MATCHING PATTERN "*.h")
