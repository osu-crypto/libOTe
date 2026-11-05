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
    Tools/CpuCapabilities.cpp
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
        Vole/LogVole/LogVoleGarbled.cpp
        Vole/LogVole/LogVoleCore.cpp
        Vole/LogVole/LogVoleCpuArithmetic.cpp
        Vole/LogVole/LogVoleCpuSampler.cpp
        Vole/LogVole/LogVoleCpuScratch.cpp
        Vole/LogVole/LogVoleCpuZk.cpp
        Vole/LogVole/LogVoleEncoding.cpp
        Vole/LogVole/LogVoleWireMemory.cpp
        Vole/LogVole/LogVoleLenc.cpp
        Vole/LogVole/LogVoleLhe.cpp
        Vole/LogVole/LogVoleRing.cpp
        Vole/LogVole/LogVoleRingReceiver.cpp
        Vole/LogVole/LogVoleRingSender.cpp
        Vole/LogVole/LogVoleShrinkExpand.cpp
        Vole/LogVole/LogVoleZk.cpp)
    if(ENABLE_LOGVOLE_CUDA)
        list(APPEND SRCS
            Vole/LogVole/cuda/LogVoleGpuKernels.cu
            Vole/LogVole/cuda/LogVoleGpuZk.cu
            Vole/LogVole/cuda/LogVoleGpuBackend.cpp
            Vole/LogVole/cuda/LogVoleGpuMemory.cpp
            Vole/LogVole/cuda/LogVoleGpuGaussian.cpp
            Vole/LogVole/cuda/LogVoleGpuGaussianKernels.cu
            Vole/LogVole/cuda/LogVoleGpuProtocol.cpp)
    endif()
endif()

set(SRCS "${SRCS}")

add_library(libOTe STATIC ${SRCS})

if(OC_ENABLE_AVX512_IFMA)
    # Compile-time availability and runtime CPU/OS support are separate checks.
    # Unsupported architectures or compilers retain the scalar implementations.
    include(CheckCXXSourceCompiles)
    check_cxx_source_compiles([=[
        #if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
        #error Unsupported compiler or architecture
        #endif
        #include <immintrin.h>
        __attribute__((target("avx512f,avx512dq,avx512ifma")))
        __m512i probe(__m512i x) {
            return _mm512_madd52lo_epu64(x, x, _mm512_mullo_epi64(x, x));
        }
        int main() {
            return __builtin_cpu_supports("avx512f") &&
                __builtin_cpu_supports("avx512dq") &&
                __builtin_cpu_supports("avx512ifma");
        }
    ]=] OC_COMPILER_HAS_AVX512_IFMA_DISPATCH)
    if(OC_COMPILER_HAS_AVX512_IFMA_DISPATCH)
        set_property(SOURCE Tools/CpuCapabilities.cpp
            Vole/LogVole/LogVoleCpuArithmetic.cpp
            Vole/LogVole/LogVoleCpuZk.cpp APPEND
            PROPERTY COMPILE_DEFINITIONS OC_COMPILER_HAS_AVX512_IFMA_DISPATCH=1)
    endif()
endif()

# Source/dependency targets inherit the directory option. Export it as well for
# consumers that instantiate coroutine templates from the installed headers.
target_compile_options(libOTe INTERFACE ${LIBOTE_ASAN_COMPILE_OPTIONS})


# make projects that include libOTe use this as an include folder
target_include_directories(libOTe PUBLIC
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>)
target_include_directories(libOTe PUBLIC
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>)

                    
target_link_libraries(libOTe cryptoTools)
if(ENABLE_SPIN)
    target_sources(libOTe PRIVATE Tools/Spin/SpinOt.cpp)
    target_link_libraries(libOTe spin::spin)
endif()


target_compile_definitions(libOTe PRIVATE
    $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:NDEBUG>
)


if(MSVC)
    target_compile_options(libOTe PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBOTE_STD_VER};/Zi>")
else()

    target_compile_options(libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER}>)
    
    if(NOT APPLE)
        # no-subobject-linkage =  GCC bug complaining about coroutines capturing lambdas
        # which only have internal linkage. But this is expected.
        target_compile_options(libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER} -Wno-subobject-linkage>)
    endif()

    if(ENABLE_SSE)
        target_compile_options(libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-maes;-msse2;-msse3;-msse4.1;-mpclmul>)
    endif()
    if(ENABLE_AVX)
        target_compile_options(libOTe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-mavx2>)
    endif()
endif()
if (ENABLE_BITPOLYMUL)
	target_link_libraries(libOTe bitpolymul)
endif ()

if(ENABLE_LOGVOLE)
	target_link_libraries(libOTe SEAL::seal)
endif()

function(configure_logvole_cuda target)
    if(ENABLE_LOGVOLE_CUDA)
        set_target_properties(${target} PROPERTIES
            CUDA_STANDARD 17 CUDA_STANDARD_REQUIRED ON
            CUDA_SEPARABLE_COMPILATION OFF CUDA_RESOLVE_DEVICE_SYMBOLS OFF
            LINKER_LANGUAGE CXX)
        target_compile_options(${target} PRIVATE
            $<$<COMPILE_LANGUAGE:CUDA>:--expt-extended-lambda>
            $<$<COMPILE_LANGUAGE:CUDA>:--expt-relaxed-constexpr>
            $<$<COMPILE_LANGUAGE:CUDA>:-lineinfo>)
        if(NOT MSVC)
            target_compile_options(${target} PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:-Xcompiler=-fPIC>)
        endif()
        target_link_libraries(${target} CUDA::cudart)
    endif()
endfunction()
configure_logvole_cuda(libOTe)

if(ENABLE_MR_KYBER)
	target_link_libraries(libOTe KyberOT)
endif()


if(LIBOTE_SHARED)
    
    add_library(libOTeShared SHARED ${SRCS} )
    target_link_libraries(libOTeShared libOTe)
    configure_logvole_cuda(libOTeShared)
    if(MSVC)
        target_compile_options(libOTeShared PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBOTE_STD_VER}>)
    else()
        target_compile_options(libOTeShared PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER}>)

        if(ENABLE_SSE)
            target_compile_options(libOTeShared PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-maes;-msse2;-msse3;-msse4.1;-mpclmul>)
        endif()
        if(ENABLE_AVX)
            target_compile_options(libOTeShared PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-mavx2>)
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
