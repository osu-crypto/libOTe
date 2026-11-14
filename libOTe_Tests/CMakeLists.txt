
set(SRCS
    BaseOT_Tests.cpp
    bitpolymul_Tests.cpp
    Common.cpp
    EACode_Tests.cpp
    ExConvCode_Tests.cpp
    NcoOT_Tests.cpp
    OT_Tests.cpp
    Pprf_Tests.cpp
    Dpf_Tests.cpp
    RevCuckoo_Tests.cpp
    Waterfall_Tests.cpp
    SilentOT_Tests.cpp
    SoftSpoken_Tests.cpp
    TungstenCode_Tests.cpp
    UnitTests.cpp
    Vole_Tests.cpp
    Foleage_Tests.cpp
    Cmp_Tests.cpp
    Permute_Tests.cpp
    Equality_Tests.cpp
    Field_Tests.cpp
    Ntt_Tests.cpp
    Poly_Tests.cpp
    RingLpn_Tests.cpp
    RingLpnSupport_Tests.cpp
    BinarySolver_Tests.cpp
    Goldilocks_Tests.cpp
    Gmw_Tests.cpp
    UInt_Tests.cpp
    Permutation_Tests.cpp
    BlkAccCode_Tests.cpp
    ChosenBaa_Tests.cpp
    AnyField_Tests.cpp
)

add_library(libOTe_Tests STATIC ${SRCS})

target_compile_definitions(libOTe_Tests PRIVATE
    $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:NDEBUG>
)


target_link_libraries(libOTe_Tests libOTe)

option(LIBOTE_BAA_BENCHMARK "Build the standalone chosen BAA benchmark" OFF)
if(LIBOTE_BAA_BENCHMARK)
    add_executable(chosen_baa_benchmark benchmarks/ChosenBaa.cpp)
    target_include_directories(chosen_baa_benchmark PRIVATE ${CMAKE_CURRENT_LIST_DIR}/..)
    target_compile_features(chosen_baa_benchmark PRIVATE cxx_std_20)
    target_link_libraries(chosen_baa_benchmark PRIVATE cryptoTools)
    add_executable(chosen_baa_directions benchmarks/ChosenBaaDirections.cpp)
    target_include_directories(chosen_baa_directions PRIVATE ${CMAKE_CURRENT_LIST_DIR}/..)
    target_compile_features(chosen_baa_directions PRIVATE cxx_std_20)
    target_link_libraries(chosen_baa_directions PRIVATE cryptoTools)
endif()


# make projects that include libOTe_Tests use this as an include folder
target_include_directories(libOTe_Tests PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 
target_include_directories(libOTe_Tests PUBLIC
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>)

if(ENABLE_LOGVOLE)
    target_sources(libOTe_Tests PRIVATE
        LogVole/tests/test_core.cpp
        LogVole/tests/test_civole.cpp
        LogVole/tests/test_encoding.cpp
        LogVole/tests/test_keyderive_coproto.cpp
        LogVole/tests/test_keyderive_core.cpp
        LogVole/tests/test_lhe.cpp
        LogVole/tests/test_lenc.cpp
        LogVole/tests/test_ring_ops.cpp
        LogVole/tests/test_shrinkexpand_coproto.cpp
        LogVole/tests/test_shrinkexpand.cpp
    )
    target_include_directories(libOTe_Tests PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/LogVole
        ${CMAKE_CURRENT_LIST_DIR}/LogVole/tests
    )
endif()


if(MSVC)
    target_compile_options(libOTe_Tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBOTE_STD_VER} /bigobj>)

else()
    target_compile_options(libOTe_Tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER}>)

    if(NOT APPLE)
        # no-subobject-linkage =  GCC bug complaining about coroutines capturing lambdas
        # which only have internal linkage. But this is expected.
        target_compile_options(libOTe_Tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Wno-subobject-linkage>)

    endif()
endif()
