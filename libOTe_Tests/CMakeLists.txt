

add_library(libOTe_Tests STATIC 

    BaseOT_Tests.cpp
    bitpolymul_Tests.cpp
    Common.cpp
    EACode_Tests.cpp
    ExConvCode_Tests.cpp
    NcoOT_Tests.cpp
    OT_Tests.cpp
    Pprf_Tests.cpp
    Dpf_Tests.cpp
    SilentOT_Tests.cpp
    SoftSpoken_Tests.cpp
    TungstenCode_Tests.cpp
    UnitTests.cpp
    Vole_Tests.cpp
    Foleage_Tests.cpp
    Permutation_Tests.cpp
    BlkAccCode_Tests.cpp)

target_link_libraries(libOTe_Tests libOTe)


# make projects that include libOTe_Tests use this as an include folder
target_include_directories(libOTe_Tests PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 
target_include_directories(libOTe_Tests PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 


if(MSVC)
    target_compile_options(libOTe_Tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBOTE_STD_VER}>)
    
else()
    target_compile_options(libOTe_Tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBOTE_STD_VER}>)
endif()