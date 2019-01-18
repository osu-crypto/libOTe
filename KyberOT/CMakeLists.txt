
#project(KyberOT)

enable_language(ASM)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2") 

SET(SRCS  kem.c poly.c polyvec.c polyvec_pointwise_acc.s fips202.c reduce.c cbdeta4.s cbdref.c precomp.c verify.c indcpa.c kex.c consts.c genmatrix.c fips202x4.c keccak4x/KeccakP-1600-times4-SIMD256.o ntt.s invntt.s randombytes.c KyberOT.c)

add_library(KyberOT STATIC ${SRCS})

target_include_directories(KyberOT PUBLIC ${CMAKE_SOURCE_DIR}) 

#############################################
#            Install                        #
#############################################

# install library
install(TARGETS KyberOT DESTINATION lib)

# install headers
install(DIRECTORY . DESTINATION include/KyberOT FILES_MATCHING PATTERN "*.h")
