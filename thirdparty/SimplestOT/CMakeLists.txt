set(SIMPLESTOT_PROTOCOL_SOURCES
    Keccak-simple.c
    cpucycles.c
    network.c
    ot_receiver.c
    ot_receiver_test.c
    ot_sender.c
    ot_sender_test.c
    randombytes.c
    sc25519_random.c)

add_library(SimplestOT STATIC ${SIMPLESTOT_PROTOCOL_SOURCES})
target_link_libraries(SimplestOT PUBLIC cryptoTools)

target_include_directories(SimplestOT PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
    $<INSTALL_INTERFACE:include>)
