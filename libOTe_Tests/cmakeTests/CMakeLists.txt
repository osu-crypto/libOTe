project(cmakeTest)

add_executable(main main.cpp)

find_package(libOTe REQUIRED ${LIBOTE_HINT})

target_link_libraries(main oc::libOTe)