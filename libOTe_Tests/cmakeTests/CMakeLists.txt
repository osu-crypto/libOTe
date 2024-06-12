 cmake_minimum_required(VERSION 3.15)
project(cmakeTest)

add_executable(main main.cpp)



find_package(libOTe REQUIRED HINTS ${LIBOTE_HINT}
	COMPONENTS
		#sodium
		#boost
		#openssl
		#circuits
		#sse
		#avx
		#no_sse
		#no_avx
		#bitpolymul
		#simplestot
		#mrr
		#mrr_twist
		#mr
		#mr_kyber
		kos
		iknp
		silentot
		softspoken_ot
		delta_kos
		silent_vole
		oos
		kkrt
)


if(MSVC)
    target_compile_options( main PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/std:c++${CRYPTO_TOOLS_STD_VER}>
    )
else()
    target_compile_options( main PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:-std=c++${CRYPTO_TOOLS_STD_VER} -pthread>
    )
endif()

target_link_libraries(main oc::libOTe)