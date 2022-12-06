 cmake_minimum_required(VERSION 3.15)
project(cmakeTest)

add_executable(main main.cpp)

if(SODIUM)
	set(cryptoDep sodium)
else()
	set(cryptoDep relic)
endif()


find_package(libOTe REQUIRED HINTS ${LIBOTE_HINT}
	COMPONENTS
		${cryptoDep}
		#sodium
		#boost
		#openssl
		#circuits
		#sse
		#avx
		#no_sse
		#no_avx
		#bitpolymul
		simplestot
		mrr
		#mrr_twist
		mr
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


target_compile_options(main PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++14> -pthread)

target_link_libraries(main oc::libOTe)