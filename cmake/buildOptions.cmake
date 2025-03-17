include_guard(GLOBAL)

set(LIBOTE_BUILD ON)

macro(EVAL var)
     if(${ARGN})
         set(${var} ON)
     else()
         set(${var} OFF)
     endif()
endmacro()


if(DEFINED COPROTO_ENABLE_BOOST)
    message("warning: setting ENABLE_BOOST as COPROTO_ENABLE_BOOST=${COPROTO_ENABLE_BOOST}")
    set(ENABLE_BOOST ${COPROTO_ENABLE_BOOST})
    unset(COPROTO_ENABLE_BOOST CACHE )
endif()

if(DEFINED COPROTO_ENABLE_OPENSSL)
    set(ENABLE_OPENSSL ${COPROTO_ENABLE_OPENSSL})
    unset(COPROTO_ENABLE_OPENSSL)
endif()

if(DEFINED ENABLE_ALL_OT)

	# requires sodium or relic
	if(${ENABLE_SODIUM} OR ${ENABLE_RELIC})
		set(oc_BB ${ENABLE_ALL_OT})
	else()
		set(oc_BB OFF)
	endif()
	set(ENABLE_SIMPLESTOT  ${oc_BB} CACHE BOOL "" FORCE)
	set(ENABLE_MR          ${oc_BB} CACHE BOOL "" FORCE)
	set(ENABLE_NP          ${oc_BB} CACHE BOOL "" FORCE)

	# requires sodium
	if(${ENABLE_SODIUM} OR ${ENABLE_RELIC})
		set(oc_BB ${ENABLE_ALL_OT})
	else()
		set(oc_BB OFF)
	endif()
	set(ENABLE_MRR ${oc_BB} CACHE BOOL "" FORCE)

	# requires sodium
	if(${ENABLE_SODIUM} AND SODIUM_MONTGOMERY)
		set(oc_BB ${ENABLE_ALL_OT})
	else()
		set(oc_BB OFF)
	endif()
	set(ENABLE_MRR_TWIST   ${oc_BB} CACHE BOOL "" FORCE)


	# requires linux
	if(UNIX AND NOT(APPLE OR MSVC) AND NOT ENABLE_PIC)
		set(oc_BB ${ENABLE_ALL_OT})
	else()
		set(oc_BB OFF)
	endif()
	set(ENABLE_SIMPLESTOT_ASM ${oc_BB}						CACHE BOOL "" FORCE)
	set(ENABLE_MR_KYBER       ${oc_BB}						CACHE BOOL "" FORCE)

	# general
	set(ENABLE_KOS            ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_IKNP           ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_SOFTSPOKEN_OT  ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_DELTA_KOS      ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_OOS            ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_KKRT           ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_SILENTOT		  ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_SILENT_VOLE    ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_FOLEAGE		  ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_REGULAR_DPF	  ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_TERNARY_DPF	  ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_SPARSE_DPF	  ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	
	unset(ENABLE_ALL_OT CACHE)

endif()


option(ENABLE_BITPOLYMUL     "Build with bit poly mul inegration" FALSE)

option(ENABLE_MOCK_OT        "Build the insecure mock base OT" OFF)

option(ENABLE_SIMPLESTOT     "Build the SimplestOT base OT" OFF)
option(ENABLE_SIMPLESTOT_ASM "Build the assembly based SimplestOT library" OFF)
option(ENABLE_MRR            "Build the McQuoidRosulekRoy 20 PopfOT base OT using Ristretto KA" OFF)
option(ENABLE_MRR_TWIST      "Build the McQuoidRosulekRoy 21 PopfOT base OT using Moeller KA" OFF)
option(ENABLE_MR             "Build the MasnyRindal base OT" OFF)
option(ENABLE_MR_KYBER       "Build the Kyber (LWE based) library and MR-Kyber base OT" OFF)

option(ENABLE_KOS            "Build the KOS OT-Ext protocol." OFF)
option(ENABLE_IKNP           "Build the IKNP OT-Ext protocol." OFF)
option(ENABLE_SILENTOT       "Build the Slient OT protocol." OFF)
option(ENABLE_SOFTSPOKEN_OT  "Build the SoftSpokenOT protocol." OFF)
option(ENABLE_DELTA_KOS      "Build the KOS Delta-OT-Ext protocol." OFF)
option(ENABLE_DELTA_IKNP     "Build the IKNP Delta-OT-Ext protocol." OFF)

option(ENABLE_OOS            "Build the OOS 1-oo-N OT-Ext protocol." OFF)
option(ENABLE_KKRT           "Build the KKRT 1-oo-N OT-Ext protocol." OFF)

option(ENABLE_PPRF           "Build the PPRF protocol." OFF)
option(ENABLE_SILENT_VOLE    "Build the Silent Vole protocol." OFF)

option(ENABLE_FOLEAGE        "Build the Foleage OLE protocol." OFF)


option(ENABLE_REGULAR_DPF    "Build the Regular DPF protocol." OFF)
option(ENABLE_TERNARY_DPF    "Build the Ternary DPF protocol." OFF)
option(ENABLE_SPARSE_DPF     "Build the Sparse DPF protocol." OFF)

option(NO_KOS_WARNING        "Build with no kos security warning." OFF)


EVAL(FETCH_BITPOLYMUL_IMPL 
	(DEFINED FETCH_BITPOLYMUL AND FETCH_BITPOLYMUL) OR
	((NOT DEFINED FETCH_BITPOLYMUL) AND (FETCH_AUTO AND ENABLE_BITPOLYMUL)))

if(ENABLE_SILENT_VOLE OR ENABLE_SILENTOT OR ENABLE_SOFTSPOKEN_OT)
	set(ENABLE_PPRF true)
endif()

option(VERBOSE_FETCH        "Print build info for fetched libraries" ON)

if(ENABLE_IKNP)
	set(ENABLE_KOS true)
endif()

if(ENABLE_FOLEAGE)
	set(ENABLE_TERNARY_DPF true)
endif()

if(ENABLE_SPARSE_DPF)
	set(ENABLE_REGULAR_DPF true)
endif()

message(STATUS "General Options\n=======================================================")

message(STATUS "Option: VERBOSE_FETCH         = ${VERBOSE_FETCH}")
message(STATUS "Option: FETCH_BITPOLYMUL      = ${FETCH_BITPOLYMUL_IMPL}\n")

message(STATUS "Option: ENABLE_ALL_OT         = ON/OFF")
message(STATUS "Option: ENABLE_BITPOLYMUL     = ${ENABLE_BITPOLYMUL}")
message(STATUS "Option: LIBOTE_STD_VER        = ${LIBOTE_STD_VER}")

message(STATUS "Base OT protocols\n=======================================================")
message(STATUS "Option: ENABLE_SIMPLESTOT     = ${ENABLE_SIMPLESTOT}")
message(STATUS "Option: ENABLE_SIMPLESTOT_ASM = ${ENABLE_SIMPLESTOT_ASM}")
message(STATUS "Option: ENABLE_MRR            = ${ENABLE_MRR}")
message(STATUS "Option: ENABLE_MRR_TWIST      = ${ENABLE_MRR_TWIST}")
message(STATUS "Option: ENABLE_MR             = ${ENABLE_MR}")
message(STATUS "Option: ENABLE_MR_KYBER       = ${ENABLE_MR_KYBER}")

message(STATUS "1-out-of-2 OT Extension protocols\n=======================================================")
message(STATUS "Option: ENABLE_KOS            = ${ENABLE_KOS}")
message(STATUS "Option: ENABLE_IKNP           = ${ENABLE_IKNP}")
message(STATUS "Option: ENABLE_SILENTOT       = ${ENABLE_SILENTOT}")
message(STATUS "Option: ENABLE_SOFTSPOKEN_OT  = ${ENABLE_SOFTSPOKEN_OT}\n\n")

message(STATUS "1-out-of-2 Delta-OT Extension protocols\n=======================================================")
message(STATUS "Option: ENABLE_DELTA_KOS      = ${ENABLE_DELTA_KOS}\n\n")

message(STATUS "Vole protocols\n=======================================================")
message(STATUS "Option: ENABLE_SILENT_VOLE    = ${ENABLE_SILENT_VOLE}\n\n")


message(STATUS "DPF protocols\n=======================================================")
message(STATUS "Option: ENABLE_REGULAR_DPF    = ${ENABLE_REGULAR_DPF}")
message(STATUS "Option: ENABLE_SPARSE_DPF     = ${ENABLE_SPARSE_DPF}")
message(STATUS "Option: ENABLE_TERNARY_DPF    = ${ENABLE_TERNARY_DPF}")
message(STATUS "Option: ENABLE_PPRF           = ${ENABLE_PPRF}\n\n")

message(STATUS "OLE and Triple protocols\n=======================================================")
message(STATUS "Option: ENABLE_FOLEAGE        = ${ENABLE_FOLEAGE}\n\n")

message(STATUS "1-out-of-N OT Extension protocols\n=======================================================")
message(STATUS "Option: ENABLE_OOS            = ${ENABLE_OOS}")
message(STATUS "Option: ENABLE_KKRT           = ${ENABLE_KKRT}\n\n")


message(STATUS "other \n=======================================================")
message(STATUS "Option: NO_KOS_WARNING        = ${NO_KOS_WARNING}")
message(STATUS "Option: LIBOTE_SHARED         = ${LIBOTE_SHARED}\n\n")


#############################################
#               Config Checks               #
#############################################

if(ENABLE_MOCK_OT)
	message("\n\nWarning: the libary is being build with insecure mock base OTs. ENABLE_MOCK_OT=${ENABLE_MOCK_OT}\n\n")
endif()

if(NOT UNIX OR APPLE OR MSVC)
	#if(ENABLE_SIMPLESTOT_ASM)
	#	message(FATAL_ERROR "ENABLE_SIMPLESTOT_ASM only supported on Linux")
	#endif()
	if(ENABLE_MR_KYBER)
		message(FATAL_ERROR "ENABLE_MR_KYBER only supported on Linux")
	endif()

endif()

if( NOT ENABLE_SIMPLESTOT AND
	NOT ENABLE_SIMPLESTOT_ASM AND
	NOT ENABLE_MRR AND
	NOT ENABLE_MRR_TWIST AND
	NOT ENABLE_MR AND
	NOT ENABLE_MR_KYBER)
	message(WARNING "NO Base OT enabled.")
endif()

if (ENABLE_MRR_TWIST AND NOT ENABLE_SODIUM)
	message(FATAL_ERROR "ENABLE_MRR_TWIST requires ENABLE_SODIUM")
endif()

if (ENABLE_MRR_TWIST AND NOT SODIUM_MONTGOMERY)
	message(FATAL_ERROR "ENABLE_MRR_TWIST requires libsodium to support Montgomery curve noclamp operations. get sodium from https://github.com/osu-crypto/libsodium to enable.")
endif()

if ((ENABLE_SIMPLESTOT OR ENABLE_MR OR ENABLE_NP OR ENABLE_MRR) AND NOT (ENABLE_SODIUM OR ENABLE_RELIC))
	message(FATAL_ERROR "ENABLE_SIMPLESTOT, ENABLE_MR, ENABLE_NP, and ENABLE_MRR require ENABLE_SODIUM or ENABLE_RELIC")
endif()

if(ENABLE_IKNP AND NOT ENABLE_KOS)
	message(FATAL_ERROR "ENABLE_IKNP requires ENABLE_KOS")
endif()


if(LIBOTE_SHARED AND NOT ENABLE_PIC AND NOT MSVC)
	message(FATAL_ERROR " LIBOTE_SHARED requires ENABLE_PIC. Set ENABLE_PIC to true and recompile.")
endif()


if(ENABLE_SIMPLESTOT_ASM AND ENABLE_PIC)
	message(FATAL_ERROR " ENABLE_SIMPLESTOT_ASM can not be compiled with ENABLE_PIC.")
endif()
if(ENABLE_MR_KYBER AND ENABLE_PIC)
	message(FATAL_ERROR " ENABLE_MR_KYBER can not be compiled with ENABLE_PIC.")
endif()


#include(${CMAKE_CURRENT_LIST_DIR}/../cryptoTools/cmake/cryptoToolsBuildOptions.cmake)
