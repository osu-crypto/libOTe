

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
	if(UNIX AND NOT(APPLE OR MSVC))
		set(oc_BB ${ENABLE_ALL_OT})
	else()
		set(oc_BB OFF)
	endif()
	set(ENABLE_SIMPLESTOT_ASM ${oc_BB}						CACHE BOOL "" FORCE)
	set(ENABLE_MR_KYBER       ${oc_BB}						CACHE BOOL "" FORCE)

	# requires sse
	if(ENABLE_SSE)
		set(oc_BB ${ENABLE_ALL_OT})
	else()
		set(oc_BB OFF)
	endif()
	set(ENABLE_SILENTOT    ${oc_BB}						CACHE BOOL "" FORCE)


	# general
	set(ENABLE_KOS            ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_IKNP           ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_SOFTSPOKEN_OT  ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_DELTA_KOS      ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_OOS            ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_KKRT           ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_SILENTOT		  ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	set(ENABLE_SILENT_VOLE		  ${ENABLE_ALL_OT}						CACHE BOOL "" FORCE)
	unset(ENABLE_ALL_OT CACHE)
endif()


if(APPLE)
	option(ENABLE_BITPOLYMUL     "Build with bit poly mul inegration" FALSE)
else()
	option(ENABLE_BITPOLYMUL     "Build with bit poly mul inegration" TRUE)
endif()

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

option(ENABLE_INSECURE_SILVER   "Build with silver codes." OFF)
option(ENABLE_LDPC              "Build with ldpc functions." OFF)
if(ENABLE_INSECURE_SILVER)
	set(ENABLE_LDPC ON)
endif()
option(NO_KOS_WARNING        "Build with no kos security warning." OFF)


EVAL(FETCH_BITPOLYMUL_IMPL 
	(DEFINED FETCH_BITPOLYMUL AND FETCH_BITPOLYMUL) OR
	((NOT DEFINED FETCH_BITPOLYMUL) AND (FETCH_AUTO AND ENABLE_BITPOLYMUL)))

if(ENABLE_SILENT_VOLE OR ENABLE_SILENTOT OR ENABLE_SOFTSPOKEN_OT)
	set(ENABLE_PPRF true)
endif()

option(VERBOSE_FETCH        "Print build info for fetched libraries" ON)


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
message(STATUS "Option: ENABLE_SILENT_VOLE      = ${ENABLE_SILENT_VOLE}\n\n")

message(STATUS "1-out-of-N OT Extension protocols\n=======================================================")
message(STATUS "Option: ENABLE_OOS            = ${ENABLE_OOS}")
message(STATUS "Option: ENABLE_KKRT           = ${ENABLE_KKRT}\n\n")


message(STATUS "other \n=======================================================")
message(STATUS "Option: NO_KOS_WARNING       = ${NO_KOS_WARNING}")
message(STATUS "Option: ENABLE_PPRF          = ${ENABLE_PPRF}\n\n")

#############################################
#               Config Checks               #
#############################################

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
