#pragma once


#define OTE_RANDOM_ORACLE 1
#define OTE_DAVIE_MEYER_AES 2


// build the library with simplest OT enabled
#define ENABLE_SIMPLESTOT ON

// build the library with Silent OT Extension enabled
#define ENABLE_SILENTOT ON

// Silent OT requires bit poly mul
#ifdef ENABLE_SILENTOT
	#define ENABLE_BITPOLYMUL ON
#endif

// build the library with Kyber OT enabled
// #define ENABLE_KYBEROT ON


// build the library with simplest OT enabled
#define OTE_KOS_HASH OTE_DAVIE_MEYER_AES


// build the library where KOS is round optimized.
/* #undef OTE_KOS_FIAT_SHAMIR */
