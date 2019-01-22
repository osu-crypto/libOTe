#pragma once


#define OTE_RANDOM_ORACLE 1
#define OTE_DAVIE_MEYER_AES 2

// build the library with simplest OT enabled
/* #undef ENABLE_SIMPLESTOT */



// build the library with Kyber OT enabled
//#define ENABLE_KYBEROT ON

// Choose which hash function should be used with KOS
#define OTE_KOS_HASH OTE_DAVIE_MEYER_AES

#define OTE_KOS_FIAT_SHAMIR