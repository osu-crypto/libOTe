#pragma once

// build the library with "simplest" Base OT enabled
/* #undef ENABLE_SIMPLESTOT */

// build the library with the ASM "simplest" Base OT enabled
/* #undef ENABLE_SIMPLESTOT_ASM */

// build the library with Masney Rindal Base OT enabled
/* #undef ENABLE_MR */

// build the library with Masney Rindal Kyber Base OT enabled
/* #undef ENABLE_MR_KYBER */

// build the library with Naor Pinkas Base OT enabled
/* #undef ENABLE_NP */



// build the library with Keller Orse Scholl OT-Ext enabled
/* #undef ENABLE_KOS */

// build the library with IKNP OT-Ext enabled
/* #undef ENABLE_IKNP */

// build the library with Silent OT Extension enabled
/* #undef ENABLE_SILENTOT */



// build the library with KOS Delta-OT-ext enabled
#define ENABLE_DELTA_KOS ON

// build the library with IKNP Delta-OT-ext enabled
/* #undef ENABLE_DELTA_IKNP */



// build the library with OOS 1-oo-N OT-Ext enabled
/* #undef ENABLE_OOS */

// build the library with KKRT 1-oo-N OT-Ext enabled
/* #undef ENABLE_KKRT */

// build the library with RR 1-oo-N OT-Ext OT-ext enabled
/* #undef ENABLE_RR */

// build the library with RR approx k-oo-N OT-ext enabled
/* #undef ENABLE_AKN */


#define OTE_RANDOM_ORACLE 1
#define OTE_DAVIE_MEYER_AES 2

#define OTE_KOS_HASH OTE_DAVIE_MEYER_AES

// build the library where KOS is round optimized.
/* #undef OTE_KOS_FIAT_SHAMIR */


#if defined(ENABLE_SIMPLESTOT_ASM) && defined(_MSC_VER)
    #undef ENABLE_SIMPLESTOT_ASM
    #warning "ENABLE_SIMPLESTOT_ASM should not be defined on windows."
#endif
#if defined(ENABLE_MR_KYBER) && defined(_MSC_VER)
    #undef ENABLE_MR_KYBER
    #warning "ENABLE_MR_KYBER should not be defined on windows."
#endif
        
