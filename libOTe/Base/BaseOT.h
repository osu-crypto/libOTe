#pragma once


#include "SimplestOT.h"
#include "naor-pinkas.h"
#include "MasnyRindal.h"
namespace osuCrypto
{
#ifdef ENABLE_SIMPLESTOT_ASM
#define LIBOTE_HAS_BASE_OT
    using DefaultBaseOT = AsmSimplestOT;
#elif defined ENABLE_MR
#define LIBOTE_HAS_BASE_OT
    using DefaultBaseOT = MasnyRindal;
#elif defined ENABLE_NP_KYBER
#define LIBOTE_HAS_BASE_OT
    using DefaultBaseOT = MasnyRindalKyber;
#elif defined ENABLE_SIMPLESTOT
#define LIBOTE_HAS_BASE_OT
    using DefaultBaseOT = SimplestOT;
#elif defined ENABLE_NP
#define LIBOTE_HAS_BASE_OT
    using DefaultBaseOT = NaorPinkas;
#endif
}