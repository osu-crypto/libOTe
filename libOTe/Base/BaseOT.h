#pragma once


#include "SimplestOT.h"
#include "naor-pinkas.h"
#include "MasnyRindal.h"
#include "MoellerPopfOT.h"
#include "RistrettoPopfOT.h"
#include "EKEPopf.h"
#include "FeistelMulRistPopf.h"

namespace osuCrypto
{
#define LIBOTE_HAS_BASE_OT
#ifdef ENABLE_SIMPLESTOT_ASM
    using DefaultBaseOT = AsmSimplestOT;
#elif defined ENABLE_MR
    using DefaultBaseOT = MasnyRindal;
#elif defined ENABLE_NP_KYBER
    using DefaultBaseOT = MasnyRindalKyber;
#elif defined ENABLE_SIMPLESTOT
    using DefaultBaseOT = SimplestOT;
#elif defined ENABLE_POPF_MOELLER
    using DefaultBaseOT = MoellerPopfOT<DomainSepEKEPopf>;
#elif defined ENABLE_POPF_RISTRETTO
    using DefaultBaseOT = RistrettoPopfOT<DomainSepFeistelMulRistPopf>;
#elif defined ENABLE_NP
    using DefaultBaseOT = NaorPinkas;
#else
#undef LIBOTE_HAS_BASE_OT
#endif
}
