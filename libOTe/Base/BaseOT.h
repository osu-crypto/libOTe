#pragma once


#include "SimplestOT.h"
#include "naor-pinkas.h"
#include "MasnyRindal.h"
#include "McRosRoyTwist.h"
#include "McRosRoy.h"
#include "libOTe/Tools/Popf/EKEPopf.h"
#include "libOTe/Tools/Popf/FeistelMulRistPopf.h"

namespace osuCrypto
{
#define LIBOTE_HAS_BASE_OT
#ifdef ENABLE_SIMPLESTOT_ASM
    using DefaultBaseOT = AsmSimplestOT;
#elif defined ENABLE_MRR_TWIST && defined ENABLE_SSE
    using DefaultBaseOT = McRosRoyTwist;
#elif defined ENABLE_MR
    using DefaultBaseOT = MasnyRindal;
#elif defined ENABLE_MRR
    using DefaultBaseOT = McRosRoy;
#elif defined ENABLE_NP_KYBER
    using DefaultBaseOT = MasnyRindalKyber;
#elif defined ENABLE_SIMPLESTOT
    using DefaultBaseOT = SimplestOT;
#elif defined ENABLE_NP
    using DefaultBaseOT = NaorPinkas;
#else
#undef LIBOTE_HAS_BASE_OT
#endif
}
