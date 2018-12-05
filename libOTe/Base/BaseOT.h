#pragma once


#include "SimplestOT.h"
#include "naor-pinkas.h"
namespace osuCrypto
{
#ifdef ENABLE_SIMPLESTOT

#define LIBOTE_HAS_BASE_OT
    using DefaultBaseOT = SimplestOT;
#elif (defined ENABLE_RELIC  || ENABLE_MIRACL)

#define LIBOTE_HAS_BASE_OT
    using DefaultBaseOT = NaorPinkas;
#endif
}