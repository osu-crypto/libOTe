#pragma once


#include "SimplestOT.h"
#include "naor-pinkas.h"
namespace osuCrypto
{
#ifdef ENABLE_SIMPLEST_ASM_LIB

#define LIBOTE_HAS_BASE_OT
    using DefaultBaseOT = SimplestOT;
#elif defined NAOR_PINKAS

#define LIBOTE_HAS_BASE_OT
    using DefaultBaseOT = NaorPinkas;
#endif
}