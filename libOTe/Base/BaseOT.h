#pragma once


#include "SimplestOT.h"
#include "naor-pinkas.h"
namespace osuCrypto
{
#ifdef ENABLE_SIMPLESTOT
    using DefaultBaseOT = SimplestOT;
#else
    using DefaultBaseOT = NaorPinkas;
#endif
}