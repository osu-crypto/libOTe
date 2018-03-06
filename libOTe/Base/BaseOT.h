#pragma once


#include "SimplestOT.h"
#include "naor-pinkas.h"
namespace osuCrypto
{
#ifdef ENABLE_SIMPLEST_OT
    using DefaultBaseOT = SimplestOT;
#else
    using DefaultBaseOT = NaorPinkas;
#endif
}