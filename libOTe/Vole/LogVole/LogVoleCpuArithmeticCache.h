#pragma once

namespace osuCrypto::LogVole::detail
{
    // The former CRT/gadget function-static settings, captured once when the
    // owning ring context is built. Arithmetic borrows this value directly.
    struct CpuArithmeticCache
    {
        bool mCrtQuotient = true;
        bool mFastCrt = false;
        bool mVectorCrt = false;
        bool mFusedGadget = false;
        bool mFusedLowDigit = false;

        CpuArithmeticCache();
    };
}
