#pragma once

namespace osuCrypto::LogVole::detail
{
    // CPU dispatch decisions captured once by the owner and borrowed read-only.
    // Scalar mode skips detection; neither mode reads process configuration.
    class CpuArithmeticCache
    {
    public:
        enum class Mode { Automatic, Scalar };

        explicit CpuArithmeticCache(Mode mode = Mode::Automatic);

        bool avx512() const noexcept { return mAvx512; }
        bool ifma() const noexcept { return mIfma; }

    private:
        bool mAvx512 = false;
        bool mIfma = false;
    };
}
