#pragma once

namespace osuCrypto
{
    // CPU dispatch decisions captured once by the owner and borrowed read-only.
    // Scalar mode skips detection; neither mode reads process configuration.
    class CpuCapabilities
    {
    public:
        enum class Mode { Automatic, Scalar };

        explicit CpuCapabilities(Mode mode = Mode::Automatic);

        bool avx512() const noexcept { return mAvx512; }
        bool ifma() const noexcept { return mIfma; }

    private:
        bool mAvx512 = false;
        bool mIfma = false;
    };
}
