#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_SPIN
#include "libOTe/TwoChooseOne/ConfigureCode.h"
#include "cryptoTools/Common/Aligned.h"
#include <spin/Code.h>
#include <spin/PreparedEncoder.h>
#include <algorithm>
#include <cstring>
#include <optional>
#include <stdexcept>

namespace osuCrypto {

// Silent OT's SPIN compression (MultType::Spin): one party's prepared Turbo
// SPIN encoder (spin::Parameters::PacketRs8T64) and its scratch. Both parties
// must construct it from the same request, seed and noise distribution.
// Regular noise uses the full seeded setup; stationary noise uses the banked
// heuristic refresh. SpinConfigure (ConfigureCode.h) picks the noise.
class SpinCode {
public:
    // K for a request: the next multiple of 128, at least 8192 so the noise
    // configuration has room for its partitions. Not tied to the distance
    // certificates, which cover K = 2^14, 2^16, ..., 2^26.
    static u64 messageSize(u64 requested) {
        constexpr u64 minimum = 8192, maximum = u64(1) << 40;
        if (!requested || requested > maximum)
            throw std::invalid_argument("SPIN OT request size is out of range");
        const auto k = roundUpTo(std::max(requested, minimum), spin::message_alignment(parameters));
        if (!spin::valid_message_size(parameters, k))
            throw std::invalid_argument("SPIN OT request exceeds the largest Turbo code");
        return k;
    }

    SpinCode(u64 requested, block seed, SdNoiseDistribution noise)
        : mEncoder({ messageSize(requested), parameters, seed.get<u64>(0), seed.get<u64>(1) }, setup(noise))
        , mBlocks(mEncoder.make_workspace())
    {}

    // Reseeds `code` when its size and noise distribution match (no allocation
    // for stationary noise; a full rebuild of the map for regular noise with a
    // new seed); otherwise constructs it.
    static void prepare(std::optional<SpinCode>& code, u64 requested, block seed, SdNoiseDistribution noise) {
        if (code && code->messageSize() == messageSize(requested) &&
            code->mEncoder.setup_options().mode == setup(noise).mode)
            code->mEncoder.setCodeSeed({ seed.get<u64>(0), seed.get<u64>(1) });
        else
            code.emplace(requested, seed, noise);
    }

    u64 messageSize() const { return mEncoder.message_size(); }
    u64 codeSize() const { return mEncoder.code_size(); }
    const spin::PreparedEncoder& encoder() const { return mEncoder; }

    // Transposed encoding in place: x holds 2K blocks; the first K receive the
    // result and the rest are unchanged.
    void transpose(span<block> x) {
        mEncoder.transpose_inplace<block>(std::span<block>(x.data(), x.size()), mBlocks);
    }

    // The same map on 2K choice bytes, each 0 or 1 (correlated OT's separate
    // choices), through SPIN's bit-vector transpose. The first K bytes receive
    // the result. The first call allocates the bit workspace and scratch.
    void transpose(span<u8> x) {
        const u64 n = codeSize(), k = messageSize();
        if (x.size() != n)
            throw std::invalid_argument("SPIN choice transpose needs 2K bytes");
        if (!mBits) {
            mBits.emplace(mEncoder.make_bit_workspace());
            mBitsIn.resize(n / 64);
            mBitsOut.resize(k / 64);
        }
        constexpr u64 low = 0x0101010101010101ull;
        u64 high = 0;
        for (u64 w = 0; w < n / 64; ++w) {
            u64 word = 0;
            for (u64 j = 0; j < 8; ++j) {
                u64 v;
                std::memcpy(&v, x.data() + 64 * w + 8 * j, 8);
                high |= v & ~low;
                word |= ((v * 0x0102040810204080ull) >> 56) << (8 * j);
            }
            mBitsIn[w] = word;
        }
        if (high)
            throw std::invalid_argument("SPIN choice bytes must be 0 or 1");
        mEncoder.transpose_bits(std::span<const u64>(mBitsIn.data(), mBitsIn.size()),
            std::span<u64>(mBitsOut.data(), mBitsOut.size()), *mBits);
        for (u64 i = 0; i < k; i += 8) {
            const u64 bits = (mBitsOut[i / 64] >> (i % 64)) & 255;
            const u64 v = (((bits & 127) * 0x0002040810204081ull) & low) | ((bits >> 7) << 56);
            std::memcpy(x.data() + i, &v, 8);
        }
    }

private:
    static constexpr auto parameters = spin::Parameters::PacketRs8T64;
    static spin::SetupOptions setup(SdNoiseDistribution noise) {
        if (noise != SdNoiseDistribution::Regular && noise != SdNoiseDistribution::Stationary)
            throw std::invalid_argument("Invalid SPIN noise distribution");
        return { noise == SdNoiseDistribution::Stationary ? spin::SetupMode::BankedHeuristic : spin::SetupMode::Full };
    }

    spin::PreparedEncoder mEncoder;
    spin::PreparedEncoder::Workspace mBlocks;
    std::optional<spin::PreparedEncoder::BitWorkspace> mBits;
    AlignedUnVector<u64> mBitsIn, mBitsOut;
};

}
#endif
