#include "libOTe/Vole/LogVole/LogVoleCpuSampler.h"
#include "libOTe/Vole/LogVole/LogVoleCpuArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCpuZkArith.h"
#include "libOTe/Vole/LogVole/LogVoleCpuZk.h"
#include "libOTe/Vole/LogVole/LogVoleRing.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleZk.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#endif
#include "libOTe/Vole/LogVole/LogVoleCore.h"
#include "libOTe/Vole/LogVole/LogVoleLhe.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"
#include "libOTe_Tests/LogVole_TestUtil.h"
#include "cryptoTools/Common/CLP.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"
#include "seal/util/ntt.h"
#include "seal/util/rlwe.h"
#include "seal/util/uintarith.h"
#include "seal/util/clipnormal.h"
#include "seal/randomtostd.h"

#include <array>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <tuple>

using namespace osuCrypto;
using namespace osuCrypto::LogVole;

void LogVole_Cpu_FusedExpandEvalMatchesSeparateOperations(const oc::CLP&)
{
    PRNG random(toBlock(0x4556414c, 0x46555345));
    for (unsigned limbs : {2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    for (unsigned mu : {3, 9})
    for (bool gadget : {false, true})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const unsigned digitBits = limbs*bits/2, plaintextBits = bits-1;
        std::vector<RnsPoly> keys(mu), inputs(mu), initial(mu);
        for (unsigned row = 0; row < mu; ++row)
        {
            keys[row] = sampleUniformPoly(ctx, random);
            inputs[row] = sampleUniformPoly(ctx, random);
            initial[row] = sampleUniformPoly(ctx, random);
            if (gadget)
                for (unsigned j = 0; j < limbs; ++j)
                    if (j != row%limbs)
                        std::fill_n(inputs[row].mCoeffs.data()+j*1024, 1024, u64{0});
        }
        LencEncodeOutput enc{};
        LOGVOLE_REQUIRE_TRUE(lencEncTrunc(ctx, keys, 1, digitBits, plaintextBits,
            random, enc, 0, 0, 0, false, gadget));
        DigestTree tree{};
        LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(ctx, inputs, 1, digitBits, plaintextBits,
            tree, enc.mLacct.mWidthPadded, gadget));
        // Independent composition of the existing coefficient-domain evaluator,
        // forward transform and ring subtraction specifies the fused operation.
        std::vector<RnsPoly> eval;
        LOGVOLE_REQUIRE_TRUE(lencEvalTrunc(ctx, enc.mLacct, tree, mu, 1, digitBits,
            plaintextBits, eval, false, 1, gadget));
        LOGVOLE_REQUIRE_TRUE(forwardNttBatch(eval, ctx));
        auto expected = initial;
        for (unsigned row = 0; row < mu; ++row)
            LOGVOLE_REQUIRE_TRUE(ringSubInplace(expected[row], eval[row], ctx));
        for (u32 workers : {1, 2, 4, 8})
        {
            auto actual = initial;
            LOGVOLE_REQUIRE_TRUE(lencSubtractEvalTruncNttInplace(ctx, enc.mLacct, tree,
                mu, 1, digitBits, plaintextBits, actual, workers, gadget));
            for (unsigned row = 0; row < mu; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, expected[row].mCoeffs));
        }
        auto invalid = initial;
        invalid.pop_back();
        LOGVOLE_REQUIRE_FALSE(lencSubtractEvalTruncNttInplace(ctx, enc.mLacct, tree,
            mu, 1, digitBits, plaintextBits, invalid, 1, gadget));
        for (unsigned row = 0; row < invalid.size(); ++row)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(invalid[row].mCoeffs, initial[row].mCoeffs));
    }
}

void LogVole_Cpu_GoldenMarginMatchesIntegerReference(const oc::CLP&)
{
#if !defined(__SIZEOF_INT128__)
    LOGVOLE_SKIP() << "Independent margin oracle requires unsigned __int128";
#else
    PRNG random(toBlock(0x474f4c44, 0x4d415247));
    for (unsigned limbs : {2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    {
        auto moduli = seal::CoeffModulus::Create(1024, std::vector<int>(limbs, bits));
        for (unsigned target = 0; target < limbs; ++target)
        {
            std::vector<seal::Modulus> reduced;
            std::vector<std::size_t> indices;
            std::vector<wideU64> fractions;
            for (unsigned j = 0; j < limbs; ++j) if (j != target)
            {
                indices.push_back(j);
                reduced.push_back(moduli[j]);
                const auto fraction = (~__uint128_t{0}) / moduli[j].value();
                fractions.push_back({static_cast<u64>(fraction), static_cast<u64>(fraction >> 64)});
            }
            seal::util::RNSBase base(reduced, seal::MemoryPoolHandle::ThreadLocal());
            std::span<const seal::util::MultiplyUIntModOperand> inverse(
                base.inv_punctured_prod_mod_base_array(), reduced.size());
            for (std::size_t count : {0, 1, 7, 8, 9, 33, 129})
            {
                std::vector<u64> input(count * limbs + 2);
                random.get(input.data(), input.size());
                for (unsigned j = 0; j < limbs; ++j)
                {
                    const u64 q = moduli[j].value();
                    const std::array<u64, 8> edges = {0, 1, q-1, q, q+1, 2*q-1, 2*q, ~u64{0}};
                    for (std::size_t i = 0; i < std::min(count, edges.size()); ++i)
                        input[1+j*count+i] = edges[i];
                }
                const auto original = input;
                __uint128_t closest = ~__uint128_t{0};
                for (std::size_t i = 0; i < count; ++i)
                {
                    __uint128_t sum = __uint128_t{1} << 127;
                    for (std::size_t j = 0; j < indices.size(); ++j)
                    {
                        const u64 q = reduced[j].value();
                        const u64 residue = (static_cast<__uint128_t>(input[1+indices[j]*count+i] % q) *
                            inverse[j].operand) % q;
                        sum += residue * ((~__uint128_t{0}) / q);
                    }
                    closest = std::min(closest, std::min(sum, __uint128_t{0} - sum));
                }
                for (const auto margin : {__uint128_t{0}, __uint128_t{1},
                    (__uint128_t{1} << 127), ~__uint128_t{0}, closest, closest-1, closest+1})
                {
                    bool accepted = false;
                    const bool used = LogVole::detail::cpuCheckRoundingMargin(input.data()+1, count,
                        moduli, indices, inverse, fractions,
                        {static_cast<u64>(margin), static_cast<u64>(margin >> 64)}, accepted);
                    LOGVOLE_REQUIRE_EQ(accepted, used && (count == 0 || closest >= margin));
                    LOGVOLE_REQUIRE_TRUE(input == original);
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
                    const char* enabled = std::getenv("LV_CPU_VECTOR_GOLDEN_CHECK");
                    LOGVOLE_REQUIRE_EQ(used, (bits == 52 || bits == 55) &&
                        (!enabled || enabled[0] != '0') && __builtin_cpu_supports("avx512f") &&
                        __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512ifma"));
#endif
                }
                bool accepted = true;
                const std::vector<std::size_t> invalid{moduli.size()};
                LOGVOLE_REQUIRE_FALSE(LogVole::detail::cpuCheckRoundingMargin(input.data()+1, count,
                    moduli, invalid, inverse, fractions, {}, accepted));
                LOGVOLE_REQUIRE_TRUE(accepted);
            }
        }
    }
#endif
}

void LogVole_Cpu_ReduceMatchesReference(const oc::CLP&)
{
    PRNG random(toBlock(0x52454455, 0x4345));
    for (int bits : {30, 52, 55, 60})
    for (u64 gap : {1ULL, 32767ULL, 16777215ULL, 16777216ULL})
    for (std::size_t count : {0, 1, 7, 8, 9, 127, 1024})
    {
        const u64 q = (u64{1} << bits) - gap;
        const seal::Modulus modulus(q);
        std::vector<u64> input(count + 2), actual(count + 2, 123), expected = actual;
        random.get(input.data(), input.size());
        const std::array<u64, 8> edges = {0, 1, q-1, q, q+1, 2*q-1, 2*q, ~u64{0}};
        for (std::size_t i = 0; i < count; ++i)
        {
            if (i < edges.size()) input[i+1] = edges[i];
            expected[i+1] = input[i+1] % q;
        }
        const auto original = actual;
        const bool used = LogVole::detail::cpuReduceMod(input.data()+1, actual.data()+1, count, modulus);
        LOGVOLE_REQUIRE_TRUE(actual == (used ? expected : original));
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
        const char* enabled = std::getenv("LV_CPU_VECTOR_REDUCE");
        const bool expectedFast = (bits == 52 || bits == 55) && gap < (u64{1} << 24) &&
            (!enabled || enabled[0] != '0') && __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512dq");
        LOGVOLE_REQUIRE_EQ(used, expectedFast);
#endif
        auto alias = input;
        LOGVOLE_REQUIRE_EQ(LogVole::detail::cpuReduceMod(alias.data()+1, alias.data()+1, count, modulus), used);
        if (used) for (std::size_t i = 0; i < count; ++i) LOGVOLE_REQUIRE_EQ(alias[i+1], expected[i+1]);
        LOGVOLE_REQUIRE_EQ(alias.front(), input.front());
        LOGVOLE_REQUIRE_EQ(alias.back(), input.back());
        if (count)
        {
            // A rejection at the last coefficient must leave earlier outputs
            // untouched too, so a caller can replay the complete scalar pass.
            const u64 limit = ~u64{0};
            input[count] = limit;
            actual = original;
            LOGVOLE_REQUIRE_TRUE(!LogVole::detail::cpuReduceMod(
                input.data()+1, actual.data()+1, count, modulus, &limit));
            LOGVOLE_REQUIRE_TRUE(actual == original);
        }
    }
}

void LogVole_Cpu_ScaleAndRoundMatchesReference(const oc::CLP&)
{
#if !defined(__SIZEOF_INT128__)
    LOGVOLE_SKIP() << "Independent wide-division oracle requires unsigned __int128";
#else
    PRNG random(toBlock(0x5343414c, 0x45524e44));
    for (unsigned limbs : {2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    {
        auto moduli = seal::CoeffModulus::Create(1024, std::vector<int>(limbs, bits));
        auto pool = seal::MemoryPoolHandle::ThreadLocal();
        const seal::util::RNSBase base(moduli, pool);
        for (u64 p : {u64{17}, (u64{1} << (bits - 1)) - 33, moduli[0].value() - 1,
            moduli[0].value(), moduli.back().value(), (u64{1} << bits) - 1})
        for (std::size_t count : {0, 1, 7, 8, 9, 127, 1024})
        {
            std::vector<u64> input(limbs * count), actual(count+2, 123), expected = actual;
            random.get(input.data(), input.size());
            if (count >= 8)
            {
                std::vector<u64> boundaries(limbs * count, 0);
                for (unsigned k = 0; k < 8; ++k)
                {
                    auto* x = boundaries.data() + k * limbs;
                    if (k >= 2) std::copy_n(base.base_prod(), limbs, x);
                    if (k >= 4) seal::util::right_shift_uint(x, 1, limbs, x);
                    if (k == 1 || k == 6) seal::util::add_uint(x, limbs, u64{1}, x);
                    if (k == 2 || k == 5) seal::util::sub_uint(x, limbs, u64{1}, x);
                }
                base.decompose_array(boundaries.data(), count, pool);
                for (unsigned j = 0; j < limbs; ++j)
                    std::copy_n(boundaries.data()+j*count, 8, input.data()+j*count);
            }
            for (std::size_t k = 0; k < count; ++k)
            {
                // Independent wide division, with the same specified 128-bit
                // fractional rounding as the production scalar implementation.
                __uint128_t fraction = __uint128_t{1} << 127;
                u64 result = 0;
                for (unsigned j = 0; j < limbs; ++j)
                {
                    const u64 q = moduli[j].value();
                    const u64 x = static_cast<u64>((static_cast<__uint128_t>(input[j*count+k] % q) *
                        base.inv_punctured_prod_mod_base_array()[j].operand) % q);
                    const __uint128_t numerator = static_cast<__uint128_t>(x) * p;
                    const auto term = (numerator % q) * (~__uint128_t{0} / q);
                    const auto next = fraction + term;
                    result = (result + static_cast<u64>(numerator / q) + (next < fraction)) % p;
                    fraction = next;
                }
                expected[k+1] = result;
            }
            const auto original = actual;
            const bool used = LogVole::detail::cpuScaleAndRoundRns(input.data(), actual.data()+1, count, base, p);
            LOGVOLE_REQUIRE_TRUE(actual == (used ? expected : original));
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
            const char* enabled = std::getenv("LV_CPU_VECTOR_ROUND");
            const bool expectedFast = (limbs == 4 || limbs == 8) && (bits == 52 || bits == 55) &&
                (!enabled || enabled[0] != '0') && __builtin_cpu_supports("avx512f") &&
                __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512ifma");
            LOGVOLE_REQUIRE_EQ(used, expectedFast);
#endif
        }
        std::vector<u64> unchanged(16, 123), input(8 * limbs);
        LOGVOLE_REQUIRE_TRUE(!LogVole::detail::cpuScaleAndRoundRns(input.data(), unchanged.data(), 8,
            base, u64{1} << bits));
        LOGVOLE_REQUIRE_TRUE(std::all_of(unchanged.begin(), unchanged.end(), [](u64 x) { return x == 123; }));
    }
#endif
}

void LogVole_Cpu_FusedGadgetMatchesBalancedReference(const oc::CLP&)
{
    PRNG random(toBlock(0x47414447, 0x4554));
    for (unsigned limbs : {4, 8})
    {
        const unsigned bits = limbs == 4 ? 55 : 52, digitBits = limbs * bits / 2;
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto& base = *hostContext->key_context_data()->rns_tool()->base_q();
        for (unsigned trial = 0; trial < 16; ++trial)
        {
            auto poly = sampleUniformPoly(ctx, random);
            // Exact integer boundary cases, converted to RNS by SEAL: around
            // Q/2, the low digit's rounding tie, and the high digit's sign bit.
            std::vector<u64> integers(limbs * 1024, 0);
            for (unsigned i = 0; i < 24; ++i)
            {
                auto* value = integers.data() + i * limbs;
                const unsigned bit = i < 12 ? digitBits - 1 : 2 * digitBits - 2;
                value[bit / 64] = u64{1} << (bit % 64);
                if (i % 3 == 0) seal::util::sub_uint(value, limbs, u64{1}, value);
                if (i % 3 == 2) seal::util::add_uint(value, limbs, u64{1}, value);
                if (i % 12 >= 6) seal::util::sub_uint(base.base_prod(), value, limbs, value);
            }
            for (unsigned i = 24; i < 30; ++i)
            {
                auto* value = integers.data() + i * limbs;
                seal::util::right_shift_uint(base.base_prod(), 1, limbs, value);
                if (i % 3 == 0) seal::util::sub_uint(value, limbs, u64{1}, value);
                if (i % 3 == 2) seal::util::add_uint(value, limbs, u64{1}, value);
            }
            base.decompose_array(integers.data(), 1024, seal::MemoryPoolHandle::ThreadLocal());
            for (unsigned j = 0; j < limbs; ++j)
                std::copy_n(integers.data() + j * 1024, 32, poly.mCoeffs.data() + j * 1024);
            std::vector<RnsPoly> reference, actual;
            // Asking for both digits uses the general signed-integer path.
            LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRangeCentered(poly, digitBits, 0, 2, ctx, reference));
            LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRangeCentered(poly, digitBits, 1, 1, ctx, actual));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[0].mCoeffs, reference[1].mCoeffs));
            const bool fused = LogVole::detail::cpuCenteredHighDigit(poly.mCoeffs.data(),
                actual[0].mCoeffs.data(), 1024, digitBits, base);
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
            const auto enabled = [](const char* name) {
                const char* value = std::getenv(name);
                return !value || value[0] != '0';
            };
            const bool expectedFast = __builtin_cpu_supports("avx512f") &&
                __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512ifma") &&
                enabled("LV_CPU_FUSED_GADGET") && enabled("LV_CPU_VECTOR_CRT") && enabled("LV_CPU_FAST_CRT");
            LOGVOLE_REQUIRE_EQ(fused, expectedFast);
#endif
            if (fused) LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[0].mCoeffs, reference[1].mCoeffs));
            RnsPoly recomposed;
            LOGVOLE_REQUIRE_TRUE(gadgetRecomposeBits(reference, digitBits, ctx, recomposed));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(recomposed.mCoeffs, poly.mCoeffs));
            // Unsupported shape must decline before changing any destination.
            std::vector<u64> untouched(limbs * 1024, 123);
            LOGVOLE_REQUIRE_TRUE(!LogVole::detail::cpuCenteredHighDigit(
                poly.mCoeffs.data(), untouched.data(), 1023, digitBits, base));
            LOGVOLE_REQUIRE_TRUE(std::all_of(untouched.begin(), untouched.end(), [](u64 x) { return x == 123; }));
        }
    }
}

void LogVole_Cpu_LowDigitMatchesIntegerReference(const oc::CLP&)
{
    PRNG random(toBlock(0x4c4f5744, 0x49474954));
    for (unsigned limbs : {2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    for (unsigned digitBits : {63, 110, 208, 256})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        auto poly = sampleUniformPoly(ctx, random);
        // CRT integers 0, 1, 2, Q-1 and Q-2 exercise a quotient estimate
        // immediately below an integer, including its final correction.
        for (unsigned j = 0; j < limbs; ++j)
        {
            const u64 q = ringModulusValue(ctx, j);
            for (unsigned k = 0; k < 3; ++k) poly.mCoeffs[j*1024+k] = k;
            poly.mCoeffs[j*1024+3] = q-1;
            poly.mCoeffs[j*1024+4] = q-2;
        }
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto& base = *hostContext->key_context_data()->rns_tool()->base_q();
        auto pool = seal::MemoryPoolHandle::ThreadLocal();
        std::vector<u64> expected(poly.mCoeffs.begin(), poly.mCoeffs.end());
        base.compose_array(expected.data(), 1024, pool);
        for (unsigned i = 0; i < 1024; ++i)
        for (unsigned w = 0; w < limbs; ++w)
        {
            if (w*64 >= digitBits) expected[i*limbs+w] = 0;
            else if ((w+1)*64 > digitBits)
                expected[i*limbs+w] &= (u64{1} << (digitBits-w*64))-1;
        }
        base.decompose_array(expected.data(), 1024, pool);
        std::vector<RnsPoly> actual;
        LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRange(poly, digitBits, 0, 1, ctx, actual));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[0].mCoeffs, expected));
        std::vector<u64> direct(limbs*1024+2, 123);
        const bool used = LogVole::detail::cpuLowDigitRns(poly.mCoeffs.data(), direct.data()+1,
            1024, digitBits, base);
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
        const auto enabled = [](const char* name) {
            const char* value = std::getenv(name);
            return !value || value[0] != '0';
        };
        const bool supported = ((limbs==4 && bits==55 && digitBits==110) ||
            (limbs==8 && bits==52 && digitBits==208)) &&
            __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512dq") &&
            __builtin_cpu_supports("avx512ifma") && enabled("LV_CPU_FUSED_LOW_DIGIT") &&
            enabled("LV_CPU_VECTOR_CRT") && enabled("LV_CPU_FAST_CRT");
        LOGVOLE_REQUIRE_EQ(used, supported);
#endif
        if (used) LOGVOLE_REQUIRE_TRUE(std::equal(expected.begin(), expected.end(), direct.begin()+1));
        else LOGVOLE_REQUIRE_TRUE(std::all_of(direct.begin(), direct.end(), [](u64 x) { return x==123; }));
        LOGVOLE_REQUIRE_EQ(direct.front(), u64{123});
        LOGVOLE_REQUIRE_EQ(direct.back(), u64{123});
        for (std::size_t count : {0, 1, 7, 9, 1023})
        {
            std::fill(direct.begin(), direct.end(), 123);
            LOGVOLE_REQUIRE_TRUE(!LogVole::detail::cpuLowDigitRns(
                poly.mCoeffs.data(), direct.data()+1, count, digitBits, base));
            LOGVOLE_REQUIRE_TRUE(std::all_of(direct.begin(), direct.end(), [](u64 x) { return x==123; }));
        }
    }
}

void LogVole_Cpu_LheDecryptMatchesTransformReference(const oc::CLP&)
{
    PRNG random(toBlock(0x4c4845, 0x444543));
    for (unsigned limbs : {2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto& hostModuli = getRingHostModuli(ctx);
        LOGVOLE_REQUIRE_EQ(hostModuli.size(), static_cast<std::size_t>(limbs));
        constexpr unsigned rows = 9;
        auto sk = sampleUniformPoly(ctx, random);
        auto skNtt = sk;
        LOGVOLE_REQUIRE_TRUE(forwardNtt(skNtt, ctx));
        std::vector<RnsPoly> publicA(rows), cipher(rows), expected(rows);
        for (unsigned row = 0; row < rows; ++row)
        {
            publicA[row] = sampleUniformPolyNtt(ctx, random);
            auto& ct = cipher[row];
            ct.mCoeffs.resize(limbs * 1024);
            random.get(ct.mCoeffs.data(), ct.mCoeffs.size());
            // The optimized coefficient path must preserve the original
            // arbitrary-u64 canonicalization, including wraparound boundaries.
            ct.mCoeffs[0] = 0;
            ct.mCoeffs[1] = ~u64{0};
            ct.mCoeffs[2] = ringModulusValue(ctx, 0);
            auto& result = expected[row];
            result = ct;
            LOGVOLE_REQUIRE_TRUE(forwardNtt(result, ctx));
            for (unsigned j = 0; j < limbs; ++j)
            for (unsigned k = 0; k < 1024; ++k)
            {
                const auto i = j * 1024 + k;
                const auto& q = hostModuli[j];
                result.mCoeffs[i] = seal::util::sub_uint_mod(result.mCoeffs[i],
                    seal::util::multiply_uint_mod(publicA[row].mCoeffs[i], skNtt.mCoeffs[i], q), q);
            }
            LOGVOLE_REQUIRE_TRUE(inverseNtt(result, ctx));
        }
        for (u32 workers : {1, 3, 8})
        for (bool inputNtt : {false, true})
        for (bool outputNtt : {false, true})
        {
            auto input = cipher;
            auto reference = expected;
            if (inputNtt) LOGVOLE_REQUIRE_TRUE(forwardNttBatch(input, ctx));
            if (outputNtt) LOGVOLE_REQUIRE_TRUE(forwardNttBatch(reference, ctx));
            std::vector<RnsPoly> actual;
            LOGVOLE_REQUIRE_TRUE(lheDec(ctx, input, sk, actual, &publicA, inputNtt, outputNtt, workers));
            for (unsigned row = 0; row < rows; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, reference[row].mCoeffs));
            auto consumed = input;
            LOGVOLE_REQUIRE_TRUE(lheDec(ctx, std::move(consumed), sk, actual, &publicA, inputNtt, outputNtt, workers));
            for (unsigned row = 0; row < rows; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[row].mCoeffs, reference[row].mCoeffs));
            consumed = input;
            LOGVOLE_REQUIRE_TRUE(lheDec(ctx, std::move(consumed), sk, consumed, &publicA, inputNtt, outputNtt, workers));
            for (unsigned row = 0; row < rows; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(consumed[row].mCoeffs, reference[row].mCoeffs));
            if (inputNtt && outputNtt)
            {
                // A caller may use the ciphertext batch as its public A too.
                std::vector<RnsPoly> aliasReference;
                LOGVOLE_REQUIRE_TRUE(lheDec(ctx, input, sk, aliasReference, &input, true, true, workers));
                consumed = input;
                LOGVOLE_REQUIRE_TRUE(lheDec(ctx, std::move(consumed), sk, consumed, &consumed, true, true, workers));
                for (unsigned row = 0; row < rows; ++row)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(consumed[row].mCoeffs, aliasReference[row].mCoeffs));
            }
            // The owning output may alias the input batch.
            LOGVOLE_REQUIRE_TRUE(lheDec(ctx, input, sk, input, &publicA, inputNtt, outputNtt, workers));
            for (unsigned row = 0; row < rows; ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(input[row].mCoeffs, reference[row].mCoeffs));
        }
    }
}

void LogVole_Cpu_DenoiseMatchesIntegerRounding(const oc::CLP&)
{
    PRNG random(toBlock(0x44454e4f, 0x495345));
    for (unsigned limbs : {1, 2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto& hostModuli = getRingHostModuli(ctx);
        LOGVOLE_REQUIRE_EQ(hostModuli.size(), static_cast<std::size_t>(limbs));
        const auto& base = *hostContext->key_context_data()->rns_tool()->base_q();
        auto pool = seal::MemoryManager::GetPool();
        constexpr std::size_t count = 9, n = 1024;
        std::vector<RnsPoly> input(count * limbs), expected(count);
        for (auto& poly : expected) resizeZero(poly.mCoeffs, n * limbs);
        for (std::size_t i = 0; i < count; ++i)
        for (std::size_t j = 0; j < limbs; ++j)
        {
            auto& poly = input[i * limbs + j];
            resizeZero(poly.mCoeffs, n * limbs);
            for (std::size_t w = 0; w < limbs; ++w)
            for (std::size_t k = 0; k < n; ++k)
            {
                const u64 q = ringModulusValue(ctx, w);
                poly.mCoeffs[w*n+k] = k == 0 ? 0 : k == 1 ? q-1 : random.get<u64>() % q;
            }
            // Independent oracle: reconstruct the full integer, then divide by
            // Q/q_j with nearest-integer rounding. This exercises the entire
            // residue range and uses neither Shoup operands nor fixed-point CRT.
            auto composed = poly.mCoeffs;
            base.compose_array(composed.data(), n, pool);
            const u64* divisor = base.punctured_prod_array() + j * limbs;
            std::vector<u64> half(limbs), value(limbs), quotient(limbs), remainder(limbs);
            seal::util::right_shift_uint(divisor, 1, limbs, half.data());
            for (std::size_t k = 0; k < n; ++k)
            {
                seal::util::add_uint(composed.data() + k*limbs, half.data(), limbs, value.data());
                seal::util::divide_uint(value.data(), divisor, limbs, quotient.data(), remainder.data(), pool);
                expected[i].mCoeffs[j*n+k] = seal::util::modulo_uint(quotient.data(), limbs, hostModuli[j]);
            }
        }
        for (u32 workers : {1, 3, 8})
        {
            std::vector<RnsPoly> actual;
            LOGVOLE_REQUIRE_TRUE(shrinkExpandDenoiseComb(ctx, input, actual, workers));
            LOGVOLE_REQUIRE_EQ(actual.size(), expected.size());
            for (std::size_t i = 0; i < count; ++i)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, expected[i].mCoeffs));
        }
        auto alias = input;
        LOGVOLE_REQUIRE_TRUE(shrinkExpandDenoiseComb(ctx, alias, alias, 3));
        for (std::size_t i = 0; i < count; ++i)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(alias[i].mCoeffs, expected[i].mCoeffs));
        std::vector<RnsPoly> moved;
        auto* originalAllocation = alias[0].mCoeffs.data();
        LOGVOLE_REQUIRE_TRUE(seedLabelAgg(std::move(alias), count, 1, params, moved));
        LOGVOLE_REQUIRE_TRUE(moved[0].mCoeffs.data() == originalAllocation);
        LOGVOLE_REQUIRE_TRUE(seedLabelAgg(std::move(moved), count, 1, params, moved));
        LOGVOLE_REQUIRE_TRUE(moved[0].mCoeffs.data() == originalAllocation);
        auto malformed = input;
        malformed[0].mCoeffs.resize(1);
        LOGVOLE_REQUIRE_TRUE(!shrinkExpandDenoiseComb(ctx, malformed, moved, 8));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(moved[0].mCoeffs, expected[0].mCoeffs));
    }
}

void LogVole_Cpu_NttMatchesReference(const oc::CLP&)
{
    PRNG random(toBlock(0x4845584c, 0x4e5454));
    struct Case { std::size_t degree; int bits; unsigned limbs; };
    const std::array<Case, 9> cases = {{{1024, 30, 2}, {1024, 49, 2},
        {1024, 50, 2}, {1024, 51, 2}, {1024, 52, 2}, {1024, 55, 2},
        {1024, 60, 2}, {8192, 55, 4}, {16384, 52, 8}}};
    for (const auto& test : cases)
    {
        RingParams params{};
        params.mPolyModulusDegree = test.degree;
        params.mCoeffModulusBits.resize(test.limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), test.bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto* tables = hostContext->key_context_data()->small_ntt_tables();
        for (unsigned limb = 0; limb < test.limbs; ++limb)
        for (unsigned inverse = 0; inverse < 2; ++inverse)
        for (unsigned trial = 0; trial < 4; ++trial)
        {
            const auto& table = tables[limb];
            const u64 q = table.modulus().value();
            const u64 bound = (inverse ? 2 : 4) * q;
            std::vector<u64> actual(test.degree);
            for (auto& value : actual) value = random.get<u64>() % bound;
            const std::array<u64, 8> edges = {0, 1, q-1, q, q+1, 2*q-1, bound-2, bound-1};
            std::copy(edges.begin(), edges.end(), actual.begin());
            auto expected = actual;
            // Invoke SEAL's original Harvey implementation directly, bypassing
            // the public NTT entry points that dispatch to HEXL when enabled.
            if (inverse)
            {
                const auto invDegree = table.inv_degree_modulo();
                table.ntt_handler().transform_from_rev(expected.data(), table.coeff_count_power(),
                    table.get_from_inv_root_powers(), &invDegree);
                seal::util::inverse_ntt_negacyclic_harvey(actual.data(), table);
            }
            else
            {
                table.ntt_handler().transform_to_rev(expected.data(), table.coeff_count_power(),
                    table.get_from_root_powers());
                seal::util::ntt_negacyclic_harvey(actual.data(), table);
            }
            for (auto& value : expected) value %= q;
            LOGVOLE_REQUIRE_TRUE(actual == expected);
        }
        RnsPoly raw{}, canonical{}, expected{};
        raw.mCoeffs.resize(test.degree*test.limbs);
        random.get(raw.mCoeffs.data(), raw.mCoeffs.size());
        canonical = raw;
        for (unsigned limb = 0; limb < test.limbs; ++limb)
            for (std::size_t i = 0; i < test.degree; ++i)
                canonical.mCoeffs[limb*test.degree+i] %= ringModulusValue(ctx, limb);
        expected = canonical;
        for (unsigned limb = 0; limb < test.limbs; ++limb)
        {
            const auto& table = tables[limb];
            table.ntt_handler().transform_to_rev(expected.mCoeffs.data()+limb*test.degree,
                table.coeff_count_power(), table.get_from_root_powers());
            for (std::size_t i = 0; i < test.degree; ++i)
                expected.mCoeffs[limb*test.degree+i] %= ringModulusValue(ctx, limb);
        }
        LOGVOLE_REQUIRE_TRUE(forwardNtt(raw, ctx));
        LOGVOLE_REQUIRE_TRUE(forwardNttCanonical(canonical, ctx));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(raw.mCoeffs, expected.mCoeffs));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(canonical.mCoeffs, expected.mCoeffs));
    }
}

void LogVole_Cpu_CrtMatchesSeal(const oc::CLP&)
{
    PRNG random(toBlock(0xA18, 0x671));
    for (unsigned limbs : {2, 4, 8})
    for (int bits : {30, 52, 55, 60})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto& base = *hostContext->key_context_data()->rns_tool()->base_q();
        for (std::size_t count : {7, 8, 9, 127, 1024})
        for (unsigned trial = 0; trial < 8; ++trial)
        {
            std::vector<u64> source(limbs * count), actual(source.size(), 12345);
            for (unsigned j = 0; j < limbs; ++j)
            for (unsigned i = 0; i < count; ++i)
            {
                const u64 q = ringModulusValue(ctx, j);
                source[j * count + i] = i < 4 ? std::array<u64,4>{0,1,q-1,q/2}[i]
                    : random.get<u64>() % q;
            }
            auto expected = source;
            base.compose_array(expected.data(), count, seal::MemoryManager::GetPool());
            const bool used = LogVole::detail::cpuComposeRns(source.data(), actual.data(), count, base);
            if (used) LOGVOLE_REQUIRE_TRUE(actual == expected);
            else LOGVOLE_REQUIRE_TRUE(std::all_of(actual.begin(), actual.end(), [](u64 v) { return v == 12345; }));
        }
    }
}

void LogVole_Cpu_CrtMixedWidthsMatchSeal(const oc::CLP&)
{
    PRNG random(toBlock(0x435254, 0x20260910));
    for (unsigned limbs : {4, 8})
    for (int topBits : {52, 55})
    {
        const std::size_t count = 1024;
        RingParams params{};
        params.mPolyModulusDegree = count;
        params.mCoeffModulusBits.resize(limbs);
        for (unsigned j = 0; j < limbs; ++j) params.mCoeffModulusBits[j] = j%2 ? topBits : 30+j;
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto& base = *hostContext->key_context_data()->rns_tool()->base_q();
        std::vector<u64> input(limbs*count), actual(input.size(), 12345);
        for (unsigned j = 0; j < limbs; ++j)
        {
            const u64 q = ringModulusValue(ctx, j);
            for (std::size_t i = 0; i < count; ++i)
                input[j*count+i] = i < 2 ? (i ? q-1 : 0) : random.get<u64>() % q;
        }
        auto expected = input;
        base.compose_array(expected.data(), count, seal::MemoryPoolHandle::ThreadLocal());
        if (LogVole::detail::cpuComposeRns(input.data(), actual.data(), count, base))
            LOGVOLE_REQUIRE_TRUE(actual == expected);
        else LOGVOLE_REQUIRE_TRUE(std::all_of(actual.begin(), actual.end(), [](u64 x) { return x == 12345; }));
    }
}

void LogVole_Cpu_WitnessMatchesSequentialReference(const oc::CLP&)
{
#if defined(__SIZEOF_INT128__)
    for (u64 width : {1, 7, 8, 9, 1031})
    for (u64 depth : {1, 3})
    for (u64 modulus : {u64{257}, u64{2251799813554177}, u64{18014398508400641}})
    {
        const block circuitSeed = toBlock(0x7472, width);
        ZkMulCircuit circuit{};
        LOGVOLE_REQUIRE_TRUE(makeZkMulCircuit(width*depth, depth, circuitSeed, circuit));
        PRNG wiring(circuitSeed);
        for (u64 g = 0; g < circuit.gateCount(); ++g)
        {
            LOGVOLE_REQUIRE_EQ(circuit.mOperands[2*g], (g/width)*width+wiring.get<u64>()%width);
            LOGVOLE_REQUIRE_EQ(circuit.mOperands[2*g+1], (g/width)*width+wiring.get<u64>()%width);
        }
        for (bool sequentialDependency : {false, true})
        {
            if (sequentialDependency)
                for (u64 g = 0; g < circuit.gateCount(); ++g)
                    circuit.mOperands[2*g] = static_cast<u32>(circuit.outputWire(g)-1);
            PRNG original(toBlock(0x7878, width));
            std::vector<u64> expected(circuit.voleCount()+13, 0);
            for (u64 i = 0; i < width; ++i) expected[i] = original.get<u64>() % modulus;
            for (u64 g = 0; g < circuit.gateCount(); ++g)
                expected[circuit.outputWire(g)] = static_cast<__uint128_t>(expected[circuit.mOperands[2*g]]) *
                    expected[circuit.mOperands[2*g+1]] % modulus;
            expected[circuit.maskIndex()] = original.get<u64>() % modulus;
            const auto next = original.get<block>();
            for (u32 workers : {1, 2, 4})
            {
                PRNG optimized(toBlock(0x7878, width));
                AlignedUnVec<u64> actual;
                LOGVOLE_REQUIRE_TRUE(zkMulWitness(circuit, modulus, optimized, actual, expected.size(), workers));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual, expected));
                LOGVOLE_REQUIRE_TRUE(optimized.get<block>() == next);
            }
        }
    }
#endif
}

void LogVole_Cpu_GpuZkSeededPreparationMatchesReference(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    struct FlagScope
    {
        const char* name;
        std::string previous;
        bool hadPrevious = false;
        FlagScope(const char* variable, const char* value) : name(variable)
        {
            if (const char* old = std::getenv(name)) { hadPrevious = true; previous = old; }
            ::tests_libOTe::logvole_test::setEnvironment(name, value, 1);
        }
        ~FlagScope()
        {
            if (hadPrevious) ::tests_libOTe::logvole_test::setEnvironment(name, previous.c_str(), 1);
            else ::tests_libOTe::logvole_test::unsetEnvironment(name);
        }
    };
    struct GpuScope
    {
        bool previous = gpu::enabled();
        ~GpuScope() { gpu::setEnabled(previous); }
    } gpuScope;
    const bool wantGpu = cmd.getOr("gpu", 0) != 0;
    gpu::setEnabled(wantGpu);
    if (wantGpu) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
    if (!gpu::enabled()) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    PRNG pairedProofRoots(sysRandomSeed());
    // Exact raw Barrett generation, including non-primes and both endpoints
    // of the supported interval. CPU SEAL is the independent oracle here.
    for (auto role : {ProtocolCacheRole::Sender, ProtocolCacheRole::Receiver})
    {
        ScopedProtocolCacheScope scope(role, allocateProtocolCacheRunId());
        if (!gpu::enabled()) continue; // explicit per-role GPU ablation
        for (u64 modulus : {2ULL, 4ULL, 257ULL, 1000ULL, 2251799813554177ULL,
                18014398508400641ULL, (1ULL << 61u) - 1u})
        {
            const seal::Modulus reference(modulus);
            gpu::HostModulus actual;
            LOGVOLE_REQUIRE_TRUE(gpu::prepareZkModulusDevice(modulus, actual));
            LOGVOLE_REQUIRE_EQ(actual.mValue, modulus);
            LOGVOLE_REQUIRE_EQ(actual.mRatio0, reference.const_ratio()[0]);
            LOGVOLE_REQUIRE_EQ(actual.mRatio1, reference.const_ratio()[1]);
            gpu::HostModulus cached;
            LOGVOLE_REQUIRE_TRUE(gpu::prepareZkModulusDevice(modulus, cached));
            LOGVOLE_REQUIRE_EQ(cached.mRatio0, actual.mRatio0);
            LOGVOLE_REQUIRE_EQ(cached.mRatio1, actual.mRatio1);
            for (u64 delta : std::array<u64, 4>{0, 1, modulus - 1u, ~u64(0)})
            for (const auto proof : {ZkProof{0, 0}, ZkProof{modulus - 1u, modulus - 1u},
                    ZkProof{~u64(0), ~u64(0)}})
            {
                const u64 expected = static_cast<u64>((static_cast<unsigned __int128>(proof.mV) * delta +
                    proof.mU % modulus) % modulus);
                bool accepted = false;
                LOGVOLE_REQUIRE_TRUE(gpu::zkAcceptDevice(proof, expected, delta, modulus, accepted));
                LOGVOLE_REQUIRE_TRUE(accepted && zkAccept(proof, expected, delta, modulus));
                LOGVOLE_REQUIRE_TRUE(gpu::zkAcceptDevice(proof, modulus, delta, modulus, accepted));
                LOGVOLE_REQUIRE_TRUE(!accepted && !zkAccept(proof, modulus, delta, modulus));
            }
        }
    }
    for (u64 invalid : {0ULL, 1ULL, 1ULL << 61u, ~0ULL})
    {
        gpu::HostModulus retained{17, 23, 31};
        bool accepted = true;
        LOGVOLE_REQUIRE_TRUE(!gpu::prepareZkModulusDevice(invalid, retained));
        LOGVOLE_REQUIRE_TRUE(retained.mValue == 17 && retained.mRatio0 == 23 && retained.mRatio1 == 31);
        LOGVOLE_REQUIRE_TRUE(!gpu::zkAcceptDevice(ZkProof{}, 0, 0, invalid, accepted));
        LOGVOLE_REQUIRE_TRUE(accepted);
    }
    for (u64 width : {1, 7, 8, 1031})
    for (u64 depth : {1, 3})
    {
        const u64 budget = width * (depth + 1) + 1;
        const block circuitSeed = toBlock(0x5647, width + depth);
        ZkMulCircuit reference, actual;
        LOGVOLE_REQUIRE_TRUE(makeZkMulCircuitForBudget(budget, depth, circuitSeed, reference));
        LOGVOLE_REQUIRE_TRUE(gpu::makeZkMulCircuitForBudgetDevice(budget, depth, circuitSeed, actual));
        LOGVOLE_REQUIRE_EQ(actual.mWidth, reference.mWidth);
        LOGVOLE_REQUIRE_EQ(actual.mDepth, reference.mDepth);
        LOGVOLE_REQUIRE_TRUE(actual.mOperands.empty());
        LOGVOLE_REQUIRE_TRUE(actual.mOperandsDevice != nullptr);
        ZkMulCircuit copied = actual;
        LOGVOLE_REQUIRE_TRUE(copied.mOperands.empty());
        LOGVOLE_REQUIRE_TRUE(copied.mOperandsDevice == actual.mOperandsDevice);
        LOGVOLE_REQUIRE_TRUE(gpu::zkMulUploadOperands(actual));
        LOGVOLE_REQUIRE_TRUE(!gpu::makeZkMulCircuitForBudgetDevice(1, depth, circuitSeed, actual));
        LOGVOLE_REQUIRE_TRUE(actual.mOperandsDevice == copied.mOperandsDevice);

        ZkMulCircuit detached = copied;
        LOGVOLE_REQUIRE_TRUE(gpu::zkMulDetachOperands(detached));
        LOGVOLE_REQUIRE_TRUE(detached.mOperands.empty());
        LOGVOLE_REQUIRE_TRUE(detached.mOperandsDevice != copied.mOperandsDevice);
        LOGVOLE_REQUIRE_TRUE(gpu::zkMulMaterializeOperands(detached));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(detached.mOperands, reference.mOperands));
        const auto detachedOwner = detached.mOperandsDevice;
        detached.mDepth = std::numeric_limits<u64>::max();
        LOGVOLE_REQUIRE_TRUE(!gpu::zkMulDetachOperands(detached));
        LOGVOLE_REQUIRE_TRUE(detached.mOperandsDevice == detachedOwner);
        LOGVOLE_REQUIRE_TRUE(rangesEqual(detached.mOperands, reference.mOperands));
        detached.mDepth = depth;

        if (width == 7 && depth == 3)
        {
            ScopedProtocolCacheScope senderScope(
                ProtocolCacheRole::Sender, allocateProtocolCacheRunId());
            // Role ablations may intentionally disable the verifier's GPU.
            if (gpu::enabled())
            for (auto setting : {CivoleSetting::GoldenSeed, CivoleSetting::NoGoldenSeed})
            {
                const u32 bits = setting == CivoleSetting::GoldenSeed ? 55 : 52;
                ZkMulProver reconfiguredProver;
                reconfiguredProver.mDeviceState = gpu::makeZkMulDeviceState(copied);
                LOGVOLE_REQUIRE_TRUE(reconfiguredProver.mDeviceState != nullptr);
                reconfiguredProver.configure(copied, bits, 1, setting, budget);
                LOGVOLE_REQUIRE_TRUE(reconfiguredProver.mDeviceState == nullptr);
                LOGVOLE_REQUIRE_TRUE(reconfiguredProver.mCircuit.mOperands.empty());
                LOGVOLE_REQUIRE_TRUE(reconfiguredProver.mCircuit.mOperandsDevice == copied.mOperandsDevice);
                ZkMulVerifier verifier;
                verifier.mUseDevice = true;
                verifier.mDeviceState = std::make_shared<int>(1);
                verifier.configure(copied, bits, 1, setting, budget);
                LOGVOLE_REQUIRE_TRUE(verifier.mDeviceState == nullptr);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperands.empty());
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice != nullptr);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice != copied.mOperandsDevice);
                const auto firstOwner = verifier.mCircuit.mOperandsDevice;

                ZkMulCircuit invalid = copied;
                invalid.mDepth += 1;
                const auto priorState = std::make_shared<int>(2);
                verifier.mDeviceState = priorState;
                bool threw = false;
                try { verifier.configure(invalid, bits, 1, setting, budget); }
                catch (const std::runtime_error&) { threw = true; }
                LOGVOLE_REQUIRE_TRUE(threw);
                LOGVOLE_REQUIRE_TRUE(verifier.mDeviceState == priorState);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice == firstOwner);

                verifier.configure(copied, bits, 1, setting, budget);
                LOGVOLE_REQUIRE_TRUE(verifier.mDeviceState == nullptr);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice != firstOwner);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice != copied.mOperandsDevice);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperands.empty());
                LOGVOLE_REQUIRE_TRUE(gpu::zkMulMaterializeOperands(verifier.mCircuit));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(verifier.mCircuit.mOperands, reference.mOperands));

                // CPU configuration retains the public API's eager host access,
                // while leaving the caller's device-only snapshot unchanged.
                ZkMulVerifier hostVerifier;
                hostVerifier.configure(copied, bits, 1, setting, budget);
                LOGVOLE_REQUIRE_TRUE(hostVerifier.mCircuit.mOperandsDevice == nullptr);
                LOGVOLE_REQUIRE_TRUE(rangesEqual(hostVerifier.mCircuit.mOperands, reference.mOperands));
                LOGVOLE_REQUIRE_TRUE(copied.mOperands.empty());

                // A public host edit supersedes an older device snapshot.
                ZkMulCircuit edited = copied;
                LOGVOLE_REQUIRE_TRUE(gpu::zkMulMaterializeOperands(edited));
                edited.mOperands[0] = (edited.mOperands[0] + 1) % width;
                verifier.configure(edited, bits, 1, setting, budget);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice == nullptr);
                LOGVOLE_REQUIRE_TRUE(rangesEqual(verifier.mCircuit.mOperands, edited.mOperands));
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperands.data() != edited.mOperands.data());

                // A circuit independently generated by this role transfers its
                // unique allocation without a D2D clone or host round trip.
                ZkMulCircuit unique;
                LOGVOLE_REQUIRE_TRUE(gpu::makeZkMulCircuitForBudgetDevice(
                    budget, depth, circuitSeed, unique));
                LOGVOLE_REQUIRE_EQ(unique.mOperandsDevice.use_count(), 1);
                const void* uniqueOwner = unique.mOperandsDevice.get();
                verifier.mDeviceState = std::make_shared<int>(3);
                verifier.configure(std::move(unique), bits, 1, setting, budget);
                LOGVOLE_REQUIRE_TRUE(unique.mOperandsDevice == nullptr);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice.get() == uniqueOwner);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperands.empty());
                LOGVOLE_REQUIRE_TRUE(verifier.mDeviceState == nullptr);
                LOGVOLE_REQUIRE_TRUE(gpu::zkMulMaterializeOperands(verifier.mCircuit));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(verifier.mCircuit.mOperands, reference.mOperands));

                ZkMulCircuit invalidUnique;
                LOGVOLE_REQUIRE_TRUE(gpu::makeZkMulCircuitForBudgetDevice(
                    budget, depth, circuitSeed, invalidUnique));
                LOGVOLE_REQUIRE_EQ(invalidUnique.mOperandsDevice.use_count(), 1);
                invalidUnique.mDepth += 1;
                threw = false;
                try { verifier.configure(std::move(invalidUnique), bits, 1, setting, budget); }
                catch (const std::runtime_error&) { threw = true; }
                LOGVOLE_REQUIRE_TRUE(threw);
                LOGVOLE_REQUIRE_TRUE(verifier.mCircuit.mOperandsDevice.get() == uniqueOwner);

                if (setting == CivoleSetting::GoldenSeed)
                {
                    // Configuration can precede a decision to run the proof
                    // on the CPU. Exercise both real protocol fallbacks before
                    // their first host access, with GPU execution disabled too.
                    ZkMulVerifier fallbackVerifier;
                    fallbackVerifier.mUseDevice = true;
                    fallbackVerifier.configure(copied, bits, 1, setting, budget);
                    LOGVOLE_REQUIRE_TRUE(fallbackVerifier.mCircuit.mOperands.empty());
                    const auto fallbackOwner = fallbackVerifier.mCircuit.mOperandsDevice;
                    ZkMulProver fallbackProver;
                    fallbackProver.mUseDevice = true;
                    fallbackProver.configure(copied, bits, 1, setting, budget);
                    LOGVOLE_REQUIRE_TRUE(fallbackProver.mCircuit.mOperands.empty());
                    const auto fallbackProverOwner = fallbackProver.mCircuit.mOperandsDevice;
                    GpuScope hostOnly;
                    gpu::setEnabled(false);
                    fallbackVerifier.mUseDevice = false;
                    fallbackProver.mUseDevice = false;
                    PRNG witnessPrng(toBlock(0x46414c4c, 1));
                    AlignedUnVec<u64> witness;
                    LOGVOLE_REQUIRE_TRUE(zkMulWitness(reference, fallbackProver.modulus(),
                        witnessPrng, witness, budget));
                    PRNG senderPrng(toBlock(0x46414c4c, 2));
                    PRNG receiverPrng(toBlock(0x46414c4c, 3));
                    auto sockets = coproto::LocalAsyncSocket::makePair();
                    auto offline = macoro::sync_wait(macoro::when_all_ready(
                        fallbackVerifier.offline(19, senderPrng, sockets[0]),
                        fallbackProver.offline(sockets[1])));
                    std::get<0>(offline).result();
                    std::get<1>(offline).result();
                    LOGVOLE_REQUIRE_TRUE(fallbackVerifier.mCircuit.mOperands.empty());
                    LOGVOLE_REQUIRE_TRUE(fallbackProver.mCircuit.mOperands.empty());
                    auto online = macoro::sync_wait(macoro::when_all_ready(
                        fallbackVerifier.verify(senderPrng, sockets[0]),
                        fallbackProver.prove(witness, receiverPrng, sockets[1])));
                    std::get<0>(online).result();
                    std::get<1>(online).result();
                    LOGVOLE_REQUIRE_TRUE(fallbackVerifier.mAccepted);
                    LOGVOLE_REQUIRE_TRUE(!fallbackVerifier.mCheckOnDevice);
                    LOGVOLE_REQUIRE_TRUE(!fallbackProver.mCheckOnDevice);
                    LOGVOLE_REQUIRE_TRUE(!fallbackVerifier.mAcceptOnDevice);
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(fallbackVerifier.mCircuit.mOperands, reference.mOperands));
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(fallbackProver.mCircuit.mOperands, reference.mOperands));
                    LOGVOLE_REQUIRE_TRUE(fallbackVerifier.mCircuit.mOperandsDevice == fallbackOwner);
                    LOGVOLE_REQUIRE_TRUE(fallbackProver.mCircuit.mOperandsDevice == fallbackProverOwner);
                    LOGVOLE_REQUIRE_TRUE(fallbackProver.mCircuit.mOperands.data() !=
                        fallbackVerifier.mCircuit.mOperands.data());
                    LOGVOLE_REQUIRE_TRUE(copied.mOperands.empty());
                    LOGVOLE_REQUIRE_TRUE(fallbackOwner != copied.mOperandsDevice);
                    ZkProof hostProof;
                    LOGVOLE_REQUIRE_TRUE(zkMulProverResponse(reference, witness, fallbackProver.mMacs,
                        fallbackProver.mLastChallenge, fallbackProver.modulus(), 1, hostProof));
                    LOGVOLE_REQUIRE_EQ(fallbackProver.mLastProof.mU, hostProof.mU);
                    LOGVOLE_REQUIRE_EQ(fallbackProver.mLastProof.mV, hostProof.mV);
                    u64 hostValue = 0;
                    LOGVOLE_REQUIRE_TRUE(zkMulVerifierValue(reference, fallbackVerifier.mKeys,
                        fallbackVerifier.mLastChallenge, 19, fallbackVerifier.modulus(), 1, hostValue));
                    LOGVOLE_REQUIRE_EQ(fallbackVerifier.mLastValue, hostValue);
                }

                bool receiverGpu = false;
                {
                    ScopedProtocolCacheScope receiverScope(
                        ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
                    receiverGpu = gpu::enabled();
                }
                if (setting == CivoleSetting::GoldenSeed && receiverGpu)
                {
                    // The protocol wrapper must use GPU acceptance by default
                    // and preserve its explicit host rollback on the same pair.
                    ZkMulVerifier gpuVerifier;
                    ZkMulProver gpuProver;
                    gpuVerifier.mUseDevice = gpuProver.mUseDevice = true;
                    gpuVerifier.configure(copied, bits, 1, setting, budget);
                    gpuProver.configure(copied, bits, 1, setting, budget);
                    // Each fixture has fresh party seeds. The host witness and
                    // its GPU token intentionally share one seed for exact parity.
                    const block witnessSeed = pairedProofRoots.get<block>();
                    PRNG witnessPrng(witnessSeed),
                        senderPrng(pairedProofRoots.get<block>()),
                        receiverPrng(pairedProofRoots.get<block>());
                    AlignedUnVec<u64> witness;
                    LOGVOLE_REQUIRE_TRUE(zkMulWitness(reference, gpuProver.modulus(), witnessPrng, witness, budget));
                    gpuProver.mWiresDevice = gpu::zkMulWitnessDevice(copied, gpuProver.modulus(), witnessSeed, budget);
                    LOGVOLE_REQUIRE_TRUE(gpuProver.mWiresDevice != nullptr);
                    auto sockets = coproto::LocalAsyncSocket::makePair();
                    auto offline = macoro::sync_wait(macoro::when_all_ready(
                        gpuVerifier.offline(19, senderPrng, sockets[0]), gpuProver.offline(sockets[1])));
                    std::get<0>(offline).result();
                    std::get<1>(offline).result();
                    for (const char* mode : {"1", "0"})
                    {
                        FlagScope acceptance("LV_GPU_ZK_ACCEPT_DEVICE", mode);
                        const bool deviceOnly = mode[0] == '0';
                        gpuVerifier.mDeviceOnlyHostSpans = deviceOnly;
                        gpuProver.mDeviceOnlyHostSpans = deviceOnly;
                        gpuProver.mVoleDeviceInput = deviceOnly;
                        if (deviceOnly)
                        {
                            // A present but undersized device handle must fail
                            // before either socket or query seed is consumed.
                            auto prior = gpuProver.mWiresDevice;
                            auto undersized = std::make_shared<gpu::DeviceScalars>();
                            LOGVOLE_REQUIRE_TRUE(undersized->resize(budget - 1u));
                            gpuProver.mWiresDevice = undersized;
                            bool rejected = false;
                            try
                            {
                                macoro::sync_wait(gpuProver.prove(
                                    std::span<u64>{}, receiverPrng, sockets[1]));
                            }
                            catch (const std::runtime_error&) { rejected = true; }
                            gpuProver.mWiresDevice = std::move(prior);
                            LOGVOLE_REQUIRE_TRUE(rejected);
                        }
                        auto online = macoro::sync_wait(macoro::when_all_ready(
                            gpuVerifier.verify(senderPrng, sockets[0]),
                            gpuProver.prove(deviceOnly ? std::span<u64>{}
                                : std::span<u64>(witness.data(), witness.size()),
                                receiverPrng, sockets[1])));
                        std::get<0>(online).result();
                        std::get<1>(online).result();
                        LOGVOLE_REQUIRE_TRUE(gpuVerifier.mAccepted);
                        LOGVOLE_REQUIRE_TRUE(gpuVerifier.mCheckOnDevice && gpuProver.mCheckOnDevice);
                        LOGVOLE_REQUIRE_EQ(gpuVerifier.mAcceptOnDevice, mode[0] == '1');
                        LOGVOLE_REQUIRE_EQ(gpuVerifier.mKeys.empty(), deviceOnly);
                        LOGVOLE_REQUIRE_EQ(gpuProver.mMacs.empty(), deviceOnly);
                        if (deviceOnly)
                        {
                            LOGVOLE_REQUIRE_EQ(gpuVerifier.mVole.outputDeviceCount(), budget);
                            LOGVOLE_REQUIRE_EQ(gpuProver.mVole.outputDeviceCount(), budget);
                            auto keysDevice = std::static_pointer_cast<gpu::DeviceScalars>(
                                gpuVerifier.mVole.outputDevice());
                            auto macsDevice = std::static_pointer_cast<gpu::DeviceScalars>(
                                gpuProver.mVole.outputDevice());
                            auto witnessDevice = std::static_pointer_cast<gpu::DeviceScalars>(
                                gpuProver.mWiresDevice);
                            LOGVOLE_REQUIRE_TRUE(keysDevice && macsDevice && witnessDevice);
                            AlignedUnVec<u64> keys, macs, downloadedWitness;
                            keys.resize(budget);
                            macs.resize(budget);
                            downloadedWitness.resize(budget);
                            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*keysDevice, keys));
                            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*macsDevice, macs));
                            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*witnessDevice, downloadedWitness));
                            witness[reference.maskIndex()] = downloadedWitness[reference.maskIndex()];
                            LOGVOLE_REQUIRE_TRUE(rangesEqual(downloadedWitness, witness));
                            const seal::Modulus modulus(gpuProver.modulus());
                            for (std::size_t i = 0; i < budget; ++i)
                                LOGVOLE_REQUIRE_EQ(macs[i], mulAddMod(witness[i], 19u, keys[i], modulus));
                            ZkProof hostProof;
                            LOGVOLE_REQUIRE_TRUE(zkMulProverResponse(reference, witness, macs,
                                gpuProver.mLastChallenge, gpuProver.modulus(), 1, hostProof));
                            LOGVOLE_REQUIRE_EQ(gpuProver.mLastProof.mU, hostProof.mU);
                            LOGVOLE_REQUIRE_EQ(gpuProver.mLastProof.mV, hostProof.mV);
                        }
                    }
                }
            }
        }
        for (u64 modulus : {257ULL, 2251799813554177ULL, 18014398508400641ULL})
        {
            const block witnessSeed = toBlock(modulus, width);
            PRNG referencePrng(witnessSeed);
            AlignedUnVec<u64> expected, fetched;
            LOGVOLE_REQUIRE_TRUE(zkMulWitness(reference, modulus, referencePrng, expected, budget + 13));
            // Exercise host-empty wiring before materializing any CPU copy.
            auto device = gpu::zkMulWitnessDevice(copied, modulus, witnessSeed, budget + 13);
            LOGVOLE_REQUIRE_TRUE(device != nullptr);
            fetched.resize(expected.size());
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, std::span<u64>(fetched.data(), fetched.size())));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(expected, fetched));
            // LV_GPU_ZK_PREPARATION=0 prepares only the input scalars on the
            // host, then evaluates the same circuit through this GPU overload.
            PRNG hostInputPrng(witnessSeed);
            AlignedUnVec<u64> hostInputs;
            hostInputs.resize(static_cast<std::size_t>(width + 1));
            for (auto& value : hostInputs) value = hostInputPrng.get<u64>() % modulus;
            LOGVOLE_REQUIRE_TRUE(hostInputPrng.get<block>() == referencePrng.get<block>());
            auto hostPrepared = gpu::zkMulWitnessDevice(reference, modulus,
                std::span<const u64>(hostInputs.data(), hostInputs.size()), budget + 13);
            LOGVOLE_REQUIRE_TRUE(hostPrepared != nullptr);
            AlignedUnVec<u64> hostPreparedWitness;
            hostPreparedWitness.resize(expected.size());
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*hostPrepared,
                std::span<u64>(hostPreparedWitness.data(), hostPreparedWitness.size())));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(expected, hostPreparedWitness));
            LOGVOLE_REQUIRE_TRUE(gpu::zkMulMaterializeOperands(actual));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mOperands, reference.mOperands));
            LOGVOLE_REQUIRE_TRUE(copied.mOperands.empty());

            PRNG labelPrng(toBlock(width, modulus));
            std::vector<u64> macs(budget), keys(budget);
            const seal::Modulus mod(modulus);
            for (u64 i = 0; i < budget; ++i)
            {
                macs[i] = labelPrng.get<u64>() % modulus;
                keys[i] = (macs[i] + modulus - mulMod(expected[i], 19, mod)) % modulus;
            }
            ZkProof referenceProof, actualProof;
            u64 referenceValue = 0, actualValue = 0;
            LOGVOLE_REQUIRE_TRUE(zkMulProverResponse(reference, expected, macs, 73, modulus, 1, referenceProof));
            LOGVOLE_REQUIRE_TRUE(zkMulProverResponse(actual, fetched, macs, 73, modulus, 4, actualProof));
            LOGVOLE_REQUIRE_TRUE(zkMulVerifierValue(reference, keys, 73, 19, modulus, 1, referenceValue));
            LOGVOLE_REQUIRE_TRUE(zkMulVerifierValue(actual, keys, 73, 19, modulus, 4, actualValue));
            LOGVOLE_REQUIRE_EQ(referenceProof.mU, actualProof.mU);
            LOGVOLE_REQUIRE_EQ(referenceProof.mV, actualProof.mV);
            LOGVOLE_REQUIRE_EQ(referenceValue, actualValue);
            LOGVOLE_REQUIRE_TRUE(zkAccept(actualProof, actualValue, 19, modulus));

            // Exercise the production GPU proof helpers in both constant/power
            // modes, rather than testing only the witness kernel.
            auto deviceMacs = gpu::uploadScalars(macs);
            auto deviceKeys = gpu::uploadScalars(keys);
            auto proverState = gpu::makeZkMulDeviceState(copied);
            auto verifierState = gpu::makeZkMulDeviceState(copied);
            LOGVOLE_REQUIRE_TRUE(deviceMacs && deviceKeys && proverState && verifierState);
            for (const char* mode : {"1", "0"})
            {
                FlagScope constants("LV_GPU_ZK_DEVICE_CONSTANTS", mode);
                ZkProof proof;
                u64 value = 0;
                LOGVOLE_REQUIRE_TRUE(gpu::zkMulProverResponseDevice(
                    copied, *device, *deviceMacs, 73, modulus, *proverState, proof));
                LOGVOLE_REQUIRE_TRUE(gpu::zkMulVerifierValueDevice(
                    copied, *deviceKeys, 73, 19, modulus, *verifierState, value));
                LOGVOLE_REQUIRE_EQ(proof.mU, referenceProof.mU);
                LOGVOLE_REQUIRE_EQ(proof.mV, referenceProof.mV);
                LOGVOLE_REQUIRE_EQ(value, referenceValue);
                bool accepted = false;
                LOGVOLE_REQUIRE_TRUE(gpu::zkAcceptDevice(proof, value, 19, modulus, accepted));
                LOGVOLE_REQUIRE_TRUE(accepted);
                proof.mU = (proof.mU + 1) % modulus;
                LOGVOLE_REQUIRE_TRUE(gpu::zkAcceptDevice(proof, value, 19, modulus, accepted));
                LOGVOLE_REQUIRE_TRUE(!accepted);
            }
        }
        LOGVOLE_REQUIRE_TRUE(gpu::zkMulMaterializeOperands(copied));
        LOGVOLE_REQUIRE_TRUE(copied.mOperands.data() != actual.mOperands.data());
        actual.mOperands[0] ^= 1;
        LOGVOLE_REQUIRE_TRUE(rangesEqual(copied.mOperands, reference.mOperands));
    }
#else
    LOGVOLE_SKIP() << "requires CUDA build";
#endif
}

void LogVole_Cpu_GpuZkMatMulSeededInputsMatchReference(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    struct GpuScope
    {
        bool previous = gpu::enabled();
        ~GpuScope() { gpu::setEnabled(previous); }
    } gpuScope;
    const bool wantGpu = cmd.getOr("gpu", 0) != 0;
    gpu::setEnabled(wantGpu);
    if (wantGpu) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
    if (!gpu::enabled()) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    const u64 largePrime = seal::PlainModulus::Batching(1024, 52).value();
    for (u64 dim : { 1u, 3u, 7u, 16u, 33u, 128u })
    for (u64 modulus : { u64{2}, u64{65537}, largePrime })
    {
        ZkMatMulStatement statement{};
        statement.mDim = dim;
        statement.mReps = 3;
        std::vector<u64> sizes{ 0, statement.voleCount(), zkVoleRequestSize(statement.voleCount()),
            statement.voleCount() + 13 };
        std::sort(sizes.begin(), sizes.end());
        sizes.erase(std::unique(sizes.begin(), sizes.end()), sizes.end());
        for (u64 requested : sizes)
        {
            const u64 count = requested ? requested : statement.voleCount();
            const block seed = toBlock(0x4d41544d554c, dim ^ modulus);
            PRNG cpuPrng(seed, 3);
            AlignedUnVec<u64> expected;
            LOGVOLE_REQUIRE_TRUE(zkMatMulWitnessInputs(statement, modulus, cpuPrng, expected, requested));

            // Independent placement oracle: exactly 2*d*d AES words populate
            // A then B; the next words are independent repetition masks.
            // The padded request consumes no additional parent randomness.
            PRNG stream(seed, 256);
            std::vector<u64> oracle(static_cast<std::size_t>(count), 0);
            for (u64 i = 0; i < 2 * dim * dim; ++i) oracle[i] = stream.get<u64>() % modulus;
            for (u32 rep = 0; rep < statement.repetitions(); ++rep)
                oracle[statement.maskIndex(rep)] = stream.get<u64>() % modulus;
            LOGVOLE_REQUIRE_TRUE(rangesEqual(expected, oracle));
            for (unsigned i = 0; i < 4; ++i)
                LOGVOLE_REQUIRE_EQ(cpuPrng.get<u64>(), stream.get<u64>());

            auto device = gpu::zkMatMulWitnessInputsDevice(statement, modulus, seed, requested);
            LOGVOLE_REQUIRE_TRUE(device != nullptr);
            LOGVOLE_REQUIRE_EQ(device->count(), count);
            AlignedUnVec<u64> fetched;
            fetched.resize(static_cast<std::size_t>(count));
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, fetched));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(fetched, oracle));

            // Keep two independently owned device results alive at once. A
            // repeated seeded call must neither reuse nor overwrite the first.
            auto replay = gpu::zkMatMulWitnessInputsDevice(statement, modulus, seed, requested);
            LOGVOLE_REQUIRE_TRUE(replay != nullptr);
            LOGVOLE_REQUIRE_TRUE(replay->data() != device->data());
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*replay, fetched));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(fetched, oracle));
            auto another = gpu::zkMatMulWitnessInputsDevice(statement, modulus, toBlock(1, dim), requested);
            LOGVOLE_REQUIRE_TRUE(another != nullptr);
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, fetched));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(fetched, oracle));

            // The existing product kernel must accept the returned placement,
            // including odd dimensions on both sides of its tile boundary.
            if (dim <= 33)
            {
                AlignedUnVec<u64> expectedProduct, actualProduct;
                LOGVOLE_REQUIRE_TRUE(zkMatMulFillProduct(statement, modulus, 1,
                    expected, expectedProduct));
                gpu::DeviceScalars product;
                LOGVOLE_REQUIRE_TRUE(gpu::zkMatMulFillProductDevice(*device, statement,
                    modulus, product));
                actualProduct.resize(statement.entries());
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(product, actualProduct));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actualProduct, expectedProduct));
                // Public product evaluation writes a separate destination;
                // neither live private witness, mask nor padding may change.
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, fetched));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(fetched, oracle));
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*replay, fetched));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(fetched, oracle));
            }
        }
    }

    ZkMatMulStatement valid{};
    valid.mDim = 7;
    const block seed = toBlock(0x494e56414c4944, 7);
    auto retained = gpu::zkMatMulWitnessInputsDevice(valid, largePrime, seed);
    LOGVOLE_REQUIRE_TRUE(retained != nullptr);
    AlignedUnVec<u64> before, after;
    before.resize(retained->count());
    after.resize(retained->count());
    LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*retained, before));
    LOGVOLE_REQUIRE_TRUE(gpu::zkMatMulWitnessInputsDevice(valid, 0, seed) == nullptr);
    LOGVOLE_REQUIRE_TRUE(gpu::zkMatMulWitnessInputsDevice(valid, 1, seed) == nullptr);
    LOGVOLE_REQUIRE_TRUE(gpu::zkMatMulWitnessInputsDevice(valid, largePrime, seed, valid.voleCount() - 1) == nullptr);
    LOGVOLE_REQUIRE_TRUE(gpu::zkMatMulWitnessInputsDevice(valid, largePrime, seed, std::numeric_limits<u64>::max()) == nullptr);
    for (u64 dim : { u64{0}, std::numeric_limits<u64>::max(),
            static_cast<u64>(std::numeric_limits<u32>::max()), u64{1} << 32 })
    {
        auto invalid = valid;
        invalid.mDim = dim;
        LOGVOLE_REQUIRE_TRUE(gpu::zkMatMulWitnessInputsDevice(invalid, largePrime, seed) == nullptr);
    }
    LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*retained, after));
    LOGVOLE_REQUIRE_TRUE(rangesEqual(before, after));
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires CUDA build";
#endif
}

void LogVole_Cpu_DyadicMatchesReference(const oc::CLP&)
{
    PRNG random(toBlock(0x398, 0x8941));
    for (unsigned bits : {52, 55})
    for (u64 gap : {1, 81919, 16777215, 16777217})
    for (std::size_t count : {7, 8, 9, 127, 1024, 65537})
    {
        const u64 q = (u64{1} << bits) - gap;
        const seal::Modulus mod(q);
        std::vector<u64> a(count+1), b(count+1), c(count+1), expected(count+1);
        random.get(a.data(), a.size());
        random.get(b.data(), b.size());
        random.get(c.data(), c.size());
        const std::array<u64, 8> edges = {0, 1, q-1, q, q+1, 2*q-1, (u64{1} << bits)-1, ~u64{0}};
        for (std::size_t i = 1; i <= count; ++i)
        {
            if (i <= 64)
            {
                a[i] = edges[(i-1) % 8];
                b[i] = edges[(i-1) / 8];
                c[i] = edges[(i+2) % 8];
            }
            // Include canonical values and all 64-bit values in the same call.
            else if (i & 1) { a[i] %= q; b[i] %= q; c[i] %= q; }
        }
        for (bool subtract : {false, true})
        for (unsigned alias = 0; alias < 3; ++alias)
        {
            auto result = alias == 0 ? c : a;
            const auto& x = alias == 0 ? a : result;
            const auto& y = alias == 2 ? result : b;
            expected = result;
            for (std::size_t i = 1; i <= count; ++i)
                expected[i] = subtract
                    ? seal::util::sub_uint_mod(result[i] % q, mulMod(x[i] % q, y[i] % q, mod), mod)
                    : mulAddMod(x[i] % q, y[i] % q, result[i] % q, mod);
            const auto original = result;
            const auto operation = subtract ? LogVole::detail::cpuDyadicMultiplySubtract
                : LogVole::detail::cpuDyadicMultiplyAdd;
            const bool used = operation(
                x.data()+1, y.data()+1, result.data()+1, count, mod);
            LOGVOLE_REQUIRE_TRUE(result == (used ? expected : original));
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
            const char* enabled = std::getenv("LV_CPU_VECTOR_DYADIC");
            LOGVOLE_REQUIRE_EQ(used, count>=8 && gap<(u64{1}<<24) &&
                (!enabled || enabled[0]!='0') && __builtin_cpu_supports("avx512f") &&
                __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512ifma"));
#endif
        }
    }
}

void LogVole_Cpu_FusedDotMatchesReference(const oc::CLP&)
{
#if !defined(__SIZEOF_INT128__)
    LOGVOLE_SKIP() << "Independent wide-product oracle requires unsigned __int128";
#else
    PRNG random(toBlock(0x444f54, 0x49464d41));
    for (int bits : {30, 52, 55, 60})
    for (u64 gap : {1ULL, 32767ULL, 16777215ULL, 16777216ULL})
    for (std::size_t terms : {1, 2, 5, 16, 32, 33})
    for (std::size_t count : {0, 1, 7, 8, 9, 127})
    {
        const u64 q = (u64{1} << bits) - gap;
        const seal::Modulus modulus(q);
        std::vector<std::vector<u64>> a(terms, std::vector<u64>(count+2)), b = a;
        std::vector<const u64*> ap(terms), bp(terms);
        std::vector<u64> c(count+2), expected;
        random.get(c.data(), c.size());
        for (std::size_t t = 0; t < terms; ++t)
        {
            random.get(a[t].data(), a[t].size());
            random.get(b[t].data(), b[t].size());
            for (std::size_t i = 0; i < count; ++i)
            {
                if (i == 0) a[t][i+1] = b[t][i+1] = q-1;
                else if (i == 1) a[t][i+1] = b[t][i+1] = ~u64{0};
                else if (i & 1) { a[t][i+1] %= q; b[t][i+1] %= q; }
            }
            ap[t] = a[t].data()+1;
            bp[t] = b[t].data()+1;
        }
        expected = c;
        for (std::size_t i = 0; i < count; ++i)
        {
            __uint128_t sum = c[i+1] % q;
            for (std::size_t t = 0; t < terms; ++t)
                sum += static_cast<__uint128_t>(ap[t][i] % q) * (bp[t][i] % q);
            expected[i+1] = static_cast<u64>(sum % q);
        }
        const auto original = c;
        const bool used = LogVole::detail::cpuDyadicInnerProduct(ap.data(), bp.data(), terms, c.data()+1, count, modulus);
        LOGVOLE_REQUIRE_TRUE(c == (used ? expected : original));
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
        const auto enabled = [](const char* name) { const char* value = std::getenv(name); return !value || value[0] != '0'; };
        const bool expectedFast = (bits == 52 || bits == 55) && gap < (u64{1} << 24) && terms >= 3 && terms <= 32 &&
            enabled("LV_CPU_FUSED_DOT") && enabled("LV_CPU_VECTOR_DYADIC") && __builtin_cpu_supports("avx512f") &&
            __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512ifma");
        LOGVOLE_REQUIRE_EQ(used, expectedFast);
#endif
    }
    for (int bits : {30, 52, 55, 60})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, {bits, bits});
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        // More than one block of 32, with generic-modulus fallback coverage.
        std::vector<RnsPoly> a(65), b(65);
        std::vector<const RnsPoly*> ap, bp;
        auto actual = sampleUniformPoly(ctx, random), expected = actual;
        for (unsigned t = 0; t < a.size(); ++t)
        {
            a[t] = sampleUniformPoly(ctx, random);
            b[t] = sampleUniformPoly(ctx, random);
            ap.push_back(&a[t]); bp.push_back(&b[t]);
            LOGVOLE_REQUIRE_TRUE(dyadicMultiplyAddNttInplace(a[t], b[t], expected, ctx));
        }
        LOGVOLE_REQUIRE_TRUE(dyadicInnerProductNttInplace(ap, bp, actual, ctx));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mCoeffs, expected.mCoeffs));
        ap[0] = &actual;
        LOGVOLE_REQUIRE_TRUE(!dyadicInnerProductNttInplace(ap, bp, actual, ctx));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mCoeffs, expected.mCoeffs));
    }
#endif
}

void LogVole_Cpu_RecursiveLeafMatchesIntegerReference(const oc::CLP&)
{
#if defined(__SIZEOF_INT128__)
    PRNG random(toBlock(0x1eaf, 0x20260910));
    for (int bits : {52, 55})
    {
        const auto moduli = seal::CoeffModulus::Create(1024, std::vector<int>(8, bits));
        for (unsigned selected = 0; selected < moduli.size(); ++selected)
        for (u64 inverse : {u64{0}, u64{1}, moduli[selected].value()-1,
                            random.get<u64>() % moduli[selected].value()})
        for (std::size_t count : {1, 7, 8, 9, 63, 1024})
        {
            const auto q = moduli[selected].value();
            std::vector<u64> input(count+1), output(count*moduli.size()+2, 0x12345678), expected=output;
            for (std::size_t i = 0; i < count; ++i)
            {
                const std::array<u64, 7> edges{0, 1, q/2-1, q/2, q/2+1, q-2, q-1};
                input[i+1] = i < edges.size() ? edges[i] : random.get<u64>() % q;
                const u64 residue = static_cast<__uint128_t>(input[i+1]) * inverse % q;
                for (std::size_t j = 0; j < moduli.size(); ++j)
                    expected[1+j*count+i] = residue > q/2 ? moduli[j].value()-(q-residue) : residue;
            }
            const bool dispatched = LogVole::detail::cpuUnliftCenteredRns(input.data()+1, output.data()+1,
                count, moduli[selected], inverse, moduli);
            if (dispatched) LOGVOLE_REQUIRE_TRUE(output == expected);
            else LOGVOLE_REQUIRE_TRUE(std::all_of(output.begin(), output.end(), [](u64 x) { return x == 0x12345678; }));
            for (u64 value : {q, q+1, ~u64{0}})
            {
                const auto before = output;
                input[count] = value;
                LOGVOLE_REQUIRE_FALSE(LogVole::detail::cpuUnliftCenteredRns(input.data()+1,
                    output.data()+1, count, moduli[selected], inverse, moduli));
                LOGVOLE_REQUIRE_TRUE(output == before);
            }
        }
        std::array<u64, 8> input{}, output;
        output.fill(0x12345678);
        const std::array<seal::Modulus, 1> small{seal::Modulus(257)};
        LOGVOLE_REQUIRE_TRUE(!LogVole::detail::cpuUnliftCenteredRns(input.data(), output.data(), 8, moduli[0], 1, small));
        LOGVOLE_REQUIRE_TRUE(!LogVole::detail::cpuUnliftCenteredRns(input.data(), output.data(), 8, small[0], 1, small));
        LOGVOLE_REQUIRE_TRUE(std::all_of(output.begin(), output.end(), [](u64 x) { return x == 0x12345678; }));

        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(8);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), bits);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        std::vector<RnsPoly> raw(2), canonical(2);
        for (unsigned leaf = 0; leaf < 2; ++leaf)
        {
            raw[leaf].mCoeffs.resize(8192);
            random.get(raw[leaf].mCoeffs.data(), raw[leaf].mCoeffs.size());
            canonical[leaf] = raw[leaf];
            for (std::size_t i = 0; i < 8192; ++i)
                canonical[leaf].mCoeffs[i] %= ringModulusValue(ctx, i/1024);
        }
        DigestTree actual{}, expected{};
        LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(ctx, raw, 1, 4*bits, bits-1, actual, 2, true));
        LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(ctx, canonical, 1, 4*bits, bits-1, expected, 2, true));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mDigest.mCoeffs, expected.mDigest.mCoeffs));
    }
#endif
}

void LogVole_Cpu_ErrorSamplingMatchesSeal(const oc::CLP&)
{
    for (unsigned limbs : {2, 4, 8})
    for (double deviation : {0.0, 3.2, 64.0})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), limbs == 4 ? 55 : 52);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        PRNG random(toBlock(0x6677, limbs));
        RnsPoly actual{};
        actual.mCoeffs.resize(1024*limbs);
        random.get(actual.mCoeffs.data(), actual.mCoeffs.size());
        auto expected = actual;
        PRNG original(toBlock(0x9abc, limbs)), optimized(toBlock(0x9abc, limbs));
        seal::prng_seed_type seed{};
        original.get(seed.data(), seed.size());
        auto generator = seal::UniformRandomGeneratorFactory::DefaultFactory()->create(seed);
        seal::RandomToStandardAdapter engine(generator);
        seal::util::ClippedNormalDistribution distribution(0, deviation, 6*deviation);
        for (std::size_t i = 0; i < 1024; ++i)
        {
            const i64 noise = static_cast<i64>(distribution(engine));
            for (unsigned j = 0; j < limbs; ++j)
            {
                const u64 q = ringModulusValue(ctx, j);
                const u64 addend = noise < 0 ? q-static_cast<u64>(-noise) : static_cast<u64>(noise);
                expected.mCoeffs[j*1024+i] = (expected.mCoeffs[j*1024+i] % q + addend) % q;
            }
        }
        LOGVOLE_REQUIRE_TRUE(addPolyError(actual, deviation, 6*deviation, optimized, ctx));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mCoeffs, expected.mCoeffs));
        std::array<u64, 16> before{}, after{};
        original.get(before.data(), before.size());
        optimized.get(after.data(), after.size());
        LOGVOLE_REQUIRE_TRUE(before == after);
    }
    // Custom clipping bounds can exceed a ring modulus. The error-NTT
    // shortcut must then preserve the general normalization path.
    for (bool wideNoise : {false, true})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, {30, 30});
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        PRNG inputPrng(toBlock(0x57494445, 0x4e4f4953));
        std::vector<RnsPoly> inputs{sampleUniformPoly(ctx, inputPrng), sampleUniformPoly(ctx, inputPrng)};
        const double deviation = wideNoise ? double(ringModulusValue(ctx, 0))*0.75 : 3.2;
        PRNG actualPrng(toBlock(123,456)), expectedPrng(toBlock(123,456));
        std::vector<RnsPoly> expected(2);
        bool noncanonical = false;
        for (auto& poly : expected)
        {
            resizeZero(poly.mCoeffs, 2048);
            LOGVOLE_REQUIRE_TRUE(addPolyError(poly, deviation, 4*deviation, expectedPrng, ctx));
            for (std::size_t i = 0; i < poly.mCoeffs.size(); ++i)
                noncanonical |= poly.mCoeffs[i] >= ringModulusValue(ctx, i/1024);
            LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));
        }
        LOGVOLE_REQUIRE_EQ(noncanonical, wideNoise);
        LencEncodeOutput actual{};
        LOGVOLE_REQUIRE_TRUE(lencEncTrunc(ctx, inputs, 1, 30, 29, actualPrng, actual,
            deviation, 4*deviation, 2, false, false));
        LOGVOLE_REQUIRE_EQ(actual.mRNtt.size(), expected.size());
        for (unsigned i = 0; i < 2; ++i)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mRNtt[i].mCoeffs, expected[i].mCoeffs));
    }
}

void LogVole_Cpu_ResamplingOverwritesPreviousQuery(const oc::CLP&)
{
    PRNG random(toBlock(0x52455341, 0x4d504c45));
    std::vector<RnsPoly> actual;
    for (unsigned limbs : {2, 4, 8, 2})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        params.mCoeffModulusBits.resize(limbs);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
            limbs == 4 ? 55 : 52);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        auto digest = sampleUniformPoly(ctx, random);
        std::array<u8, 16> seed{};
        random.get(seed.data(), seed.size());
        u64 sid = 17, instance = 2;
        for (unsigned query = 0; query < 12; ++query)
        {
            switch (query % 4)
            {
            case 0: seed[query % seed.size()] ^= 0x80; break;
            case 1: ++sid; break;
            case 2: ++instance; break;
            case 3: digest.mCoeffs[query] ^= 1; break;
            }
            const u32 mu = query < 6 ? 3 : 5;
            const auto previous = actual;
            const auto ct2Seed = deriveSeedInstanceBlock(seed, sid, digest, instance, mu);
            LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, mu, seed, sid, digest, instance, actual));
            LOGVOLE_REQUIRE_EQ(actual.size(), mu);
            for (u32 i = 0; i < mu; ++i)
            {
                // A fresh single-polynomial draw defines the expected stream;
                // reused buffers must not retain a prior query or index.
                const auto expected = deriveUniformPolyFromSeed(ctx, ct2Seed, 0xC720AA55u, i);
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, expected.mCoeffs));
            }
            if (previous.size() == actual.size())
                LOGVOLE_REQUIRE_FALSE(rangesEqual(previous[0].mCoeffs, actual[0].mCoeffs));
        }
        const auto previous = actual;
        LOGVOLE_REQUIRE_FALSE(buildHashedCt2(ctx, 0, seed, sid, digest, instance, actual));
        LOGVOLE_REQUIRE_EQ(actual.size(), previous.size());
        LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[0].mCoeffs, previous[0].mCoeffs));

        for (unsigned query = 0; query < 4; ++query)
        {
            std::array<block, 3> seeds{};
            random.get(seeds.data(), seeds.size());
            LOGVOLE_REQUIRE_TRUE(deriveUniformPolyBatchFromSeedListInplace(ctx, seeds, 77, 2, actual));
            for (unsigned i = 0; i < 6; ++i)
            {
                const auto expected = deriveUniformPolyFromSeed(ctx, seeds[i/2], 77, i%2);
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, expected.mCoeffs));
            }
        }
        deriveUniformPolyBatchFromSeedInplace(ctx, ZeroBlock, 77, 0, actual);
        LOGVOLE_REQUIRE_TRUE(actual.empty());
    }
}

void LogVole_Cpu_SamplerMatchesSeal(const oc::CLP&)
{
    PRNG random(toBlock(0x739182, 0x193));
    auto fast = LogVole::detail::cpuBlake2xbFactory();
    seal::Blake2xbPRNGFactory reference;
    bool exercisedRejection = false;
    for (unsigned trial = 0; trial < 32; ++trial)
    {
        seal::prng_seed_type seed{};
        random.get(seed.data(), seed.size());
        auto a = fast->create(seed);
        auto b = reference.create(seed);
        LOGVOLE_REQUIRE_TRUE(a->info().type_ == b->info().type_);
        for (std::size_t size : {0, 1, 7, 64, 4095, 4096, 4097, 65539, 3})
        {
            std::vector<seal::seal_byte> actual(size), expected(size);
            a->generate(size, actual.data());
            b->generate(size, expected.data());
            LOGVOLE_REQUIRE_TRUE(actual == expected);
        }
        a->refresh();
        b->refresh();
        std::array<seal::seal_byte, 8199> actual{}, expected{};
        a->generate(actual.size(), actual.data());
        b->generate(expected.size(), expected.data());
        LOGVOLE_REQUIRE_TRUE(actual == expected);

        // Include the production 52/55-bit ring fields and smaller/larger ones.
        for (int bits : {30, 52, 55, 60})
        {
            RingParams params{};
            params.mPolyModulusDegree = 1024;
            assignValues<int>(params.mCoeffModulusBits, {bits, bits});
            RingNttContext ctx{};
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
            std::vector<u64> ap(2048), bp(2048);
            const auto hostContext = getRingHostContext(ctx);
            LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
            const auto& parms = hostContext->key_context_data()->parms();
            LogVole::detail::cpuSamplePolyUniform(fast->create(seed), parms, ap.data());
            seal::util::sample_poly_uniform(reference.create(seed), parms, bp.data());
            LOGVOLE_REQUIRE_TRUE(ap == bp);
        }
        // Use a modulus away from a power of two to force rejection (~1/64
        // of draws), including replacement draws across PRNG refill boundaries.
        // Sampling itself does not require an NTT prime or a SEALContext.
        const u64 q = (u64{3} << 58) + 123;
        seal::EncryptionParameters parms(seal::scheme_type::ckks);
        parms.set_poly_modulus_degree(1024);
        parms.set_coeff_modulus({seal::Modulus(q)});
        std::vector<u64> ap(1024), bp(1024), raw(1024);
        reference.create(seed)->generate(raw.size() * sizeof(u64),
            reinterpret_cast<seal::seal_byte*>(raw.data()));
        const u64 limit = ~u64{0} - (~u64{0} % q) - 1;
        exercisedRejection |= std::any_of(raw.begin(), raw.end(), [limit](u64 v) { return v >= limit; });
        LogVole::detail::cpuSamplePolyUniform(fast->create(seed), parms, ap.data());
        seal::util::sample_poly_uniform(reference.create(seed), parms, bp.data());
        LOGVOLE_REQUIRE_TRUE(ap == bp);
    }
    LOGVOLE_REQUIRE_TRUE(exercisedRejection);

    // Force rare rejections in the vector-supported rings, then several
    // replacement rejections across a refill. Also compare the next PRNG bytes.
    class ScriptedGenerator final : public seal::UniformRandomGenerator
    {
    public:
        ScriptedGenerator() : UniformRandomGenerator({}) {}
    private:
        seal::prng_type type() const noexcept override { return seal::prng_type::unknown; }
        void refill_buffer() override
        {
            for (std::size_t i = 0; i < buffer_size_ / sizeof(u64); ++i, ++mIndex)
            {
                const u64 value = (mIndex < 2048 ? mIndex % 32 == 31 : mIndex < 2560 || mIndex % 2 == 0)
                    ? ~u64{0} : mIndex;
                std::memcpy(buffer_begin_ + i * sizeof(u64), &value, sizeof(value));
            }
        }
        u64 mIndex = 0;
    };
    for (int bits : {52, 55})
    {
        seal::EncryptionParameters parms(seal::scheme_type::ckks);
        parms.set_poly_modulus_degree(1024);
        parms.set_coeff_modulus(seal::CoeffModulus::Create(1024, {bits, bits}));
        auto a = std::make_shared<ScriptedGenerator>(), b = std::make_shared<ScriptedGenerator>();
        std::vector<u64> actual(2048), expected(2048);
        LogVole::detail::cpuSamplePolyUniform(a, parms, actual.data());
        seal::util::sample_poly_uniform(b, parms, expected.data());
        LOGVOLE_REQUIRE_TRUE(actual == expected);
        std::array<seal::seal_byte, 4099> nextA{}, nextB{};
        a->generate(nextA.size(), nextA.data());
        b->generate(nextB.size(), nextB.data());
        LOGVOLE_REQUIRE_TRUE(nextA == nextB);
    }
}

void LogVole_Cpu_ZkArithmeticMatchesReference(const oc::CLP&)
{
    PRNG random(toBlock(0x738, 0x514));
    const std::array<u64, 9> moduli = {257, (u64{1} << 50) + 27,
        (u64{1} << 51) - 1, (u64{1} << 51) - 16777215,
        2251799813554177ULL, 18014398508400641ULL,
        (u64{1} << 54) - 1, (u64{1} << 54) - 16777215,
        (u64{1} << 54) - 16777217};
    for (u64 q : moduli)
    {
        const seal::Modulus mod(q);
        LogVole::detail::withCpuZkArithmetic(mod, [&](const auto& arithmetic) {
            const std::array<u64, 7> edges = {0, 1, 2, q/2, q-1, q, ~u64{0}};
            for (u64 a : edges) for (u64 b : edges)
                LOGVOLE_REQUIRE_EQ(arithmetic.multiply(a, b), mulMod(a, b, mod));
            for (unsigned i = 0; i < 100000; ++i)
            {
                const u64 a = random.get<u64>() % q;
                const u64 b = random.get<u64>() % q;
                const u64 c = random.get<u64>() % q;
                LOGVOLE_REQUIRE_EQ(arithmetic.multiplyAdd(a, b, c), mulAddMod(a, b, c, mod));
            }
        });
    }
}

void LogVole_Cpu_ZkVectorMatchesReference(const oc::CLP&)
{
#if !defined(__SIZEOF_INT128__)
    LOGVOLE_SKIP() << "Independent wide-division oracle requires unsigned __int128";
#else
    PRNG random(toBlock(0x5a4b5645, 0x43544f52));
    for (int bits : {30, 51, 54, 60})
    for (u64 gap : {1ULL, 32767ULL, 16777215ULL, 16777216ULL})
    for (std::size_t count : {0, 1, 7, 8, 9, 15, 17, 1024})
    {
        const u64 q = (u64{1} << bits) - gap;
        const seal::Modulus mod(q);
        const auto multiply = [q](u64 a, u64 b) {
            return static_cast<u64>((static_cast<__uint128_t>(a) * b) % q);
        };
        std::vector<u64> wires(1026), labels(1026), outputs(count + 2);
        std::vector<u32> operands(2 * count + 2);
        random.get(wires.data(), wires.size());
        random.get(labels.data(), labels.size());
        random.get(outputs.data(), outputs.size());
        const std::array<u64, 8> edges = {0, 1, q-1, q, q+1, 2*q-1, 2*q, ~u64{0}};
        for (std::size_t i = 0; i < edges.size(); ++i)
        {
            wires[i+1] = edges[i];
            labels[i+1] = edges[edges.size()-i-1];
            if (i < count) outputs[i+1] = edges[i];
        }
        for (std::size_t i = 0; i < 2 * count; ++i)
            operands[i+1] = i < 16 ? (i/2 + (i%2)*3) % 8 : random.get<u32>() % 1024;
        for (u64 chi : {u64{0}, u64{1}, q-1, ~u64{0}, random.get<u64>()})
        for (u64 delta : {u64{0}, u64{1}, q-1, ~u64{0}})
        {
            const u64 firstPower = random.get<u64>();
            std::array<u64, 2> expected{0, 0}, actual{123, 456};
            u64 verifier = 0, actualVerifier = 789, power = firstPower % q;
            for (std::size_t i = 0; i < count; ++i)
            {
                const u32 x = operands[2*i+1]+1, y = operands[2*i+2]+1;
                const u64 a0 = multiply(labels[x], labels[y]);
                const u64 a1 = (outputs[i+1] % q + 2*q - multiply(wires[x], labels[y])
                    - multiply(wires[y], labels[x])) % q;
                const u64 b = (a0 + multiply(delta, outputs[i+1])) % q;
                expected[0] = (expected[0] + multiply(power, a0)) % q;
                expected[1] = (expected[1] + multiply(power, a1)) % q;
                verifier = (verifier + multiply(power, b)) % q;
                power = multiply(power, chi);
            }
            const bool used = LogVole::detail::cpuZkProverRange(operands.data()+1, wires.data()+1,
                labels.data()+1, outputs.data()+1, count, firstPower, chi, mod, actual);
            LOGVOLE_REQUIRE_EQ(LogVole::detail::cpuZkVerifierRange(operands.data()+1, labels.data()+1,
                outputs.data()+1, count, firstPower, chi, delta, mod, actualVerifier), used);
            const std::array<u64, 2> original{123, 456};
            LOGVOLE_REQUIRE_TRUE(actual == (used ? expected : original));
            LOGVOLE_REQUIRE_EQ(actualVerifier, used ? verifier : u64{789});
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
            const char* enabled = std::getenv("LV_CPU_VECTOR_ZK");
            const char* pseudo = std::getenv("LV_CPU_ZK_PSEUDO_REDUCE");
            const bool expectedFast = (bits == 51 || bits == 54) && gap < (u64{1} << 24) && count >= 8 &&
                (!enabled || enabled[0] != '0') && (!pseudo || pseudo[0] != '0') &&
                __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512dq") &&
                __builtin_cpu_supports("avx512ifma");
            LOGVOLE_REQUIRE_EQ(used, expectedFast);
#endif
        }
    }
#endif
}

void LogVole_Cpu_ZkProofMatchesReference(const oc::CLP&)
{
    PRNG random(toBlock(0x819, 0x514));
    for (u64 q : {257ULL, 2251799813554177ULL, 18014398508400641ULL})
    for (u64 budget : {3ULL, 83ULL, 4096ULL})
    {
        const seal::Modulus mod(q);
        ZkMulCircuit circuit;
        LOGVOLE_REQUIRE_TRUE(makeZkMulCircuitForBudget(budget, budget == 3 ? 1 : 7, random.get<block>(), circuit));
        AlignedUnVec<u64> wires;
        LOGVOLE_REQUIRE_TRUE(zkMulWitness(circuit, q, random, wires));
        std::vector<u64> macs(circuit.voleCount()), keys(circuit.voleCount());
        const u64 delta = 19;
        for (std::size_t i = 0; i < macs.size(); ++i)
        {
            macs[i] = random.get<u64>() % q;
            keys[i] = (macs[i] + q - mulMod(wires[i], delta, mod)) % q;
        }
        for (u64 chi : {u64{0}, u64{1}, u64{73}, ~u64{0}})
        {
            ZkProof reference{};
            u64 bReference = 0, pw = chi % q;
            for (u64 g = 0; g < circuit.gateCount(); ++g)
            {
                const u64 x = circuit.mOperands[2*g], y = circuit.mOperands[2*g+1];
                const u64 z = circuit.outputWire(g);
                const u64 a0 = mulMod(macs[x], macs[y], mod);
                const u64 a1 = (macs[z] + 2*q - mulMod(wires[x], macs[y], mod)
                    - mulMod(wires[y], macs[x], mod)) % q;
                const u64 b = mulAddMod(keys[z], delta, mulMod(keys[x], keys[y], mod), mod);
                reference.mU = mulAddMod(pw, a0, reference.mU, mod);
                reference.mV = mulAddMod(pw, a1, reference.mV, mod);
                bReference = mulAddMod(pw, b, bReference, mod);
                pw = mulMod(pw, chi, mod);
            }
            reference.mU = addMod(reference.mU, macs[circuit.maskIndex()], mod);
            reference.mV = (reference.mV + q - wires[circuit.maskIndex()]) % q;
            bReference = addMod(bReference, keys[circuit.maskIndex()], mod);
            for (u32 threads : {1, 2, 3, 4, 8, 12, 16})
            {
                ZkProof proof;
                u64 b = 0;
                LOGVOLE_REQUIRE_TRUE(zkMulProverResponse(circuit, wires, macs, chi, q, threads, proof));
                LOGVOLE_REQUIRE_TRUE(zkMulVerifierValue(circuit, keys, chi, delta, q, threads, b));
                LOGVOLE_REQUIRE_EQ(proof.mU, reference.mU);
                LOGVOLE_REQUIRE_EQ(proof.mV, reference.mV);
                LOGVOLE_REQUIRE_EQ(b, bReference);
                LOGVOLE_REQUIRE_TRUE(zkAccept(proof, b, delta, q));
                proof.mU = (proof.mU + 1) % q;
                LOGVOLE_REQUIRE_TRUE(!zkAccept(proof, b, delta, q));
            }
        }
    }
}

void LogVole_Cpu_GadgetDigitWidths(const oc::CLP&)
{
    for (int bits : {52, 55})
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, {bits, bits, bits, bits, bits, bits, bits, bits});
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0x325, 0x786, 1);
        for (u32 digitBits : {31, 63, 64, 65, 110, 128, 208, 256, 416})
        for (bool centered : {false, true})
        {
            const u32 levels = (8 * bits + digitBits - 1) / digitBits + 1;
            std::vector<RnsPoly> digits;
            LOGVOLE_REQUIRE_TRUE(centered
                ? gadgetDecomposeBitsRangeCentered(poly, digitBits, 0, levels, ctx, digits)
                : gadgetDecomposeBitsRange(poly, digitBits, 0, levels, ctx, digits));
            RnsPoly actual;
            LOGVOLE_REQUIRE_TRUE(gadgetRecomposeBits(digits, digitBits, ctx, actual));
            LOGVOLE_REQUIRE_TRUE(std::equal(poly.mCoeffs.begin(), poly.mCoeffs.end(), actual.mCoeffs.begin()));
        }
    }
}
