#include "libOTe/Tools/BlkAccCode/ChosenBaaVole.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/TestCollection.h"
#include "Common.h"
#include "libOTe/Tools/Field/Goldilocks.h"
#include "libOTe/Tools/BlkAccCode/ReedMullerBaaCode.h"
#include "libOTe/Tools/BlkAccCode/SmallAlphabetBaaCode.h"
#include <algorithm>
#include <bit>

using namespace osuCrypto;

namespace
{
    struct RepeatedPoints : ChosenBaaField<Goldilocks>
    {
        static Goldilocks point(u64) { return Goldilocks(1); }
    };
    template<u64 K>
    void checkPrimeField(u64 n)
    {
        using F = Goldilocks;
        using Field = ChosenBaaField<F>;
        ChosenBaaCode<K, F> code;
        code.config(n, block(901, n));
        PRNG random(block(902, n));
        std::array<F, K> polynomial;
        for (auto& x : polynomial) x = F(random.get());
        std::array<F, 16> evaluated;
        for (u64 i = 0; i < 16; ++i)
        {
            F value(0);
            for (u64 j = K; j-- > 0;) value = value * Field::point(i) + polynomial[j];
            evaluated[i] = value;
        }
        for (u64 col = 0; col < 16 - K; ++col)
        {
            F value(0);
            for (u64 row = 0; row < K; ++row) value += evaluated[row] * code.matrix(row, col);
            if (value != evaluated[K + col]) throw RTE_LOC;
        }
        AlignedUnVector<F> x(n), y(n), z(n), message(code.outputSize()), forward(n), next(n), weights(n);
        for (auto* v : {&x, &y, &message}) for (auto& value : *v) value = F(random.get());
        const auto original = x, originalY = y;
        const F alpha(random.get());
        for (u64 i = 0; i < n; ++i) z[i] = x[i] + alpha * y[i];
        code.dualEncode2(x,y);
        code.dualEncode(z);
        auto separate = originalY;
        code.dualEncode(separate);
        for (u64 i = 0; i < code.outputSize(); ++i)
            if (z[i] != x[i] + alpha * y[i] || y[i] != separate[i]) throw RTE_LOC;
        for (u64 i = 0; i < n / 16; ++i)
        {
            for (u64 j = 0; j < K; ++j) forward[16*i+j] = message[K*i+j];
            for (u64 col = 0; col < 16-K; ++col)
            {
                F value(0);
                for (u64 row = 0; row < K; ++row) value += message[K*i+row] * code.matrix(row,col);
                forward[16*i+K+col] = value;
            }
        }
        for (u64 stage = 0; stage < 2; ++stage)
        {
            PRNG prng(code.weightSeed(stage));
            // Independent scalar sampler: uniform field elements, rejecting zero.
            for (auto& w : weights) do { w = F(prng.get()); } while (w == F(0));
            F sum(0);
            for (u64 i = n; i-- > 0;)
                next[i] = sum += forward[code.permutationIndex(stage,i)] * weights[i];
            std::swap(next,forward);
        }
        F lhs(0),rhs(0);
        AlignedUnVector<F> optimized(n), workspace(n);
        code.encode(message, optimized, workspace);
        if (!std::equal(optimized.begin(), optimized.end(), forward.begin())) throw RTE_LOC;
        optimized = original;
        code.dualEncode(optimized, workspace);
        for (u64 i = 0; i < code.outputSize(); ++i) if (optimized[i] != x[i]) throw RTE_LOC;
        for (u64 i = 0; i < message.size(); ++i) lhs += message[i] * x[i];
        for (u64 i = 0; i < n; ++i) rhs += original[i] * forward[i];
        if (lhs != rhs) throw RTE_LOC;
    }
    template<u64 K>
    void checkCode(u64 n)
    {
        PRNG prng(block(42, n));
        ChosenBaaCode<K> code;
        code.config(n, prng.get<block>());
        std::array<block, K> polynomial;
        std::array<block, 16> evaluations;
        prng.get(polynomial.data(), polynomial.size());
        for (u64 point = 0; point < 16; ++point)
        {
            block value = ZeroBlock;
            for (u64 degree = K; degree-- > 0;)
                value = value.gf128Mul(block(0, point + 1)) ^ polynomial[degree];
            evaluations[point] = value;
        }
        for (u64 col = 0; col < 16 - K; ++col)
        {
            block value = ZeroBlock;
            for (u64 row = 0; row < K; ++row)
                value ^= evaluations[row].gf128Mul(code.matrix(row, col));
            if (value != evaluations[K + col]) throw RTE_LOC;
        }
        for (u64 stage = 0; stage < 2; ++stage)
        {
            std::vector<bool> seen(n);
            for (u64 i = 0; i < n; ++i)
            {
                auto j = code.permutationIndex(stage, i);
                if (j >= n || seen[j]) throw RTE_LOC;
                seen[j] = true;
            }
        }

        AlignedUnVector<block> x(n), y(n), scaled(n), message(code.outputSize());
        prng.get(x.data(), n);
        prng.get(y.data(), n);
        prng.get(message.data(), message.size());
        const auto originalX = x, originalY = y;
        const auto alpha = prng.get<block>();
        for (u64 i = 0; i < n; ++i)
            scaled[i] = x[i] ^ y[i].gf128Mul(alpha);
        code.dualEncode2(x, y);
        code.dualEncode(scaled);
        for (u64 i = 0; i < message.size(); ++i)
            if (scaled[i] != (x[i] ^ y[i].gf128Mul(alpha))) throw RTE_LOC;

        // Independent forward traversal: local RS expansion followed by
        // gather/weight/suffix-sum, in the opposite order to the transpose.
        AlignedUnVector<block> forward(n), next(n), weights(n);
        for (u64 i = 0; i < n / 16; ++i)
        {
            for (u64 row = 0; row < K; ++row)
                forward[16 * i + row] = message[K * i + row];
            for (u64 col = 0; col < 16 - K; ++col)
            {
                block sum = ZeroBlock;
                for (u64 row = 0; row < K; ++row)
                    sum ^= message[K * i + row].gf128Mul(code.matrix(row, col));
                forward[16 * i + K + col] = sum;
            }
        }
        for (u64 stage = 0; stage < 2; ++stage)
        {
            PRNG random(code.weightSeed(stage));
            random.get(weights.data(), weights.size());
            if (std::find(weights.begin(), weights.end(), ZeroBlock) != weights.end())
                throw RTE_LOC; // Fixed test seeds have no rejection draws.
            block sum = ZeroBlock;
            for (u64 j = n; j-- > 0;)
            {
                sum ^= forward[code.permutationIndex(stage, j)].gf128Mul(weights[j]);
                next[j] = sum;
            }
            std::swap(forward, next);
        }
        block lhs = ZeroBlock, rhs = ZeroBlock;
        AlignedUnVector<block> optimized(n), workspace(n);
        code.encode(message, optimized, workspace);
        if (!std::equal(optimized.begin(), optimized.end(), forward.begin())) throw RTE_LOC;
        optimized = originalX;
        code.dualEncode(optimized, workspace);
        for (u64 i = 0; i < code.outputSize(); ++i) if (optimized[i] != x[i]) throw RTE_LOC;
        for (u64 i = 0; i < message.size(); ++i)
            lhs ^= message[i].gf128Mul(x[i]);
        for (u64 i = 0; i < n; ++i)
            rhs ^= forward[i].gf128Mul(originalX[i]);
        if (lhs != rhs) throw RTE_LOC;

        auto separate = originalY;
        code.dualEncode(separate);
        for (u64 i = 0; i < message.size(); ++i)
            if (separate[i] != y[i]) throw RTE_LOC;
    }

    template<typename F>
    void checkSmall(u64 n)
    {
        using Field = ChosenBaaField<F>;
        SmallAlphabetBaaCode<F> code;
        code.config(n, block(210, n));
        PRNG random(block(211, n));
        AlignedUnVector<F> message(n / 2), input(n), forward(n), scalar(n), next(n), scratch(n);
        for (auto* v : {&message, &input}) for (auto& x : *v) x = F(random.get());
        for (u64 b = 0; b < n / 16; ++b)
        {
            for (u64 j = 0; j < 8; ++j) scalar[b * 16 + j] = message[b * 8 + j];
            for (u64 col = 0; col < 8; ++col)
            {
                F sum = Field::zero();
                for (u64 row = 0; row < 8; ++row)
                    sum = Field::add(sum, Field::mul(message[b * 8 + row], code.matrix(row, col)));
                scalar[b * 16 + 8 + col] = sum;
            }
        }
        for (unsigned stage = 0; stage < 2; ++stage)
        {
            F sum = Field::zero(); std::vector<bool> seen(n);
            for (u64 i = 0; i < n; ++i)
            {
                const auto meta = code.metadata(stage, i), p = meta & ((1u << 24) - 1);
                if (p >= n || seen[p]) throw RTE_LOC;
                seen[p] = true;
                next[i] = sum = Field::add(scalar[p], Field::mul(sum, Field::point(meta >> 24)));
            }
            std::swap(scalar, next);
        }
        code.encode(message, forward, scratch);
        if (!std::equal(scalar.begin(), scalar.end(), forward.begin())) throw RTE_LOC;
        F lhs = Field::zero(), rhs = Field::zero();
        for (u64 i = 0; i < n; ++i) lhs = Field::add(lhs, Field::mul(input[i], forward[i]));
        code.dualEncode(input, scratch);
        for (u64 i = 0; i < n / 2; ++i) rhs = Field::add(rhs, Field::mul(message[i], input[i]));
        if (lhs != rhs) throw RTE_LOC;
    }
    void checkRm(u64 n)
    {
        ReedMullerBaaCode<> code;
        code.config(n, block(109, n));
        PRNG random(block(110, n));
        AlignedUnVector<block> message(n / 2), input(n), forward(n), scalar(n), next(n), scratch(n);
        random.get(message.data(), message.size()); random.get(input.data(), n);
        // Independent evaluation of all degree <= 2 Boolean monomials.
        for (u64 b = 0; b < n / 32; ++b)
        for (unsigned point = 0; point < 32; ++point)
        {
            auto value = ZeroBlock;
            unsigned row = 0;
            for (unsigned mask = 0; mask < 32; ++mask)
                if (std::popcount(mask) <= 2)
                {
                    if ((point & mask) == mask) value ^= message[b * 16 + row];
                    ++row;
                }
            scalar[b * 32 + point] = value;
        }
        for (unsigned stage = 0; stage < 2; ++stage)
        {
            block sum = ZeroBlock;
            std::vector<bool> seen(n);
            for (u64 i = 0; i < n; ++i)
            {
                const auto p = code.permutationIndex(stage, i);
                if (p >= n || seen[p]) throw RTE_LOC;
                seen[p] = true;
                next[i] = sum ^= scalar[p];
            }
            std::swap(scalar, next);
        }
        code.encode(message, forward, scratch);
        if (!std::equal(scalar.begin(), scalar.end(), forward.begin())) throw RTE_LOC;
        block lhs = ZeroBlock, rhs = ZeroBlock;
        for (u64 i = 0; i < n; ++i) lhs ^= input[i].gf128Mul(forward[i]);
        code.dualEncode(input, scratch);
        for (u64 i = 0; i < n / 2; ++i) rhs ^= message[i].gf128Mul(input[i]);
        if (lhs != rhs) throw RTE_LOC;
    }
    task<> badOpening(Socket& socket)
    {
        std::array<u8, 32> invalidCommitment{};
        std::array<u8, 16> contribution{};
        co_await socket.send(invalidCommitment);
        co_await socket.recv(contribution);
        co_await socket.send(contribution);
    }
}

void ChosenBaa_Code_test(const CLP&)
{
    for (u64 bit = 0; bit < 128; ++bit)
    for (u32 c = 1; c <= 256; ++c)
    {
        const block x = bit < 64 ? block(0, u64{1} << bit) : block(u64{1} << (bit - 64), 0);
        if (SmallBaaArithmetic<block>::madd(x, c, ZeroBlock) != x.gf128Mul(block(0, c))) throw RTE_LOC;
    }
    for (u64 n : {16, 32, 48, 256, 1040, 262144})
    {
        checkSmall<block>(n);
        if (n < 262144) checkSmall<Goldilocks>(n);
    }
    for (u64 n : {32, 64, 96, 256, 1056, 262144}) checkRm(n);
    // Exhaust the binary constituent: this verifies the exact RM weight
    // enumerator used by the finite distance calculation, not just distance 8.
    std::array<u64, 33> spectrum{};
    std::array<block, 16> rmInput;
    std::array<block, 32> rmOutput;
    for (u64 word = 0; word < (1u << 16); ++word)
    {
        for (unsigned j = 0; j < 16; ++j) rmInput[j] = block(0, (word >> j) & 1);
        ReedMullerBaaCode<>::localEncode(rmInput.data(), rmOutput.data());
        u64 weight = 0; for (auto x : rmOutput) weight += (x != ZeroBlock);
        ++spectrum[weight];
    }
    std::array<u64, 33> expected{};
    expected[0] = expected[32] = 1; expected[8] = expected[24] = 620;
    expected[12] = expected[20] = 13888; expected[16] = 36518;
    if (spectrum != expected) throw RTE_LOC;
    bool repeatedRejected = false;
    try { ChosenBaaCode<8, Goldilocks, RepeatedPoints> code; code.config(16, ZeroBlock); }
    catch (const std::invalid_argument&) { repeatedRejected = true; }
    if (!repeatedRejected) throw RTE_LOC;
    for (auto type : {MultType::ChosenBaa16x8, MultType::ChosenBaa16x4})
    {
        const u64 rate = type == MultType::ChosenBaa16x8 ? 2 : 4;
        for (auto noise : {SdNoiseDistribution::Regular, SdNoiseDistribution::Stationary})
        for (u64 n : {1, 7, 8, 9, 511, 512, 1023, 1024, 1048576})
        {
            auto config = syndromeDecodingConfigure(128, n, type,
                noise, {1.0});
            if (config.mNoiseVectorSize % 16 ||
                config.mNoiseVectorSize / rate < n ||
                config.mNoiseVectorSize < config.mNumPartitions * config.mSizePer ||
                config.mNumPartitions != (rate == 2 ? 128 : 64))
                throw RTE_LOC;
        }
        // A lower attack floor exposes the distinct distance terms. Check
        // both noise distributions; stationary coefficients include zero.
        for (auto noise : {SdNoiseDistribution::Regular, SdNoiseDistribution::Stationary})
        {
            const auto config = syndromeDecodingConfigure(40, 4096, type, noise, {1.0});
            const u64 expected = type == MultType::ChosenBaa16x8 ? 128 : 56;
            if (config.mNumPartitions != expected) throw RTE_LOC;
            // Odd targets round the quarter-rate floor up before batching.
            for (u64 security : {129, 256})
            {
                const auto scaled = syndromeDecodingConfigure(security, 4096, type, noise, {1.0});
                const u64 floor = rate == 2 ? security : security / 2 + security % 2;
                if (scaled.mNumPartitions != roundUpTo(floor, u64{8})) throw RTE_LOC;
            }
        }
        bool rejected = false;
        try { syndromeDecodingConfigure(128, u64(1) << 31, type,
            SdNoiseDistribution::Regular, {1.0}); }
        catch (const std::invalid_argument&) { rejected = true; }
        if (!rejected) throw RTE_LOC;
    }
    if (getRegNoiseWeight(0.60, 4096, 40, SdNoiseDistribution::Stationary,
        SdNoiseSecurityModel::binary()) != 56)
        throw RTE_LOC;
    for (double distance : {0.60, std::numeric_limits<double>::quiet_NaN(), 1e-300})
    {
        bool rejected = false;
        try { getRegNoiseWeight(distance, 4096, 128, SdNoiseDistribution::Regular,
            SdNoiseSecurityModel::binary()); }
        catch (const std::invalid_argument&) { rejected = true; }
        if (!rejected) throw RTE_LOC;
    }
    for (u64 n : {16, 32, 48, 256, 1040})
    {
        checkCode<4>(n);
        checkCode<8>(n);
        checkPrimeField<4>(n);
        checkPrimeField<8>(n);
    }
#ifdef OC_ENABLE_SSE2
    // Cover both sides of the prefetch dispatch threshold and a non-power-of-two
    // length. The forward/transpose check also exercises the bounded hint tail.
    for (u64 n : {(u64{1} << 18) - 16, u64{1} << 18, (u64{1} << 18) + 16})
    {
        checkCode<4>(n);
        checkCode<8>(n);
    }
#endif
    for (u64 n : {u64(0), u64(17), u64(1) << 32})
    {
        bool rejected = false;
        try { ChosenBaaCode<8> code; code.config(n, ZeroBlock); }
        catch (const std::invalid_argument&) { rejected = true; }
        if (!rejected) throw RTE_LOC;
    }
}

void ChosenBaa_Seed_test(const CLP&)
{
    PRNG sender(block(1, 2)), receiver(block(3, 4));
    block a = ZeroBlock, b = OneBlock, previous = ZeroBlock;
    for (u64 trial = 0; trial < 3; ++trial)
    {
        auto sockets = cp::LocalAsyncSocket::makePair();
        auto send = chosenBaaSeed(true, sender, sockets[0], a);
        auto recv = chosenBaaSeed(false, receiver, sockets[1], b);
        tests_libOTe::eval(send, recv);
        if (a != b || a == previous) throw RTE_LOC;
        previous = a;
    }
    auto sockets = cp::LocalAsyncSocket::makePair();
    auto send = badOpening(sockets[0]);
    auto recv = chosenBaaSeed(false, receiver, sockets[1], b);
    bool rejected = false;
    try { tests_libOTe::eval(send, recv); }
    catch (const std::runtime_error&) { rejected = true; }
    if (!rejected) throw RTE_LOC;
}
