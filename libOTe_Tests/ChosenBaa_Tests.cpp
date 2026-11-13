#include "libOTe/Tools/BlkAccCode/ChosenBaaVole.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/TestCollection.h"
#include "Common.h"
#include "libOTe/Tools/Field/Goldilocks.h"
#include <algorithm>

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
