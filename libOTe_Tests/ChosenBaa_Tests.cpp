#include "libOTe/Tools/BlkAccCode/ChosenBaaCode.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/TestCollection.h"
#include "Common.h"
#include <algorithm>

using namespace osuCrypto;

namespace
{
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
    for (auto type : {MultType::ChosenBaa16x8, MultType::ChosenBaa16x4})
    {
        const u64 rate = type == MultType::ChosenBaa16x8 ? 2 : 4;
        for (u64 n : {1, 7, 8, 9, 511, 512, 1023, 1024, 1048576})
        {
            auto config = syndromeDecodingConfigure(128, n, type,
                SdNoiseDistribution::Regular, {1.0});
            if (config.mNoiseVectorSize % 16 ||
                config.mNoiseVectorSize / rate < n ||
                config.mNoiseVectorSize < config.mNumPartitions * config.mSizePer ||
                config.mNumPartitions != 200)
                throw RTE_LOC;
        }
        bool rejected = false;
        try { syndromeDecodingConfigure(128, u64(1) << 31, type,
            SdNoiseDistribution::Regular, {1.0}); }
        catch (const std::invalid_argument&) { rejected = true; }
        if (!rejected) throw RTE_LOC;
    }
    for (u64 n : {16, 32, 48, 256, 1040})
    {
        checkCode<4>(n);
        checkCode<8>(n);
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
