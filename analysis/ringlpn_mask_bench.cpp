// Run benchmarks sequentially. From out/build/rev-width-slack-min in WSL:
// c++ -std=c++20 -DNDEBUG -O2 -maes -mavx2 -mpclmul -pthread \
//   -I. -I../../.. -IcryptoTools -I../../../cryptoTools -Icoproto \
//   -I../../coproto -Imacoro -I../../macoro -I../../install/linux/include \
//   ../../../analysis/ringlpn_mask_bench.cpp -o ringlpn_mask_bench \
//   libOTe/liblibOTe.a cryptoTools/cryptoTools/libcryptoTools.a \
//   coproto/coproto/libcoproto.a macoro/macoro/libmacoro.a
// ./ringlpn_mask_bench 20
#include "libOTe/Triple/RingLpn/RingLpnTriple.h"
#include "libOTe/Tools/Field/Goldilocks.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include <algorithm>
#include <chrono>
#include <iostream>

using namespace osuCrypto;
using F = Goldilocks;
using Ring = RingLpnTriple<F>;
using Clock = std::chrono::steady_clock;

// Local benchmark fixture, not a protocol for generating correlations.
void setBase(std::array<Ring, 2>& rings, PRNG& prng)
{
    auto c0 = rings[0].baseCorCount();
    auto c1 = rings[1].baseCorCount();
    if (c0.mSendOtCount != c1.mRecvOtCount ||
        c1.mSendOtCount != c0.mRecvOtCount ||
        c0.mCoeffCount != c1.mCoeffCount || c0.mOleCount != c1.mOleCount)
        throw std::runtime_error("Base count mismatch");
    std::array<std::vector<std::array<block, 2>>, 2> send;
    std::array<std::vector<block>, 2> recv, mult, add;
    std::array<BitVector, 2> choice;
    send[0].resize(c0.mSendOtCount);
    send[1].resize(c1.mSendOtCount);
    for (u64 p = 0; p < 2; ++p)
    {
        prng.get(send[p].data(), send[p].size());
        recv[p ^ 1].resize(send[p].size());
        choice[p ^ 1].resize(send[p].size());
        choice[p ^ 1].randomize(prng);
        for (u64 i = 0; i < send[p].size(); ++i)
            recv[p ^ 1][i] = send[p][i][choice[p ^ 1][i]];
        mult[p].resize(c0.mOleCount / 128);
        add[p].resize(c0.mOleCount / 128);
        prng.get(mult[p].data(), mult[p].size());
    }
    prng.get(add[0].data(), add[0].size());
    for (u64 i = 0; i < add[1].size(); ++i)
        add[1][i] = (mult[0][i] & mult[1][i]) ^ add[0][i];
    std::array<std::vector<F>, 2> coeff, tensor;
    for (u64 p = 0; p < 2; ++p)
    {
        coeff[p].resize(c0.mCoeffCount);
        tensor[p].resize(c0.mCoeffCount * c0.mCoeffCount);
        for (auto& v : coeff[p]) v = prng.get();
    }
    for (u64 i = 0; i < c0.mCoeffCount; ++i)
        for (u64 j = 0; j < c0.mCoeffCount; ++j)
        {
            auto k = i * c0.mCoeffCount + j;
            tensor[0][k] = prng.get();
            tensor[1][k] = coeff[0][i] * coeff[1][j] - tensor[0][k];
        }
    for (u64 p = 0; p < 2; ++p)
        rings[p].setBaseCors(send[p], recv[p], choice[p], mult[p], add[p], coeff[p], tensor[p]);
}

double milliseconds(Clock::time_point start)
{
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

double median(std::vector<double> v)
{
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

int main(int argc, char** argv)
{
    try
    {
        const u64 logN = argc > 1 ? std::stoul(argv[1]) : 20;
        const u64 n = 1ull << logN;
        constexpr u64 rounds = 5;
        std::cout << "Goldilocks P=4 t=16 N=2^" << logN
                  << " RevCuckoo; one thread, both parties sequentially scheduled\n" << std::flush;
        std::array<Ring, 2> rings;
        for (u64 p = 0; p < 2; ++p)
        {
            rings[p].mNumPolys = 4;
            rings[p].mPolyWeight = 16;
            rings[p].init(p, n, Ring::Mode::Ole, Ring::DpfType::RevCuckooDmpf,
                          Ring::TensorBaseCorType::Precomputed);
        }
        PRNG prng0(block(2424523452345, 111124521521455324));
        PRNG prng1(block(6474567454546, 567546754674345444));
        PRNG basePrng(block(12345, 67890));
        auto socks = coproto::LocalAsyncSocket::makePair();
        std::vector<F> a(n), b(n), c0(n), c1(n);
        std::vector<double> expandTimes, maskTimes;
        for (u64 round = 0; round <= rounds; ++round)
        {
            setBase(rings, basePrng);
            auto start = Clock::now();
            auto result = macoro::sync_wait(macoro::when_all_ready(
                rings[0].expand(a, c0, prng0, socks[0]),
                rings[1].expand(b, c1, prng1, socks[1])));
            std::get<0>(result).result();
            std::get<1>(result).result();
            double elapsed = milliseconds(start);
            for (u64 i = 0; i < n; ++i)
                if (a[i] * b[i] != c0[i] + c1[i])
                    throw std::runtime_error("Incorrect OLE correlation");
            std::cout << (round ? "repeat " : "first/setup ") << round
                      << " expand_ms=" << elapsed << " checked\n" << std::flush;
            if (round) expandTimes.push_back(elapsed);
        }
        // Time both parties' existing sampleA helper, with storage already allocated.
        // This includes all P^2 pointwise products, not merely PRG output.
        for (u64 round = 0; round <= rounds; ++round)
        {
            auto seed = block(93483, round);
            auto start = Clock::now();
            rings[0].sampleA(seed);
            rings[1].sampleA(seed);
            double elapsed = milliseconds(start);
            if (round) maskTimes.push_back(elapsed);
            std::cout << "mask_pair " << round << " ms=" << elapsed << '\n';
        }
        std::cout << "MEDIAN pair_expand_ms=" << median(expandTimes)
                  << " pair_mask_ms=" << median(maskTimes)
                  << " mask_fraction=" << median(maskTimes) / median(expandTimes) << '\n';
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
