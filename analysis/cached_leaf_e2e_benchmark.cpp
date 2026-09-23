// Full reusable DMPF expansion, both parties on one thread over local sockets.
// Correlations are supplied by a trusted test fixture, outside all timers.
#include "libOTe/Dpf/WaterfallDmpf.h"
#include "libOTe/Dpf/RevCuckooDmpf.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
using namespace osuCrypto;
using Clock = std::chrono::steady_clock;

template<typename Protocol>
void setBase(std::array<Protocol, 2>& dpf, PRNG& prng)
{
    const std::array counts{dpf[0].baseOtCount(), dpf[1].baseOtCount()};
    if (counts[0].mRecvCount != counts[1].mSendCount ||
        counts[1].mRecvCount != counts[0].mSendCount) throw RTE_LOC;
    std::array<std::vector<std::array<block, 2>>, 2> send;
    std::array<std::vector<block>, 2> recv;
    std::array<BitVector, 2> choice;
    for (u64 p = 0; p < 2; ++p)
    {
        send[p].resize(counts[p].mSendCount);
        recv[p].resize(counts[p].mRecvCount);
        choice[p].resize(counts[p].mRecvCount);
        prng.get(send[p].data(), send[p].size());
        choice[p].randomize(prng);
    }
    for (u64 p = 0; p < 2; ++p)
        for (u64 i = 0; i < recv[p].size(); ++i)
            recv[p][i] = send[p ^ 1][i][choice[p][i]];
    for (u64 p = 0; p < 2; ++p)
        dpf[p].setBaseOts(send[p], recv[p], choice[p]);
}

double elapsed(Clock::time_point start)
{
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

template<typename Protocol>
void run(const std::string& profile, const std::string& label, u64 logN, auto init)
{
    const u64 n = 1ull << logN;
    constexpr u64 t = 16;
    constexpr u64 rounds = 18; // Three warmups, fifteen measured calls.
    PRNG data(block(789, 456)), coins0(block(456, 987)), coins1(block(654, 123));
    PRNG base(block(345, 876));
    std::array<Protocol, 2> dpf;
    for (u64 p = 0; p < 2; ++p) init(dpf[p], p, n);
    setBase(dpf, base);
    Matrix<u64> points0(1, t), points1(1, t);
    std::array<u64, t> points;
    for (u64 i = 0; i < t; ++i)
    {
        points[i] = (i * 65537 + 137) % n;
        points0(i) = data.get<u64>() & (2 * n - 1);
        points1(i) = points0(i) ^ points[i];
    }
    auto socks = coproto::LocalAsyncSocket::makePair();
    const auto startSetup = Clock::now();
    auto setup = macoro::sync_wait(macoro::when_all_ready(
        dpf[0].setPoints(points0, coins0, socks[0]),
        dpf[1].setPoints(points1, coins1, socks[1])));
    std::get<0>(setup).result();
    std::get<1>(setup).result();
    const auto setupMs = elapsed(startSetup);
    if constexpr (requires { dpf[0].mOverflow; })
        for (u64 i = 0; i < t; ++i)
            if (dpf[0].mOverflow[i] ^ dpf[1].mOverflow[i])
                throw std::runtime_error("Waterfall fixture overflow");
    std::array<std::vector<u64>, 2> output{std::vector<u64>(n), std::vector<u64>(n)};
    std::vector<u64> expected(n), values0(t), values1(t);
    std::vector<double> times;
    u64 bytes = 0;
    for (u64 round = 0; round < rounds; ++round)
    {
        std::fill(expected.begin(), expected.end(), 0);
        for (u64 i = 0; i < t; ++i)
        {
            values0[i] = data.get<u64>();
            values1[i] = data.get<u64>();
            expected[points[i]] += values0[i] + values1[i];
        }
        const auto before = socks[0].bytesSent() + socks[1].bytesSent();
        const auto start = Clock::now();
        auto result = macoro::sync_wait(macoro::when_all_ready(
            dpf[0].expand(values0, coins0, socks[0],
                [&](u64, u64 x, u64 value) { output[0][x] = value; }, CoeffCtxInteger{}),
            dpf[1].expand(values1, coins1, socks[1],
                [&](u64, u64 x, u64 value) { output[1][x] = value; }, CoeffCtxInteger{})));
        std::get<0>(result).result();
        std::get<1>(result).result();
        const auto ms = elapsed(start);
        const auto currentBytes = socks[0].bytesSent() + socks[1].bytesSent() - before;
        if (round >= 3)
        {
            times.push_back(ms);
            if (bytes && bytes != currentBytes) throw std::runtime_error("Changing expansion byte count");
            bytes = currentBytes;
        }
        for (u64 x = 0; x < n; ++x)
            if (output[0][x] + output[1][x] != expected[x])
                throw std::runtime_error("Incorrect output");
    }
    std::sort(times.begin(), times.end());
    std::cout << label << ',' << profile << ',' << logN << ','
        << std::fixed << std::setprecision(4) << setupMs << ','
        << times[times.size()/2] << ',' << times.front() << ',' << times.back()
        << ',' << bytes << ",checked" << std::endl;
}
#ifndef DMPF_BENCHMARK_NO_MAIN
int main(int argc, char** argv)
{
    try
    {
        const std::string profile = argc > 1 ? argv[1] : "waterfall4";
        const std::string label = argc > 2 ? argv[2] : "current";
        const u64 logN = argc > 3 ? std::stoul(argv[3]) : 20;
        if (logN < 4 || logN > 24) throw std::runtime_error("logN out of benchmark range");
        if (profile == "rev3")
            run<RevCuckooDmpf<u64>>(profile, label, logN,
                [](auto& p, u64 party, u64 n) { p.init(party, 16, 1, n, 3, 40, 40, false); });
        else if (profile == "waterfall4" || profile == "waterfall3")
            run<WaterfallDmpf<u64>>(profile, label, logN,
                [&](auto& p, u64 party, u64 n) { p.init(party, 16, 1, n,
                    profile == "waterfall4" ? WaterfallConfig::compact4N() :
                    WaterfallConfig::compact3N(), false); });
        else throw std::runtime_error("Unknown profile");
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << std::endl;
        return 1;
    }
}
#endif
