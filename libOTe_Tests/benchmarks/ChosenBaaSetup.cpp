#include "libOTe/Tools/BlkAccCode/ChosenBAA30.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

using namespace osuCrypto;
using Clock = std::chrono::steady_clock;

// Isolate encoder code generation from the surrounding benchmark loops.
OC_NOINLINE void forward(const ChosenBAA30<>& code, span<const block> message,
    span<block> output, span<block> scratch)
{
    code.encode(message, output, scratch);
}
OC_NOINLINE void transposed(const ChosenBAA30<>& code, span<block> input, span<block> scratch)
{
    code.dualEncode(input, scratch);
}
OC_NOINLINE void setup(ChosenBAA30<>& code, u64 n, block seed)
{
    code.config(n, seed);
}

double elapsed(Clock::time_point start)
{
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

double median(std::vector<double>& times)
{
    std::sort(times.begin(), times.end());
    return times[times.size() / 2];
}

int main(int argc, char** argv)
{
    const u64 n = argc > 1 ? std::stoull(argv[1]) : 2823424;
    const unsigned seed = argc > 2 ? std::stoul(argv[2]) : 1;
    if (!n || n % 16 || n > (u64{1} << 24))
        throw std::invalid_argument("Codeword length must be a multiple of 16 in [16, 2^24].");
    constexpr unsigned samples = 11, warmups = 2;
    ChosenBAA30<> code;
    AlignedUnVector<block> message(n / 2), original(n), output(n), scratch(n), transpose(n);
    PRNG random(block(126, seed));
    random.get(message.data(), message.size());
    random.get(original.data(), original.size());
    std::vector<double> setupTimes, forwardTimes, transposeTimes;

    for (unsigned i = 0; i < samples + warmups; ++i)
    {
        const auto start = Clock::now();
        setup(code, n, block(125, seed * 100 + i));
        const auto ms = elapsed(start);
        if (i >= warmups) setupTimes.push_back(ms);
    }
    u64 metadata = 0;
    for (unsigned stage = 0; stage < 2; ++stage)
        for (u64 i = 0; i < n; ++i)
            metadata = metadata * 0x9e3779b97f4a7c15ull + code.metadata(stage, i);

    for (unsigned i = 0; i < samples + warmups; ++i)
    {
        const auto start = Clock::now();
        forward(code, message, output, scratch);
        const auto ms = elapsed(start);
        if (i >= warmups) forwardTimes.push_back(ms);
    }
    for (unsigned i = 0; i < samples + warmups; ++i)
    {
        std::copy(original.begin(), original.end(), transpose.begin());
        const auto start = Clock::now();
        transposed(code, transpose, scratch);
        const auto ms = elapsed(start);
        if (i >= warmups) transposeTimes.push_back(ms);
    }
    block lhs = ZeroBlock, rhs = ZeroBlock;
    for (u64 i = 0; i < n; ++i) lhs ^= original[i].gf128Mul(output[i]);
    for (u64 i = 0; i < n / 2; ++i) rhs ^= message[i].gf128Mul(transpose[i]);
    if (lhs != rhs) throw std::runtime_error("transpose identity failed");

    std::printf("n=%llu seed=%u setup=%.6f forward=%.6f transpose=%.6f "
        "metadata=%016llx output=%016llx/%016llx\n",
        static_cast<unsigned long long>(n), seed,
        median(setupTimes), median(forwardTimes), median(transposeTimes),
        static_cast<unsigned long long>(metadata),
        static_cast<unsigned long long>(output[0].get<u64>(0)),
        static_cast<unsigned long long>(transpose[0].get<u64>(0)));
}
