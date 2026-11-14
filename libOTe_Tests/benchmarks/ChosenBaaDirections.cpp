#include "libOTe/Tools/BlkAccCode/ChosenBaaCode.h"
#include "libOTe/Tools/BlkAccCode/ReedMullerBaaCode.h"
#include "libOTe/Tools/BlkAccCode/SmallAlphabetBaaCode.h"
#include <chrono>
#include <iostream>
#include <algorithm>
using namespace osuCrypto;

template<typename Code>
void run(const char* name, u64 n, u64 seed, unsigned iterations)
{
    Code code;
    auto t0 = std::chrono::steady_clock::now();
    code.config(n, block(125, seed));
    const double setup = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    AlignedUnVector<block> message(n / 2), original(n), output(n), scratch(n), transpose(n), expected(n);
    PRNG random(block(126, seed));
    random.get(message.data(), message.size()); random.get(original.data(), n);
    std::vector<double> forwardTimes, transposeTimes;
    code.encode(message, expected, scratch);
    block check = ZeroBlock;
    for (unsigned iteration = 0; iteration < iterations + 2; ++iteration)
    {
        const auto start = std::chrono::steady_clock::now();
        code.encode(message, output, scratch);
        const auto elapsed = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        if (iteration >= 2) forwardTimes.push_back(elapsed);
        check ^= output[iteration % n];
    }
    if (!std::equal(output.begin(), output.end(), expected.begin())) throw std::runtime_error("forward changed");
    for (unsigned iteration = 0; iteration < iterations + 2; ++iteration)
    {
        std::copy(original.begin(), original.end(), transpose.begin());
        const auto start = std::chrono::steady_clock::now();
        code.dualEncode(transpose, scratch);
        const auto elapsed = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        if (iteration >= 2) transposeTimes.push_back(elapsed);
        check ^= transpose[iteration % (n / 2)];
    }
    block lhs = ZeroBlock, rhs = ZeroBlock;
    for (u64 i = 0; i < n; ++i) lhs ^= original[i].gf128Mul(output[i]);
    for (u64 i = 0; i < n / 2; ++i) rhs ^= message[i].gf128Mul(transpose[i]);
    if (lhs != rhs) throw std::runtime_error("transpose identity failed");
    std::sort(forwardTimes.begin(), forwardTimes.end()); std::sort(transposeTimes.begin(), transposeTimes.end());
    std::cout << name << ',' << n / 2 << ',' << n << ',' << seed << ',' << setup << ','
              << forwardTimes[iterations / 2] << ',' << transposeTimes[iterations / 2] << ',' << check << std::endl;
}
int main(int argc, char** argv)
{
    const u64 n = argc > 1 ? std::stoull(argv[1]) : (1u << 21);
    const unsigned iterations = argc > 2 ? std::stoul(argv[2]) : 15;
    const u64 seed = argc > 3 ? std::stoull(argv[3]) : 1;
    if (!iterations || !n || n % 32 || n > std::numeric_limits<u32>::max()) throw std::invalid_argument("benchmark arguments");
    std::cout << "code,k,n,seed,setup_ms,forward_ms,transpose_ms,checksum\n";
    run<ReedMullerBaaCode<>>("gf128_rm", n, seed, iterations);
    run<SmallAlphabetBaaCode<>>("gf128_q256", n, seed, iterations);
    run<ChosenBaaCode<8>>("gf128_rs", n, seed, iterations);
}
