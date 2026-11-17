// Full-width modular reduction oracle. See this directory's README.md for CMake/CTest.
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuPseudo52.cuh"
#include <cstdio>
#include <cstdlib>
#include <vector>
using namespace osuCrypto::LogVole::gpu;
void check(cudaError_t e)
{
    if (e != cudaSuccess) { std::fprintf(stderr, "%s\n", cudaGetErrorString(e)); std::exit(2); }
}
__global__ void reduce(const Wide* input, u64* a, u64* b, u64 q, u64 n)
{
    for (u64 i = blockIdx.x * blockDim.x + threadIdx.x; i < n;
         i += static_cast<u64>(gridDim.x) * blockDim.x)
    {
        a[i] = reducePseudo52FullWide<false>(input[i], q);
        b[i] = reducePseudo52FullWide<true>(input[i], q);
    }
}
u64 next(u64& s)
{
    s += 0x9e3779b97f4a7c15ULL;
    u64 z = s;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}
int main()
{
    constexpr u64 n = 1u << 20u, radix = u64{1} << 52u;
    std::vector<Wide> input(n);
    std::vector<u64> a(n), b(n);
    Wide* din; u64 *da, *db;
    check(cudaMalloc(&din, n * sizeof(Wide)));
    check(cudaMalloc(&da, n * sizeof(u64))); check(cudaMalloc(&db, n * sizeof(u64)));
    u64 state = 0x52f01d, total = 0;
    for (u32 round = 0u; round < 32u; ++round)
    {
        const u64 c = round == 0u ? 1u : round == 1u ? (u64{1} << 24u) - 1u :
            1u + next(state) % ((u64{1} << 24u) - 1u);
        const u64 q = radix - c;
        for (u64 i = 0u; i < n; ++i)
        {
            input[i] = Wide{next(state), next(state)};
            if (i < 65536u)
            {
                const u64 x = i & 255u, y = (i >> 8u) & 255u;
                input[i] = Wide{(x & 1u) ? ~u64{0} - (x >> 1u) : x >> 1u,
                                (y & 1u) ? ~u64{0} - (y >> 1u) : y >> 1u};
            }
            else if (i < 131072u)
            {
                const unsigned __int128 q2 = static_cast<unsigned __int128>(q) * q;
                const unsigned __int128 value = q2 * (i % 7u) + (i & 1u ? i % 257u : -static_cast<unsigned __int128>(i % 257u));
                input[i] = Wide{static_cast<u64>(value), static_cast<u64>(value >> 64u)};
            }
        }
        check(cudaMemcpy(din, input.data(), n * sizeof(Wide), cudaMemcpyHostToDevice));
        reduce<<<1056, 256>>>(din, da, db, q, n);
        check(cudaGetLastError());
        check(cudaMemcpy(a.data(), da, n * sizeof(u64), cudaMemcpyDeviceToHost));
        check(cudaMemcpy(b.data(), db, n * sizeof(u64), cudaMemcpyDeviceToHost));
        for (u64 i = 0u; i < n; ++i)
        {
            const unsigned __int128 value = (static_cast<unsigned __int128>(input[i].mHi) << 64u) | input[i].mLo;
            const u64 expected = static_cast<u64>(value % q);
            if (a[i] != expected || b[i] != expected)
            {
                std::fprintf(stderr, "FAIL c=%llu index=%llu\n", (unsigned long long)c, (unsigned long long)i);
                return 1;
            }
        }
        total += 2u * n;
    }
    check(cudaFree(din)); check(cudaFree(da)); check(cudaFree(db));
    std::printf("Pseudo52 full-width exact: %llu reductions, 32 moduli, full unsigned-128 inputs passed\n",
        (unsigned long long)total);
}
