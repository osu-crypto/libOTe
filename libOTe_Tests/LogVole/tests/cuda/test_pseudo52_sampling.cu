// Sampling residue/rejection oracle. See this directory's README.md for CMake/CTest.
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuPseudo52.cuh"
#include <cstdio>
#include <cstdlib>
#include <vector>
using namespace osuCrypto::LogVole::gpu;
void check(cudaError_t e)
{
    if (e != cudaSuccess) { std::fprintf(stderr, "%s\n", cudaGetErrorString(e)); std::exit(2); }
}
u64 next(u64& state)
{
    state += 0x9e3779b97f4a7c15ULL;
    u64 z = state;
    z = (z ^ (z >> 30u)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27u)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31u);
}
__global__ void reduceWords(const u64* x, const u64* thresholds,
    SamplePseudo52Word* a, SamplePseudo52Word* b, u64 q, u32 c, u64 n)
{
    for (u64 i = blockIdx.x * blockDim.x + threadIdx.x; i < n;
         i += static_cast<u64>(gridDim.x) * blockDim.x)
    {
        a[i] = samplePseudo52ReduceWord<false>(x[i], q, c, thresholds[i]);
        b[i] = samplePseudo52ReduceWord<true>(x[i], q, c, thresholds[i]);
    }
}
int main()
{
    constexpr u64 n = 1u << 20u, radix = u64{1} << 52u;
    std::vector<u64> x(n), thresholds(n);
    std::vector<SamplePseudo52Word> a(n), b(n);
    u64 *dx, *dt;
    SamplePseudo52Word *da, *db;
    check(cudaMalloc(&dx, n * sizeof(u64))); check(cudaMalloc(&dt, n * sizeof(u64)));
    check(cudaMalloc(&da, n * sizeof(SamplePseudo52Word)));
    check(cudaMalloc(&db, n * sizeof(SamplePseudo52Word)));
    u64 state = 0x52a11ce, total = 0u;
    for (u32 round = 0u; round < 32u; ++round)
    {
        const u32 c = round == 0u ? 1u : round == 1u ? (1u << 24u) - 1u :
            1u + static_cast<u32>(next(state) % ((1u << 24u) - 1u));
        const u64 q = radix - c;
        // Independent CPU expression matching SEAL, not the fused predicate.
        const u64 standard = ~u64{0} - (~u64{0} % q) - 1u;
        const u64 choices[] = {standard, standard - 1u, standard + 1u,
                              0u, 1u, q - 1u, q / 2u, ~u64{0}};
        for (u64 i = 0u; i < n; ++i)
        {
            thresholds[i] = choices[i & 7u];
            x[i] = next(state);
            if (i < 32768u)
            {
                const u64 h = i >> 3u;
                const u64 center = h * radix + q - 1u - h * c;
                x[i] = center + (i & 7u) - 3u;
                thresholds[i] = standard;
            }
            else if (i < 65536u)
            {
                const u64 offset = (i >> 3u) & 127u;
                x[i] = (i & 1u) ? ~u64{0} - offset : offset;
            }
        }
        check(cudaMemcpy(dx, x.data(), n * sizeof(u64), cudaMemcpyHostToDevice));
        check(cudaMemcpy(dt, thresholds.data(), n * sizeof(u64), cudaMemcpyHostToDevice));
        reduceWords<<<1056, 256>>>(dx, dt, da, db, q, c, n);
        check(cudaGetLastError());
        check(cudaMemcpy(a.data(), da, n * sizeof(SamplePseudo52Word), cudaMemcpyDeviceToHost));
        check(cudaMemcpy(b.data(), db, n * sizeof(SamplePseudo52Word), cudaMemcpyDeviceToHost));
        for (u64 i = 0u; i < n; ++i)
        {
            const u64 residue = x[i] % q;
            const u32 rejected = static_cast<u32>(x[i] >= thresholds[i]);
            if (a[i].residue != residue || b[i].residue != residue ||
                a[i].rejected != rejected || b[i].rejected != rejected)
            {
                std::fprintf(stderr, "FAIL c=%u index=%llu\n", c, (unsigned long long)i);
                return 1;
            }
        }
        total += 2u * n;
    }
    check(cudaFree(dx)); check(cudaFree(dt)); check(cudaFree(da)); check(cudaFree(db));
    std::printf("Pseudo52 sampler exact: %llu word/rejection checks, 32 moduli, default/custom thresholds passed\n",
        (unsigned long long)total);
}
