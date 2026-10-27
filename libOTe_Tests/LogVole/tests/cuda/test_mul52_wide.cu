// Independent full-width unsigned-128 oracle; no modular reduction can mask
// an error in either word. Build and run with this directory's CMake/CTest setup.
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuMul52.cuh"
#include <cstdio>
#include <cstdlib>
#include <vector>
using u64 = std::uint64_t;
void check(cudaError_t e)
{
    if (e != cudaSuccess) { std::fprintf(stderr, "%s\n", cudaGetErrorString(e)); std::exit(2); }
}
__global__ void multiply(const u64* a, const u64* b, ulonglong2* out, u64 n)
{
    for (u64 i = blockIdx.x * blockDim.x + threadIdx.x; i < n;
         i += static_cast<u64>(gridDim.x) * blockDim.x)
        out[i] = osuCrypto::LogVole::gpu::mulWide52(a[i], b[i]);
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
    constexpr u64 n = 1u << 20u, mask = (u64{1} << 52u) - 1u;
    std::vector<u64> a(n), b(n);
    std::vector<ulonglong2> got(n);
    u64 *da, *db;
    ulonglong2* dout;
    check(cudaMalloc(&da, n * sizeof(u64)));
    check(cudaMalloc(&db, n * sizeof(u64)));
    check(cudaMalloc(&dout, n * sizeof(ulonglong2)));
    u64 state = 0x52104, total = 0;
    for (u64 round = 0; round < 32; ++round)
    {
        for (u64 i = 0; i < n; ++i)
        {
            a[i] = next(state) & mask;
            b[i] = next(state) & mask;
            if (i < 65536u)
            {
                const u64 x = i & 255u, y = (i >> 8u) & 255u;
                const u64 edge = round == 0u ? mask : round == 1u ? (u64{1} << 32u) - 1u :
                    round == 2u ? (u64{1} << 32u) : mask - (round << 32u);
                a[i] = (x & 1u) ? edge - (x >> 1u) : x >> 1u;
                b[i] = (y & 1u) ? edge - (y >> 1u) : y >> 1u;
            }
        }
        check(cudaMemcpy(da, a.data(), n * sizeof(u64), cudaMemcpyHostToDevice));
        check(cudaMemcpy(db, b.data(), n * sizeof(u64), cudaMemcpyHostToDevice));
        multiply<<<1056, 256>>>(da, db, dout, n);
        check(cudaGetLastError());
        check(cudaMemcpy(got.data(), dout, n * sizeof(ulonglong2), cudaMemcpyDeviceToHost));
        for (u64 i = 0; i < n; ++i)
        {
            const unsigned __int128 expected = static_cast<unsigned __int128>(a[i]) * b[i];
            if (got[i].x != static_cast<u64>(expected) || got[i].y != static_cast<u64>(expected >> 64u))
            {
                std::fprintf(stderr, "FAIL round=%llu index=%llu\n", (unsigned long long)round, (unsigned long long)i);
                return 1;
            }
        }
        total += n;
    }
    check(cudaFree(da)); check(cudaFree(db)); check(cudaFree(dout));
    std::printf("MUL52 exact: %llu complete 128-bit products, boundary cross-products passed\n", (unsigned long long)total);
}
