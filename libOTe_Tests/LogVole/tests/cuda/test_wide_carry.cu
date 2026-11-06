// Full-width carry/borrow oracle. See this directory's README.md for CMake/CTest.
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuWideCarry.cuh"
#include <cstdio>
#include <cstdlib>
#include <vector>
using namespace osuCrypto::LogVole::gpu;
void check(cudaError_t e)
{
    if (e != cudaSuccess) { std::fprintf(stderr, "%s\n", cudaGetErrorString(e)); std::exit(2); }
}
__global__ void arithmetic(const Wide* a, const Wide* b, Wide* sum, Wide* diff, u64 n)
{
    for (u64 i = blockIdx.x * blockDim.x + threadIdx.x; i < n;
         i += static_cast<u64>(gridDim.x) * blockDim.x)
    {
        sum[i] = wideAddCarry(a[i], b[i]);
        diff[i] = wideSubCarry(a[i], b[i]);
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
    constexpr u64 n = 1u << 20u;
    std::vector<Wide> a(n), b(n), sum(n), diff(n);
    Wide *da, *db, *ds, *dd;
    check(cudaMalloc(&da, n * sizeof(Wide))); check(cudaMalloc(&db, n * sizeof(Wide)));
    check(cudaMalloc(&ds, n * sizeof(Wide))); check(cudaMalloc(&dd, n * sizeof(Wide)));
    u64 state = 0x128ca77, total = 0;
    for (u64 round = 0; round < 32; ++round)
    {
        for (u64 i = 0; i < n; ++i)
        {
            a[i] = {next(state), next(state)};
            b[i] = {next(state), next(state)};
            if (i < 65536u)
            {
                const u64 x = i & 255u, y = (i >> 8u) & 255u;
                a[i].mLo = (x & 1u) ? ~u64{0} - (x >> 1u) : x >> 1u;
                b[i].mLo = (y & 1u) ? ~u64{0} - (y >> 1u) : y >> 1u;
                a[i].mHi = (round & 1u) ? ~u64{0} - (round >> 1u) : round >> 1u;
                b[i].mHi = (round & 2u) ? ~u64{0} - (round >> 2u) : round >> 2u;
            }
        }
        check(cudaMemcpy(da, a.data(), n * sizeof(Wide), cudaMemcpyHostToDevice));
        check(cudaMemcpy(db, b.data(), n * sizeof(Wide), cudaMemcpyHostToDevice));
        arithmetic<<<1056, 256>>>(da, db, ds, dd, n);
        check(cudaGetLastError());
        check(cudaMemcpy(sum.data(), ds, n * sizeof(Wide), cudaMemcpyDeviceToHost));
        check(cudaMemcpy(diff.data(), dd, n * sizeof(Wide), cudaMemcpyDeviceToHost));
        for (u64 i = 0; i < n; ++i)
        {
            const unsigned __int128 av = (static_cast<unsigned __int128>(a[i].mHi) << 64u) | a[i].mLo;
            const unsigned __int128 bv = (static_cast<unsigned __int128>(b[i].mHi) << 64u) | b[i].mLo;
            const auto eq = [](Wide v, unsigned __int128 e) { return v.mLo == static_cast<u64>(e) && v.mHi == static_cast<u64>(e >> 64u); };
            if (!eq(sum[i], av + bv) || !eq(diff[i], av - bv))
            {
                std::fprintf(stderr, "FAIL round=%llu index=%llu\n", (unsigned long long)round, (unsigned long long)i);
                return 1;
            }
        }
        total += 2u * n;
    }
    check(cudaFree(da)); check(cudaFree(db)); check(cudaFree(ds)); check(cudaFree(dd));
    std::printf("Wide carry exact: %llu full-width additions/subtractions including overflow/borrow passed\n", (unsigned long long)total);
}
