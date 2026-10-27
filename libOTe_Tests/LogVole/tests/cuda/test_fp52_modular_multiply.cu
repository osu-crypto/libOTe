// Independent unsigned-128 CPU oracle for the experimental FP64 multiplier.
// nvcc -O3 -std=c++17 -arch=sm_90 -I. libOTe_Tests/LogVole/tests/cuda/test_fp52_modular_multiply.cu -o <binary>
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuFp52.cuh"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using u64 = std::uint64_t;
using i64 = std::int64_t;
using namespace osuCrypto::LogVole::gpu;

void check(cudaError_t e)
{
    if (e != cudaSuccess) { std::fprintf(stderr, "%s\n", cudaGetErrorString(e)); std::exit(2); }
}

template<bool Prediv>
__global__ void multiply(const i64* a, const u64* b, u64* out, u64 q, u64 n)
{
    const double qd = static_cast<double>(q);
    const double inv = __drcp_rn(qd);
    for (u64 i = blockIdx.x * blockDim.x + threadIdx.x; i < n;
         i += static_cast<u64>(gridDim.x) * blockDim.x)
    {
        const double ad = static_cast<double>(a[i]), bd = static_cast<double>(b[i]);
        if constexpr (Prediv)
            out[i] = static_cast<u64>(mulModFp52Prediv(ad, bd, qd, __ddiv_rn(bd, qd)));
        else out[i] = static_cast<u64>(mulModFp52(ad, bd, qd, inv));
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

int main(int argc, char** argv)
{
    const bool prediv = argc == 2 && std::strcmp(argv[1], "prediv") == 0;
    if (argc > 1 && !prediv) { std::fprintf(stderr, "Usage: %s [prediv]\n", argv[0]); return 2; }
    constexpr u64 n = 1u << 20;
    std::vector<i64> a(n);
    std::vector<u64> b(n), out(n);
    i64* da; u64 *db, *dout;
    check(cudaMalloc(&da, n * 8)); check(cudaMalloc(&db, n * 8)); check(cudaMalloc(&dout, n * 8));
    u64 state = 0x52f00d, total = 0;
    for (u64 qi = 0; qi < 32; ++qi)
    {
        const u64 q = qi == 0 ? (u64{1} << 51) + 1 : qi == 1 ? (u64{1} << 52) - 1 :
            qi < 18 ? (u64{1} << 52) - 1 - (next(state) & ((1u << 24) - 1)) :
            (u64{1} << 51) + 1 + (next(state) & ((u64{1} << 51) - 2));
        for (u64 i = 0; i < n; ++i)
        {
            a[i] = static_cast<i64>(next(state) % q);
            b[i] = next(state) % q;
            if (i < 131072)
            {
                const u64 x = i & 255, y = (i >> 8) & 255;
                a[i] = static_cast<i64>((x & 1) ? q - 1 - (x >> 1) : x >> 1);
                b[i] = (y & 1) ? q - 1 - (y >> 1) : y >> 1;
            }
            if (i < 131072 ? ((i >> 16) & 1) : (i & 1)) a[i] = -a[i];
        }
        check(cudaMemcpy(da, a.data(), n * 8, cudaMemcpyHostToDevice));
        check(cudaMemcpy(db, b.data(), n * 8, cudaMemcpyHostToDevice));
        if (prediv) multiply<true><<<1056, 256>>>(da, db, dout, q, n);
        else multiply<false><<<1056, 256>>>(da, db, dout, q, n);
        check(cudaGetLastError());
        check(cudaMemcpy(out.data(), dout, n * 8, cudaMemcpyDeviceToHost));
        for (u64 i = 0; i < n; ++i)
        {
            const u64 aa = static_cast<u64>(a[i] < 0 ? a[i] + static_cast<i64>(q) : a[i]);
            const u64 expected = static_cast<u64>((static_cast<unsigned __int128>(aa) * b[i]) % q);
            if (out[i] != expected)
            {
                std::fprintf(stderr, "FAIL q=%llu a=%lld b=%llu got=%llu expected=%llu\n",
                    (unsigned long long)q, (long long)a[i], (unsigned long long)b[i],
                    (unsigned long long)out[i], (unsigned long long)expected);
                return 1;
            }
        }
        total += n;
    }
    check(cudaFree(da)); check(cudaFree(db)); check(cudaFree(dout));
    std::printf("FP52 %s exact: %llu products, 32 moduli, signed inputs and boundary cross-products passed\n",
        prediv ? "predivided" : "original", (unsigned long long)total);
}
