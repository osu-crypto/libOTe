// Exact ZK-field products against independent host unsigned-128-bit division.
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuZkArith.cuh"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace osuCrypto::LogVole::gpu;

namespace
{
    void check(cudaError_t error)
    {
        if (error == cudaSuccess) return;
        std::fprintf(stderr, "%s\n", cudaGetErrorString(error));
        std::exit(2);
    }

    u64 next(u64& state)
    {
        state += 0x9e3779b97f4a7c15ULL;
        u64 value = state;
        value = (value ^ (value >> 30u)) * 0xbf58476d1ce4e5b9ULL;
        value = (value ^ (value >> 27u)) * 0x94d049bb133111ebULL;
        return value ^ (value >> 31u);
    }

    template<u32 Bits>
    __global__ void products(const u64* a, const u64* b, u64* out, u64 q, u32 count)
    {
        for (u32 i = blockIdx.x * blockDim.x + threadIdx.x; i < count;
             i += blockDim.x * gridDim.x)
            out[i] = mulModZkPseudo<Bits>(a[i], b[i], q);
    }
}

int main()
{
    constexpr u32 count = 1u << 18u;
    std::vector<u64> a(count), b(count), got(count);
    u64 *deviceA, *deviceB, *deviceOut;
    check(cudaMalloc(&deviceA, count * sizeof(u64)));
    check(cudaMalloc(&deviceB, count * sizeof(u64)));
    check(cudaMalloc(&deviceOut, count * sizeof(u64)));
    u64 state = 0x5a6b7c8d, total = 0;
    for (u32 bits : {51u, 54u})
    {
        const u64 radix = u64{1} << bits;
        for (u32 round = 0; round < 16; ++round)
        {
            const std::array<u32, 8> constants{
                1u, 2u, 131071u, 1081343u, (1u << 16u) - 1u,
                1u << 23u, (1u << 24u) - 2u, (1u << 24u) - 1u};
            const u32 c = round < constants.size() ? constants[round]
                : 1u + static_cast<u32>(next(state) % ((1u << 24u) - 1u));
            const u64 q = radix - c;
            const std::array<u64, 12> edges{
                0, 1, 2, q - 1, q - 2, q / 2, q / 2 + 1,
                (u64{1} << 32u) - 1, u64{1} << 32u,
                (u64{1} << 32u) + 1, q - (u64{1} << 32u), q - c};
            for (u32 i = 0; i < count; ++i)
            {
                a[i] = next(state) % q;
                b[i] = next(state) % q;
                if (i < edges.size() * edges.size())
                {
                    a[i] = edges[i / edges.size()];
                    b[i] = edges[i % edges.size()];
                }
                else if (i < count / 4)
                {
                    a[i] = q - 1 - (i & 1023u);
                    b[i] = q - 1 - (i >> 10u);
                }
            }
            check(cudaMemcpy(deviceA, a.data(), count * sizeof(u64), cudaMemcpyHostToDevice));
            check(cudaMemcpy(deviceB, b.data(), count * sizeof(u64), cudaMemcpyHostToDevice));
            if (bits == 51u) products<51u><<<256, 256>>>(deviceA, deviceB, deviceOut, q, count);
            else products<54u><<<256, 256>>>(deviceA, deviceB, deviceOut, q, count);
            check(cudaGetLastError());
            check(cudaMemcpy(got.data(), deviceOut, count * sizeof(u64), cudaMemcpyDeviceToHost));
            for (u32 i = 0; i < count; ++i)
            {
                const u64 expected = static_cast<u64>(
                    (static_cast<unsigned __int128>(a[i]) * b[i]) % q);
                if (got[i] != expected)
                {
                    std::fprintf(stderr, "FAIL bits=%u c=%u index=%u\n", bits, c, i);
                    return 1;
                }
            }
            total += count;
        }
    }
    check(cudaFree(deviceA));
    check(cudaFree(deviceB));
    check(cudaFree(deviceOut));
    std::printf("ZK modular multiply exact: %llu products, 32 moduli, boundary and random inputs passed\n",
        static_cast<unsigned long long>(total));
}
