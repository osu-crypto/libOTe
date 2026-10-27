// CUDA kernels for the VOLE-based ZK checks. See LogVoleGpuZk.h for what they
// compute and LogVoleZk.h for why the identities hold.
//
// Everything is a weighted sum of products modulo one 51- or 54-bit prime. The
// arithmetic helpers are the same SEAL-identical ones the ring kernels use, so
// each individual product matches the host, and because every partial sum is
// reduced the tree order does not change the result.

#include "libOTe/Vole/LogVole/cuda/LogVoleGpuZk.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuArith.cuh"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuZkArith.cuh"

#include <cuda_runtime.h>

#include <cstdio>
#include <cstdlib>
#include <limits>
#include <type_traits>

namespace osuCrypto::LogVole::gpu
{
    namespace
    {
        constexpr u32 kZkThreads = 256;

        __global__ void zkSetMaskKernel(u64* destination, u64 mask)
        {
            *destination = mask;
        }

        bool deviceConstantsEnabled()
        {
            const char* value = std::getenv("LV_GPU_ZK_DEVICE_CONSTANTS");
            return !value || value[0] != '0';
        }

        __global__ void zkPrepareModulusKernel(u64 modulus, HostModulus* out)
        {
            // Binary long division of the single set bit 2^128. The
            // remainder remains below 2^61, so doubling cannot overflow.
            u64 remainder = 1, lo = 0, hi = 0;
            for (int bit = 127; bit >= 0; --bit)
            {
                remainder <<= 1;
                if (remainder >= modulus)
                {
                    remainder -= modulus;
                    if (bit >= 64) hi |= u64{1} << (bit - 64);
                    else lo |= u64{1} << bit;
                }
            }
            *out = HostModulus{modulus, lo, hi};
        }

        __global__ void zkAcceptKernel(u64 proofU, u64 proofV, u64 verifierValue,
            u64 delta, GpuModulus mod, u64* accepted)
        {
            const u64 expected = addMod(mulMod(proofV, delta, mod),
                barrettReduce64(proofU, mod), mod.mValue);
            *accepted = verifierValue == expected ? 1u : 0u;
        }

        __global__ void zkPackOperandsKernel(
            const u64* residues, u32* operands, u64 count, u64 width)
        {
            for (u64 i = static_cast<u64>(blockIdx.x) * blockDim.x + threadIdx.x;
                 i < count; i += static_cast<u64>(gridDim.x) * blockDim.x)
                operands[i] = static_cast<u32>((i / 2 / width) * width + residues[i]);
        }

        u32 zkPseudoBits(u64 modulus)
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_ZK_PSEUDO_REDUCE");
                return !(v && v[0] == '0');
            }();
            if (!on) return 0;
            for (u32 bits : {54u, 51u})
            {
                const u64 radix = u64{1} << bits;
                if (modulus < radix && radix - modulus < (u64{1} << 24u))
                    return bits;
            }
            return 0;
        }

        template<u32 Bits>
        __device__ __forceinline__ u64 zkMulMod(u64 a, u64 b, const GpuModulus& mod)
        {
            if constexpr (Bits != 0) return mulModZkPseudo<Bits>(a, b, mod.mValue);
            else return mulMod(a, b, mod);
        }

        inline cudaStream_t asStream(void* s)
        {
            return static_cast<cudaStream_t>(s);
        }

        bool zkDebug()
        {
            static const bool on = [] {
                const char* v = std::getenv("LOGVOLE_GPU_DEBUG");
                return v && v[0] != '\0' && v[0] != '0';
            }();
            return on;
        }

        inline bool check(cudaError_t e, const char* where)
        {
            if (e == cudaSuccess) return true;
            if (zkDebug())
            {
                std::fprintf(stderr, "[lvzk] %s: %s\n", where, cudaGetErrorString(e));
            }
            return false;
        }

        inline GpuModulus toDevice(const HostModulus& m)
        {
            return GpuModulus{ m.mValue, m.mRatio0, m.mRatio1 };
        }

        // Loads that are read once and never revisited, tagged evict-first so they
        // do not push the gather working set out of L2.
        //
        // This is what fixes the cliff between 2^22 and 2^24 gates. A layered
        // circuit gathers its operands from the layer below - 4 MB across the value
        // and MAC arrays at 2^24 - which L2 can hold, but the check also streams the
        // output-wire MAC and the operand pair, 264 MB of it, straight through the
        // same cache. Below 2^22 the whole arrays fit in the 48 MB L2 and it does
        // not matter; above that the streaming traffic evicts the layer and every
        // gather becomes a DRAM sector read. Measured at 2^24: 4.02 ms -> see below.
        __device__ inline u64 loadStreaming(const u64* p)
        {
            return static_cast<u64>(__ldcs(reinterpret_cast<const unsigned long long*>(p)));
        }

        __device__ inline u32 loadStreaming(const u32* p)
        {
            return static_cast<u32>(__ldcs(reinterpret_cast<const unsigned int*>(p)));
        }

        __host__ __device__ inline u64 powModDevice(u64 base, u64 exp, const GpuModulus& mod)
        {
            u64 result = 1 % mod.mValue;
            u64 acc = base % mod.mValue;
            while (exp)
            {
                if (exp & 1) result = mulMod(result, acc, mod);
                acc = mulMod(acc, acc, mod);
                exp >>= 1;
            }
            return result;
        }

        // Block-wide sum modulo q of up to two accumulators. Warp shuffles for
        // the first five steps, then one shared-memory pass over the warp
        // results; that keeps the shared footprint at 2 u64 per warp.
        template<u32 Lanes>
        __device__ inline void blockReduceMod(u64 (&acc)[Lanes], u64 q, u64* shared)
        {
            const u32 lane = threadIdx.x & 31u;
            const u32 warp = threadIdx.x >> 5;
            const u32 warps = (blockDim.x + 31u) >> 5;

#pragma unroll
            for (u32 l = 0; l < Lanes; ++l)
            {
                for (u32 off = 16; off; off >>= 1)
                {
                    const u64 other = __shfl_down_sync(0xFFFFFFFFu, acc[l], off);
                    acc[l] = addMod(acc[l], other, q);
                }
            }

            if (lane == 0)
            {
#pragma unroll
                for (u32 l = 0; l < Lanes; ++l) shared[warp * Lanes + l] = acc[l];
            }
            __syncthreads();

            if (threadIdx.x == 0)
            {
#pragma unroll
                for (u32 l = 0; l < Lanes; ++l)
                {
                    u64 total = shared[l];
                    for (u32 w = 1; w < warps; ++w) total = addMod(total, shared[w * Lanes + l], q);
                    shared[l] = total;
                }
            }
            __syncthreads();
        }

        // ---- multiplication-gate check ------------------------------------
        //
        // A grid-stride loop, which for this kernel is also the cache-friendly
        // order: the whole grid advances through the gate range together, so at any
        // instant it is gathering from a window of the MAC array about one circuit
        // layer wide (4 MB across both arrays at 2^24 gates) and the 48 MB L2 holds
        // it. Giving each block a contiguous slab instead was measured and is 1.75x
        // slower - 7.07 ms against 4.03 ms at 2^24 - because the resident blocks
        // then sit in 1024 different layers at once and every gather becomes a DRAM
        // sector read with 8 of 32 bytes used.
        //
        // The output-wire MAC and the operand pair are contiguous in the gate
        // index, so those reads coalesce.
        //
        // Challenge powers: gate g carries chi^(g+1), and raising chi to g+1 per
        // thread by square-and-multiply cost ~110 modular multiplies against the 5
        // the gate itself needs. Instead thread 0 raises chi to the block's first
        // gate, each thread multiplies in chi^threadIdx (8 bits, ~16 multiplies),
        // and the loop steps by chi^(gridDim*blockDim), computed by thread 0. Identical
        // weights, so U and V are unchanged.
        template<u32 Bits>
        __global__ void zkMulProverKernel(
            const u64* __restrict__ wires,
            const u64* __restrict__ macs,
            const u32* __restrict__ operands,
            u64 gateCount,
            u64 firstOutWire,
            u64 chi,
            u64 chiStep,
            bool deviceStep,
            GpuModulus mod,
            u64* __restrict__ partials)
        {
            extern __shared__ u64 sh[];
            __shared__ u64 blockBase;
            __shared__ u64 blockStep;

            const u64 blockStart = static_cast<u64>(blockIdx.x) * blockDim.x;
            const u64 stride = static_cast<u64>(gridDim.x) * blockDim.x;

            if (threadIdx.x == 0)
            {
                blockBase = blockStart < gateCount ? powModDevice(chi, blockStart + 1, mod) : 0;
                blockStep = deviceStep ? powModDevice(chi, stride, mod) : chiStep;
            }
            __syncthreads();

            u64 acc[2] = { 0, 0 };
            u64 g = blockStart + threadIdx.x;
            if (g < gateCount)
            {
                u64 c = mulMod(blockBase, powModDevice(chi, threadIdx.x, mod), mod);
                for (; g < gateCount; g += stride)
                {
                    const u32 ix = loadStreaming(operands + 2 * g);
                    const u32 iy = loadStreaming(operands + 2 * g + 1);
                    const u64 mx = macs[ix];
                    const u64 my = macs[iy];
                    const u64 mz = loadStreaming(macs + firstOutWire + g);
                    const u64 x = wires[ix];
                    const u64 y = wires[iy];

                    const u64 a0 = zkMulMod<Bits>(mx, my, mod);
                    const u64 t = addMod(
                        zkMulMod<Bits>(x, my, mod), zkMulMod<Bits>(y, mx, mod), mod.mValue);
                    const u64 a1 = subMod(mz, t, mod.mValue);

                    acc[0] = addMod(acc[0], zkMulMod<Bits>(c, a0, mod), mod.mValue);
                    acc[1] = addMod(acc[1], zkMulMod<Bits>(c, a1, mod), mod.mValue);
                    c = zkMulMod<Bits>(c, blockStep, mod);
                }
            }

            blockReduceMod<2>(acc, mod.mValue, sh);
            if (threadIdx.x == 0)
            {
                partials[blockIdx.x] = sh[0];
                partials[gridDim.x + blockIdx.x] = sh[1];
            }
        }

        template<u32 Bits>
        __global__ void zkMulVerifierKernel(
            const u64* __restrict__ keys,
            const u32* __restrict__ operands,
            u64 gateCount,
            u64 firstOutWire,
            u64 chi,
            u64 chiStep,
            bool deviceStep,
            u64 delta,
            GpuModulus mod,
            u64* __restrict__ partials)
        {
            extern __shared__ u64 sh[];
            __shared__ u64 blockBase;
            __shared__ u64 blockStep;
            __shared__ u64 reducedDelta;

            const u64 blockStart = static_cast<u64>(blockIdx.x) * blockDim.x;
            const u64 stride = static_cast<u64>(gridDim.x) * blockDim.x;

            if (threadIdx.x == 0)
            {
                blockBase = blockStart < gateCount ? powModDevice(chi, blockStart + 1, mod) : 0;
                blockStep = deviceStep ? powModDevice(chi, stride, mod) : chiStep;
                reducedDelta = deviceStep ? barrettReduce64(delta, mod) : delta;
            }
            __syncthreads();

            u64 acc[1] = { 0 };
            u64 g = blockStart + threadIdx.x;
            if (g < gateCount)
            {
                u64 c = mulMod(blockBase, powModDevice(chi, threadIdx.x, mod), mod);
                for (; g < gateCount; g += stride)
                {
                    const u32 ix = loadStreaming(operands + 2 * g);
                    const u32 iy = loadStreaming(operands + 2 * g + 1);
                    const u64 kx = keys[ix];
                    const u64 ky = keys[iy];
                    const u64 kz = loadStreaming(keys + firstOutWire + g);

                    const u64 b = addMod(
                        zkMulMod<Bits>(kx, ky, mod), zkMulMod<Bits>(kz, reducedDelta, mod), mod.mValue);
                    acc[0] = addMod(acc[0], zkMulMod<Bits>(c, b, mod), mod.mValue);
                    c = zkMulMod<Bits>(c, blockStep, mod);
                }
            }

            blockReduceMod<1>(acc, mod.mValue, sh);
            if (threadIdx.x == 0) partials[blockIdx.x] = sh[0];
        }

        // Second stage plus the ZK mask, in one block. `maskAdd` is added to lane
        // 0 and `maskSub` subtracted from lane 1, which is exactly (+M[r], -r) for
        // the prover and (+K[r], -) for the verifier.
        template<u32 Lanes>
        __global__ void zkReduceKernel(
            const u64* __restrict__ partials,
            u64 count,
            const u64* __restrict__ maskAdd,
            const u64* __restrict__ maskSub,
            GpuModulus mod,
            u64* __restrict__ out)
        {
            extern __shared__ u64 sh[];
            u64 acc[Lanes];
#pragma unroll
            for (u32 l = 0; l < Lanes; ++l)
            {
                acc[l] = 0;
                for (u64 i = threadIdx.x; i < count; i += blockDim.x)
                {
                    acc[l] = addMod(acc[l], partials[l * count + i], mod.mValue);
                }
            }

            blockReduceMod<Lanes>(acc, mod.mValue, sh);
            if (threadIdx.x == 0)
            {
                u64 v0 = sh[0];
                if (maskAdd) v0 = addMod(v0, *maskAdd, mod.mValue);
                out[0] = v0;
                if (Lanes > 1)
                {
                    u64 v1 = sh[1];
                    if (maskSub) v1 = subMod(v1, *maskSub % mod.mValue, mod.mValue);
                    out[1] = v1;
                }
            }
        }

        // ---- matrix multiplication ---------------------------------------

        // Each cell evaluates its full length-n inner product before applying
        // its independent batching coefficient. There is no factorization of
        // the coefficients into row and column challenges.
        template<u32 Bits>
        __global__ void zkMatMulProverKernel(
            const u64* __restrict__ wires,
            const u64* __restrict__ macs,
            const u64* __restrict__ coefficients,
            u32 n,
            GpuModulus mod,
            u64* __restrict__ partials)
        {
            extern __shared__ u64 sh[];
            const u64 entries = static_cast<u64>(n) * n;
            for (u64 cell = blockIdx.x; cell < entries; cell += gridDim.x)
            {
                const u64 row = cell / n;
                const u64 col = cell % n;
                u64 acc[2] = { 0, 0 };
                for (u64 k = threadIdx.x; k < n; k += blockDim.x)
                {
                    const u64 ia = row * n + k;
                    const u64 ib = entries + k * n + col;
                    const u64 ma = macs[ia], mb = macs[ib];
                    acc[0] = addMod(acc[0], zkMulMod<Bits>(ma, mb, mod), mod.mValue);
                    const u64 cross = addMod(zkMulMod<Bits>(wires[ia], mb, mod),
                        zkMulMod<Bits>(wires[ib], ma, mod), mod.mValue);
                    acc[1] = addMod(acc[1], cross, mod.mValue);
                }
                blockReduceMod<2>(acc, mod.mValue, sh);
                if (threadIdx.x == 0)
                {
                    const u64 rho = coefficients[cell];
                    partials[cell] = zkMulMod<Bits>(rho, sh[0], mod);
                    partials[entries + cell] = zkMulMod<Bits>(
                        rho, subMod(0, sh[1], mod.mValue), mod);
                }
                // The next cell reuses sh; every thread must finish reading
                // this cell's reduction before that shared storage is reused.
                __syncthreads();
            }
        }

        template<u32 Bits>
        __global__ void zkMatMulVerifierKernel(
            const u64* __restrict__ keys,
            const u64* __restrict__ publicProduct,
            const u64* __restrict__ coefficients,
            u32 n,
            u64 delta,
            GpuModulus mod,
            u64* __restrict__ partials)
        {
            extern __shared__ u64 sh[];
            const u64 entries = static_cast<u64>(n) * n;
            const u64 reducedDelta = barrettReduce64(delta, mod);
            const u64 deltaSquared = zkMulMod<Bits>(reducedDelta, reducedDelta, mod);
            for (u64 cell = blockIdx.x; cell < entries; cell += gridDim.x)
            {
                const u64 row = cell / n;
                const u64 col = cell % n;
                u64 acc[1] = { 0 };
                for (u64 k = threadIdx.x; k < n; k += blockDim.x)
                {
                    const u64 ia = row * n + k;
                    const u64 ib = entries + k * n + col;
                    acc[0] = addMod(acc[0], zkMulMod<Bits>(keys[ia], keys[ib], mod), mod.mValue);
                }
                blockReduceMod<1>(acc, mod.mValue, sh);
                if (threadIdx.x == 0)
                {
                    const u64 value = subMod(sh[0],
                        zkMulMod<Bits>(publicProduct[cell], deltaSquared, mod), mod.mValue);
                    partials[cell] = zkMulMod<Bits>(coefficients[cell], value, mod);
                }
                __syncthreads();
            }
        }

        constexpr u32 kGemmTile = 16;

        __global__ void zkGemmKernel(
            const u64* __restrict__ a,
            const u64* __restrict__ b,
            u64* __restrict__ c,
            u32 n,
            GpuModulus mod)
        {
            __shared__ u64 as[kGemmTile][kGemmTile];
            __shared__ u64 bs[kGemmTile][kGemmTile];

            const u32 row = blockIdx.y * kGemmTile + threadIdx.y;
            const u32 col = blockIdx.x * kGemmTile + threadIdx.x;
            u64 acc = 0;

            const u32 tiles = (n + kGemmTile - 1) / kGemmTile;
            for (u32 t = 0; t < tiles; ++t)
            {
                const u32 ak = t * kGemmTile + threadIdx.x;
                const u32 bk = t * kGemmTile + threadIdx.y;
                as[threadIdx.y][threadIdx.x] =
                    (row < n && ak < n) ? a[static_cast<std::size_t>(row) * n + ak] : 0;
                bs[threadIdx.y][threadIdx.x] =
                    (bk < n && col < n) ? b[static_cast<std::size_t>(bk) * n + col] : 0;
                __syncthreads();

#pragma unroll
                for (u32 k = 0; k < kGemmTile; ++k)
                {
                    acc = addMod(
                        acc, mulMod(as[threadIdx.y][k], bs[k][threadIdx.x], mod), mod.mValue);
                }
                __syncthreads();
            }

            if (row < n && col < n) c[static_cast<std::size_t>(row) * n + col] = acc;
        }

        __global__ void zkMulEvalLayerKernel(
            u64* __restrict__ wires,
            const u32* __restrict__ operands,
            u64 firstGate,
            u64 width,
            u64 firstOutWire,
            GpuModulus mod)
        {
            const u64 j = static_cast<u64>(blockIdx.x) * blockDim.x + threadIdx.x;
            if (j >= width) return;
            const u64 g = firstGate + j;
            const u32 ix = operands[2 * g];
            const u32 iy = operands[2 * g + 1];
            wires[firstOutWire + g] = mulMod(wires[ix], wires[iy], mod);
        }

        u32 reduceBlocks(u64 items)
        {
            const u64 want = (items + kZkThreads - 1) / kZkThreads;
            if (want == 0) return 1;
            return want < kZkReduceBlocks ? static_cast<u32>(want) : kZkReduceBlocks;
        }

        // Shared bytes for blockReduceMod with `lanes` accumulators.
        constexpr u32 reduceShared(u32 lanes)
        {
            return ((kZkThreads + 31u) / 32u) * lanes * sizeof(u64);
        }
    }

    bool launchZkPrepareModulus(u64 modulus, HostModulus* out, void* stream)
    {
        if (modulus < 2 || modulus >= (u64{1} << 61u) || !out) return false;
        zkPrepareModulusKernel<<<1, 1, 0, asStream(stream)>>>(modulus, out);
        return check(cudaGetLastError(), "zkPrepareModulus");
    }

    bool launchZkAccept(u64 proofU, u64 proofV, u64 verifierValue, u64 delta,
        const HostModulus& mod, u64* accepted, void* stream)
    {
        if (mod.mValue < 2 || mod.mValue >= (u64{1} << 61u) || !accepted) return false;
        zkAcceptKernel<<<1, 1, 0, asStream(stream)>>>(
            proofU, proofV, verifierValue, delta, toDevice(mod), accepted);
        return check(cudaGetLastError(), "zkAccept");
    }

    bool launchZkMulProver(
        const u64* wires,
        const u64* macs,
        const u32* operands,
        u64 gateCount,
        u64 firstOutWire,
        u64 maskIndex,
        u64 chi,
        const HostModulus& mod,
        u64* scratch,
        u64* outUV,
        void* stream)
    {
        if (!gateCount || !wires || !macs || !operands || !scratch || !outUV) return false;
        const GpuModulus m = toDevice(mod);
        const u32 blocks = reduceBlocks(gateCount);
        const bool deviceStep = deviceConstantsEnabled();
        const u64 chiStep = deviceStep ? 0u : powModDevice(chi, static_cast<u64>(blocks) * kZkThreads, m);

        const auto launch = [&](auto tag) {
            constexpr u32 bits = decltype(tag)::value;
            zkMulProverKernel<bits><<<blocks, kZkThreads, reduceShared(2), asStream(stream)>>>(
                wires, macs, operands, gateCount, firstOutWire, chi, chiStep, deviceStep, m, scratch);
        };
        const u32 bits = zkPseudoBits(mod.mValue);
        if (bits == 54u) launch(std::integral_constant<u32, 54u>{});
        else if (bits == 51u) launch(std::integral_constant<u32, 51u>{});
        else launch(std::integral_constant<u32, 0u>{});
        if (!check(cudaGetLastError(), "zkMulProver")) return false;

        // The partials are laid out [U blocks][V blocks], so the reducer's lane
        // stride is `blocks`, not kZkReduceBlocks.
        zkReduceKernel<2><<<1, kZkThreads, reduceShared(2), asStream(stream)>>>(
            scratch, blocks, macs + maskIndex, wires + maskIndex, m, outUV);
        return check(cudaGetLastError(), "zkMulProverReduce");
    }

    bool launchZkMulVerifier(
        const u64* keys,
        const u32* operands,
        u64 gateCount,
        u64 firstOutWire,
        u64 maskIndex,
        u64 chi,
        u64 delta,
        const HostModulus& mod,
        u64* scratch,
        u64* outB,
        void* stream)
    {
        if (!gateCount || !keys || !operands || !scratch || !outB) return false;
        const GpuModulus m = toDevice(mod);
        const u32 blocks = reduceBlocks(gateCount);
        const bool deviceStep = deviceConstantsEnabled();
        const u64 chiStep = deviceStep ? 0u : powModDevice(chi, static_cast<u64>(blocks) * kZkThreads, m);

        const auto launch = [&](auto tag) {
            constexpr u32 bits = decltype(tag)::value;
            zkMulVerifierKernel<bits><<<blocks, kZkThreads, reduceShared(1), asStream(stream)>>>(
                keys, operands, gateCount, firstOutWire, chi, chiStep, deviceStep,
                deviceStep ? delta : delta % mod.mValue, m, scratch);
        };
        const u32 bits = zkPseudoBits(mod.mValue);
        if (bits == 54u) launch(std::integral_constant<u32, 54u>{});
        else if (bits == 51u) launch(std::integral_constant<u32, 51u>{});
        else launch(std::integral_constant<u32, 0u>{});
        if (!check(cudaGetLastError(), "zkMulVerifier")) return false;

        zkReduceKernel<1><<<1, kZkThreads, reduceShared(1), asStream(stream)>>>(
            scratch, blocks, keys + maskIndex, nullptr, m, outB);
        return check(cudaGetLastError(), "zkMulVerifierReduce");
    }

    bool launchZkMatMulProver(
        const u64* wires, const u64* macs, const u64* coefficients,
        u32 n, u64 maskIndex, const HostModulus& mod,
        u64* scratch, u64* outUV, void* stream)
    {
        const u64 entries = static_cast<u64>(n) * n;
        if (!n || !wires || !macs || !coefficients || !scratch || !outUV ||
            entries > std::numeric_limits<std::size_t>::max() / (2 * sizeof(u64)) ||
            maskIndex < 2 * entries) return false;
        const GpuModulus m = toDevice(mod);
        const u32 blocks = static_cast<u32>(entries < 65535u ? entries : 65535u);
        const auto launch = [&](auto tag) {
            constexpr u32 bits = decltype(tag)::value;
            zkMatMulProverKernel<bits><<<blocks, kZkThreads, reduceShared(2), asStream(stream)>>>(
                wires, macs, coefficients, n, m, scratch);
        };
        const u32 bits = zkPseudoBits(mod.mValue);
        if (bits == 54u) launch(std::integral_constant<u32, 54u>{});
        else if (bits == 51u) launch(std::integral_constant<u32, 51u>{});
        else launch(std::integral_constant<u32, 0u>{});
        if (!check(cudaGetLastError(), "zkMatMulProver")) return false;
        zkReduceKernel<2><<<1, kZkThreads, reduceShared(2), asStream(stream)>>>(
            scratch, entries, macs + maskIndex, wires + maskIndex, m, outUV);
        return check(cudaGetLastError(), "zkMatMulProverReduce");
    }

    bool launchZkMatMulVerifier(
        const u64* keys, const u64* publicProduct, const u64* coefficients,
        u32 n, u64 maskIndex, u64 delta, const HostModulus& mod,
        u64* scratch, u64* outB, void* stream)
    {
        const u64 entries = static_cast<u64>(n) * n;
        if (!n || !keys || !publicProduct || !coefficients || !scratch || !outB ||
            entries > std::numeric_limits<std::size_t>::max() / (2 * sizeof(u64)) ||
            maskIndex < 2 * entries) return false;
        const GpuModulus m = toDevice(mod);
        const u32 blocks = static_cast<u32>(entries < 65535u ? entries : 65535u);
        const auto launch = [&](auto tag) {
            constexpr u32 bits = decltype(tag)::value;
            zkMatMulVerifierKernel<bits><<<blocks, kZkThreads, reduceShared(1), asStream(stream)>>>(
                keys, publicProduct, coefficients, n, delta, m, scratch);
        };
        const u32 bits = zkPseudoBits(mod.mValue);
        if (bits == 54u) launch(std::integral_constant<u32, 54u>{});
        else if (bits == 51u) launch(std::integral_constant<u32, 51u>{});
        else launch(std::integral_constant<u32, 0u>{});
        if (!check(cudaGetLastError(), "zkMatMulVerifier")) return false;
        zkReduceKernel<1><<<1, kZkThreads, reduceShared(1), asStream(stream)>>>(
            scratch, entries, keys + maskIndex, nullptr, m, outB);
        return check(cudaGetLastError(), "zkMatMulVerifierReduce");
    }

    bool launchZkSetMask(u64* destination, u64 mask, void* stream)
    {
        if (!destination) return false;
        zkSetMaskKernel<<<1, 1, 0, asStream(stream)>>>(destination, mask);
        return check(cudaGetLastError(), "zkSetMask");
    }

    bool launchZkPackOperands(
        const u64* residues, u32* operands, u64 count, u64 width, void* stream)
    {
        if (!residues || !operands || !count || !width) return false;
        const u64 needed = (count + kZkThreads - 1) / kZkThreads;
        const u32 blocks = static_cast<u32>(needed < 65535 ? needed : 65535);
        zkPackOperandsKernel<<<blocks, kZkThreads, 0, asStream(stream)>>>(
            residues, operands, count, width);
        return check(cudaGetLastError(), "zkPackOperands");
    }

    bool launchZkMulEvalLayer(
        u64* wires,
        const u32* operands,
        u64 firstGate,
        u64 width,
        u64 firstOutWire,
        const HostModulus& mod,
        void* stream)
    {
        if (!wires || !operands || !width) return false;
        const u32 blocks = static_cast<u32>((width + kZkThreads - 1) / kZkThreads);
        zkMulEvalLayerKernel<<<blocks, kZkThreads, 0, asStream(stream)>>>(
            wires, operands, firstGate, width, firstOutWire, toDevice(mod));
        return check(cudaGetLastError(), "zkMulEvalLayer");
    }

    bool launchZkMatMulGemm(
        const u64* a, const u64* b, u64* c, u32 n, const HostModulus& mod, void* stream)
    {
        if (!n || !a || !b || !c) return false;
        const dim3 threads(kGemmTile, kGemmTile);
        const dim3 blocks((n + kGemmTile - 1) / kGemmTile, (n + kGemmTile - 1) / kGemmTile);
        zkGemmKernel<<<blocks, threads, 0, asStream(stream)>>>(a, b, c, n, toDevice(mod));
        return check(cudaGetLastError(), "zkGemm");
    }
}
