// CUDA kernels for LogVole's Ring-LWE arithmetic.
//
// Every kernel here is written to be bit-identical to the corresponding CPU
// routine in libOTe/Vole/LogVole/LogVoleRing.cpp (which itself delegates to
// Microsoft SEAL 4.1.1). That property is what lets the GPU backend be dropped
// into the protocol at arbitrary boundaries and validated by exact comparison.

#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuArith.cuh"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuFp52.cuh"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuMul52.cuh"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuWideCarry.cuh"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuPseudo52.cuh"

#include <cuda_runtime.h>
#if defined(_MSC_VER)
#include <malloc.h>
#endif

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace osuCrypto::LogVole::gpu
{
    namespace
    {
        constexpr u32 kMaxWords = 8;   // generic gadget decomposition limit
        constexpr u32 kMaxRawSetupWords = 16; // bounded GPU-native SEAL setup limit
        static_assert(sizeof(HostModulus) == sizeof(GpuModulus));
        static_assert(sizeof(HostShoupOperand) == sizeof(ShoupOperand));
        // The whole limb lives in shared memory. 1024 threads was optimal on the
        // original L40S and also lets Hopper run two resident blocks when the
        // kernel's register footprint permits it.
        constexpr u32 kNttThreads = 1024;

        __device__ u64 rawSetupPow(u64 base, u64 exponent, const GpuModulus& mod)
        {
            u64 result = 1;
            base = barrettReduce64(base, mod);
            while (exponent)
            {
                if (exponent & 1u) result = mulMod(result, base, mod);
                exponent >>= 1;
                if (exponent) base = mulMod(base, base, mod);
            }
            return result;
        }

        __device__ ShoupOperand rawSetupShoup(u64 value, const GpuModulus& mod)
        {
            Wide quotient{};
            u64 remainder = 0;
            divModWide(Wide{0, value}, mod.mValue,
                Wide{mod.mRatio0, mod.mRatio1}, &quotient, &remainder);
            return ShoupOperand{value, quotient.mLo};
        }

        __device__ bool rawSetupIsPrime(const GpuModulus& mod)
        {
            // Deterministic Miller-Rabin bases for every unsigned 64-bit input.
            constexpr u64 bases[] = {2, 325, 9375, 28178, 450775, 9780504, 1795265022};
            const u64 q = mod.mValue;
            u64 odd = q - 1;
            u32 powers = 0;
            while (!(odd & 1u)) { odd >>= 1; ++powers; }
            for (u64 base : bases)
            {
                base = barrettReduce64(base, mod);
                if (!base) continue;
                u64 value = rawSetupPow(base, odd, mod);
                if (value == 1 || value == q - 1) continue;
                bool witnessPassed = false;
                for (u32 i = 1; i < powers; ++i)
                {
                    value = mulMod(value, value, mod);
                    if (value == q - 1) { witnessPassed = true; break; }
                }
                if (!witnessPassed) return false;
            }
            return true;
        }

        __device__ GpuModulus rawSetupModulus(u64 q)
        {
            GpuModulus mod{q, 0, 0};
            // The same floor(2^128/q) Barrett ratio as SEAL Modulus and the
            // raw NTT constructor; q < 2^60 keeps shifted remainders in u64.
            u64 remainder = 1;
            for (int bit = 127; bit >= 0; --bit)
            {
                remainder <<= 1;
                if (remainder >= q)
                {
                    remainder -= q;
                    if (bit >= 64) mod.mRatio1 |= u64{1} << (bit - 64);
                    else mod.mRatio0 |= u64{1} << bit;
                }
            }
            return mod;
        }

        __device__ u64 rawSetupSealPrimeAtRank(u32 n, int bits, u32 rank)
        {
            if (bits < 2 || bits > 60 || !n || n > 131072u) return 0;
            const u64 factor = 2u * static_cast<u64>(n);
            const u64 lower = u64{1} << (bits - 1);
            u64 candidate = ((u64{1} << bits) - 1u) / factor * factor + 1u;
            // SEAL get_primes scans from the largest qualifying 1 mod 2N
            // candidate downward. CoeffModulus::Create takes each equal-bit
            // group's primes in reverse order, hence rank from the bottom.
            while (candidate > lower)
            {
                if (candidate > factor && rawSetupIsPrime(rawSetupModulus(candidate)))
                {
                    if (!rank) return candidate;
                    --rank;
                }
                if (candidate <= factor) break;
                candidate -= factor;
            }
            return 0;
        }

        __global__ void rawSetupSelectSealCoeffKernel(u32 n, const int* bits,
            u32 rho, u64* primes, u32* status)
        {
            const u32 j = threadIdx.x;
            if (j >= rho) return;
            u32 laterSame = 0;
            for (u32 k = j + 1u; k < rho; ++k)
                laterSame += static_cast<u32>(bits[k] == bits[j]);
            const u64 q = rawSetupSealPrimeAtRank(n, bits[j], laterSame);
            primes[j] = q;
            if (!q) atomicOr(status, 1u);
        }

        struct RawSetupWidths
        {
            int mBits[kMaxRawSetupWords]{};
        };

        __global__ void rawSetupSelectSealCoeffValueKernel(u32 n, RawSetupWidths widths,
            u32 rho, u64* primes, u32* status)
        {
            const u32 j = threadIdx.x;
            if (j >= rho) return;
            u32 laterSame = 0;
            for (u32 k = j + 1u; k < rho; ++k)
                laterSame += static_cast<u32>(widths.mBits[k] == widths.mBits[j]);
            const u64 q = rawSetupSealPrimeAtRank(n, widths.mBits[j], laterSame);
            primes[j] = q;
            if (!q) atomicOr(status, 1u);
        }

        __global__ void rawSetupSelectSealPlainKernel(u32 n, u32 requestedBits,
            u64 minimumQ, u64* prime, u32* selectedBits, u32* status)
        {
            if (threadIdx.x) return;
            // SEAL rejects widths above 60 in PlainModulus::Batching; the
            // caller catches that and continues to the next smaller width.
            for (int bits = static_cast<int>(min(requestedBits, 60u)); bits >= 2; --bits)
            {
                const u64 candidate = rawSetupSealPrimeAtRank(n, bits, 0u);
                if (candidate && candidate < minimumQ)
                {
                    *prime = candidate;
                    *selectedBits = static_cast<u32>(bits);
                    return;
                }
            }
            *prime = 0;
            *selectedBits = 0;
            atomicOr(status, 1u);
        }

        __global__ void rawSetupSelectSealPlainFromQKernel(u32 n, u32 requestedBits,
            const u64* orderedQ, u32 rho, const u32* coefficientStatus,
            const u32* ringStatus,
            u64* prime, u32* selectedBits, u32* status)
        {
            if (threadIdx.x) return;
            *prime = 0;
            *selectedBits = 0;
            if (*coefficientStatus || *ringStatus)
            {
                atomicOr(status, 1u);
                return;
            }
            u64 minimumQ = ~u64{0};
            for (u32 j = 0; j < rho; ++j)
            {
                const u64 q = orderedQ[j];
                if (q <= 2u * n || q >= (u64{1} << 60))
                {
                    atomicOr(status, 2u);
                    return;
                }
                minimumQ = min(minimumQ, q);
            }
            for (int bits = static_cast<int>(min(requestedBits, 60u)); bits >= 2; --bits)
            {
                const u64 candidate = rawSetupSealPrimeAtRank(n, bits, 0u);
                if (candidate && candidate < minimumQ)
                {
                    *prime = candidate;
                    *selectedBits = static_cast<u32>(bits);
                    return;
                }
            }
            atomicOr(status, 4u);
        }

        __global__ void rawSetupPlaintextLiftKernel(RingDeviceConstView rc,
            u64 plaintextPrime, u64* residues, u32* status)
        {
            __shared__ u64 quotient[kMaxRawSetupWords];
            if (threadIdx.x == 0)
            {
                const auto plain = rawSetupModulus(plaintextPrime);
                const Wide ratio{plain.mRatio0, plain.mRatio1};
                u64 remainder = 0;
                for (int limb = static_cast<int>(rc.mRho) - 1; limb >= 0; --limb)
                {
                    Wide value{};
                    divModWide(Wide{rc.mBaseProd[limb], remainder},
                        plaintextPrime, ratio, &value, &remainder);
                    if (value.mHi) atomicOr(status, 2u);
                    quotient[limb] = value.mLo;
                }
                if (remainder >= plaintextPrime) atomicOr(status, 4u);
            }
            __syncthreads();
            const u32 j = threadIdx.x;
            if (j >= rc.mRho || *status) return;
            const auto mod = static_cast<const GpuModulus*>(rc.mMods)[j];
            u64 value = 0;
            const Wide ratio{mod.mRatio0, mod.mRatio1};
            for (int limb = static_cast<int>(rc.mRho) - 1; limb >= 0; --limb)
            {
                Wide ignored{};
                divModWide(Wide{quotient[limb], value}, mod.mValue,
                    ratio, &ignored, &value);
            }
            residues[j] = value;
        }

        __global__ void rawSetupPlaintextLiftFromDeviceKernel(RingDeviceConstView rc,
            const u64* orderedQ, const u64* selectedP, u64* residues,
            const u32* fiveStatuses)
        {
            __shared__ u64 quotient[kMaxRawSetupWords];
            __shared__ u64 plaintextPrime;
            u32* status = const_cast<u32*>(fiveStatuses + 4u);
            if (threadIdx.x == 0)
            {
                plaintextPrime = *selectedP;
                u64 minimumQ = ~u64{0};
                for (u32 j = 0; j < rc.mRho; ++j) minimumQ = min(minimumQ, orderedQ[j]);
                if (fiveStatuses[0] || fiveStatuses[1] || fiveStatuses[2] ||
                    fiveStatuses[3] || plaintextPrime <= 2u * rc.mN ||
                    plaintextPrime >= minimumQ)
                    atomicOr(status, 1u);
                else
                {
                    // Never divide by an invalid or zero selected prime. The
                    // producer and all prerequisite kernels share one stream.
                    const auto plain = rawSetupModulus(plaintextPrime);
                    const Wide ratio{plain.mRatio0, plain.mRatio1};
                    u64 remainder = 0;
                    for (int limb = static_cast<int>(rc.mRho) - 1; limb >= 0; --limb)
                    {
                        Wide value{};
                        divModWide(Wide{rc.mBaseProd[limb], remainder},
                            plaintextPrime, ratio, &value, &remainder);
                        if (value.mHi) atomicOr(status, 2u);
                        quotient[limb] = value.mLo;
                    }
                    if (remainder >= plaintextPrime) atomicOr(status, 4u);
                }
            }
            __syncthreads();
            const u32 j = threadIdx.x;
            if (j >= rc.mRho || *status) return;
            const auto mod = static_cast<const GpuModulus*>(rc.mMods)[j];
            u64 value = 0;
            const Wide ratio{mod.mRatio0, mod.mRatio1};
            for (int limb = static_cast<int>(rc.mRho) - 1; limb >= 0; --limb)
            {
                Wide ignored{};
                divModWide(Wide{quotient[limb], value}, mod.mValue,
                    ratio, &ignored, &value);
            }
            residues[j] = value;
        }

        __global__ void rawSetupModuliKernel(RingDeviceConstView rc, const u64* primes,
            u64* scratch, u32* status, const u32* upstreamStatus)
        {
            const u32 j = threadIdx.x;
            if (j >= rc.mRho) return;
            if (upstreamStatus && *upstreamStatus)
            {
                atomicOr(status, 8u);
                return;
            }
            const u64 q = primes[j];
            if (q <= 2u * rc.mN || q >= (u64{1} << 60) || (q - 1u) % (2u * rc.mN))
            {
                atomicOr(status, 4u);
                return;
            }
            const GpuModulus mod = rawSetupModulus(q);
            static_cast<GpuModulus*>(const_cast<void*>(rc.mMods))[j] = mod;
            if (!rawSetupIsPrime(mod)) { atomicOr(status, 1u); return; }

            // Any primitive 2N-th root generates the same set of odd powers.
            // Its minimum is therefore exactly SEAL's selected root, regardless
            // of SEAL's randomized search seed. A bounded search may decline.
            for (u64 base = 2; base < 4096; ++base)
            {
                const u64 root = rawSetupPow(base, (q - 1) / (2u * rc.mN), mod);
                if (rawSetupPow(root, rc.mN, mod) == q - 1)
                {
                    scratch[j] = root;
                    scratch[rc.mRho + j] = root;
                    return;
                }
            }
            atomicOr(status, 2u);
        }

        __global__ void rawSetupMinimumRootsKernel(RingDeviceConstView rc,
            u64* scratch, const u32* status)
        {
            const u32 i = blockIdx.x * blockDim.x + threadIdx.x;
            const u32 j = blockIdx.y;
            if (i >= rc.mN || *status) return;
            const auto mod = static_cast<const GpuModulus*>(rc.mMods)[j];
            u64 root = rawSetupPow(scratch[j], 2u * i + 1u, mod);
            const u32 lanes = __activemask();
            const u32 lane = threadIdx.x & 31u;
            for (u32 offset = 16; offset; offset >>= 1)
            {
                const u64 other = __shfl_down_sync(lanes, static_cast<unsigned long long>(root), offset);
                if (lane + offset < 32 && (lanes & (1u << (lane + offset))))
                    root = root < other ? root : other;
            }
            if (lane == 0)
                atomicMin(reinterpret_cast<unsigned long long*>(scratch + rc.mRho + j),
                    static_cast<unsigned long long>(root));
        }

        __global__ void rawSetupNttScalarsKernel(RingDeviceConstView rc,
            u64* scratch, const u32* status)
        {
            const u32 j = threadIdx.x;
            if (j >= rc.mRho || *status) return;
            const auto mod = static_cast<const GpuModulus*>(rc.mMods)[j];
            const u64 inverseRoot = rawSetupPow(scratch[rc.mRho + j], mod.mValue - 2, mod);
            scratch[2u * rc.mRho + j] = inverseRoot;
            const u64 inverseDegree = rawSetupPow(rc.mN, mod.mValue - 2, mod);
            static_cast<ShoupOperand*>(const_cast<void*>(rc.mInvDegree))[j] =
                rawSetupShoup(inverseDegree, mod);
            // SEAL inverse table index N-1 contains inverseRoot^(N/2).
            const u64 lastRoot = rawSetupPow(inverseRoot, rc.mN / 2u, mod);
            static_cast<ShoupOperand*>(const_cast<void*>(rc.mScaledInvRoot))[j] =
                rawSetupShoup(mulMod(lastRoot, inverseDegree, mod), mod);
        }

        __global__ void rawSetupNttTablesKernel(RingDeviceConstView rc,
            const u64* scratch, const u32* status)
        {
            const u32 i = blockIdx.x * blockDim.x + threadIdx.x;
            const u32 j = blockIdx.y;
            if (i >= rc.mN || *status) return;
            const auto mod = static_cast<const GpuModulus*>(rc.mMods)[j];
            const std::size_t start = static_cast<std::size_t>(j) * rc.mN;
            const u32 forward = __brev(i) >> (32u - rc.mLogN);
            const u32 inverse = i ? (__brev(i - 1u) >> (32u - rc.mLogN)) + 1u : 0u;
            const u64 root = rawSetupPow(scratch[rc.mRho + j], i, mod);
            const u64 invRoot = rawSetupPow(scratch[2u * rc.mRho + j], i, mod);
            static_cast<ShoupOperand*>(const_cast<void*>(rc.mRoots))[start + forward] =
                rawSetupShoup(root, mod);
            static_cast<ShoupOperand*>(const_cast<void*>(rc.mInvRoots))[start + inverse] =
                rawSetupShoup(invRoot, mod);
            if (rc.mFp52InvRoots) const_cast<double*>(rc.mFp52InvRoots)[start + inverse] = static_cast<double>(invRoot);
        }

        __device__ void rawSetupProduct(const u64* primes, u32 rho, u32 excluded, u64* out)
        {
            for (u32 k = 0; k < rho; ++k) out[k] = k == 0 ? 1 : 0;
            for (u32 w = 0; w < rho; ++w)
            {
                if (w == excluded) continue;
                u64 carry = 0;
                for (u32 k = 0; k < rho; ++k)
                {
                    const u64 low = out[k] * primes[w];
                    const u64 high = mulHi64(out[k], primes[w]);
                    out[k] = low + carry;
                    carry = high + (out[k] < low);
                }
            }
        }

        __global__ void rawSetupCrtKernel(RingDeviceConstView rc, DenoiseConstView dc,
            u64* crtLift, u64* invCrtLift, u64* sampleMax, const u32* status)
        {
            const u32 j = threadIdx.x;
            const u32 rho = rc.mRho;
            if (j >= rho || *status) return;
            const auto* mods = static_cast<const GpuModulus*>(rc.mMods);
            const auto mod = mods[j];
            const auto* primes = dc.mQ;
            if (j == 0)
            {
                u64 product[kMaxRawSetupWords];
                rawSetupProduct(primes, rho, rho, product);
                for (u32 k = 0; k < rho; ++k)
                {
                    const_cast<u64*>(rc.mBaseProd)[k] = product[k];
                    const_cast<u64*>(rc.mBaseProdHalf)[k] = (product[k] >> 1) |
                        (k + 1 < rho ? product[k + 1] << 63 : 0);
                }
            }
            rawSetupProduct(primes, rho, j, const_cast<u64*>(rc.mPuncturedProd) + j * rho);
            u64 lift = 1;
            for (u32 w = 0; w < rho; ++w)
                if (w != j) lift = mulMod(lift, barrettReduce64(primes[w], mod), mod);
            const u64 inverseLift = rawSetupPow(lift, mod.mValue - 2, mod);
            crtLift[j] = lift;
            invCrtLift[j] = inverseLift;
            const auto inverseLiftOp = rawSetupShoup(inverseLift, mod);
            static_cast<ShoupOperand*>(const_cast<void*>(rc.mInvPuncturedProd))[j] = inverseLiftOp;
            sampleMax[j] = ~u64{0} - barrettReduce64(~u64{0}, mod) - 1u;
            for (u32 w = 0; w < rho; ++w)
            {
                static_cast<ShoupOperand*>(const_cast<void*>(rc.mGarnerInv))[j * rho + w] =
                    w < j ? rawSetupShoup(rawSetupPow(primes[w], mod.mValue - 2, mod), mod)
                          : ShoupOperand{0, 0};
            }
            if (rho < 2) return;
            static_cast<ShoupOperand*>(const_cast<void*>(dc.mInvCrtLiftShoup))[j] = inverseLiftOp;
            u32 reducedIndex = 0;
            for (u32 w = 0; w < rho; ++w)
            {
                if (w == j) continue;
                const u32 ci = j * (rho - 1u) + reducedIndex++;
                const auto sourceMod = mods[w];
                u64 sourceProduct = 1, targetProduct = 1;
                for (u32 u = 0; u < rho; ++u)
                {
                    if (u == j || u == w) continue;
                    sourceProduct = mulMod(sourceProduct, barrettReduce64(primes[u], sourceMod), sourceMod);
                    targetProduct = mulMod(targetProduct, barrettReduce64(primes[u], mod), mod);
                }
                const u64 sourceInverse = rawSetupPow(sourceProduct, sourceMod.mValue - 2, sourceMod);
                const_cast<u32*>(dc.mSrcLimb)[ci] = w;
                const_cast<u64*>(dc.mCrtInvPunctured)[ci] = sourceInverse;
                const_cast<u64*>(dc.mPuncturedProdModTarget)[ci] = targetProduct;
                static_cast<ShoupOperand*>(const_cast<void*>(dc.mCrtInvPuncturedShoup))[ci] =
                    rawSetupShoup(sourceInverse, sourceMod);
                static_cast<ShoupOperand*>(const_cast<void*>(dc.mScaledPuncturedShoup))[ci] =
                    rawSetupShoup(mulMod(targetProduct, inverseLift, mod), mod);
                const_cast<u64*>(dc.mFracInvLo)[ci] = sourceMod.mRatio0;
                const_cast<u64*>(dc.mFracInvHi)[ci] = sourceMod.mRatio1;
            }
        }

        __global__ void rawSetupSlotMapsKernel(u32 n, u32 logN,
            u32* map, u32* inverseMap, const u32* upstreamStatus)
        {
            if (upstreamStatus && *upstreamStatus) return;
            const u32 i = blockIdx.x * blockDim.x + threadIdx.x;
            if (i >= n / 2u) return;
            const u64 mask = 2u * n - 1u;
            u64 pos = 1, base = 3;
            for (u32 exponent = i; exponent; exponent >>= 1)
            {
                if (exponent & 1u) pos = (pos * base) & mask;
                base = (base * base) & mask;
            }
            const u32 first = __brev(static_cast<u32>((pos - 1u) / 2u)) >> (32u - logN);
            const u32 second = __brev(static_cast<u32>((2u * n - pos - 1u) / 2u)) >> (32u - logN);
            map[i] = first;
            map[n / 2u + i] = second;
            inverseMap[first] = i;
            inverseMap[second] = n / 2u + i;
        }

        __global__ void rawSetupPow2Kernel(RingDeviceConstView rc, u32 shift, u64* factors)
        {
            const u32 j = threadIdx.x;
            if (j < rc.mRho)
                factors[j] = rawSetupPow(2, shift, static_cast<const GpuModulus*>(rc.mMods)[j]);
        }

        __global__ void rawSetupScaleRoundKernel(RingDeviceConstView rc, u64 p, ScaleRoundConstView out)
        {
            const u32 j = threadIdx.x;
            if (j >= rc.mRho) return;
            const auto mod = static_cast<const GpuModulus*>(rc.mMods)[j];
            const auto inv = static_cast<const ShoupOperand*>(rc.mInvPuncturedProd)[j];
            const u64 pShoup = rawSetupShoup(p, mod).mQuotient;
            const_cast<u64*>(out.mQ)[j] = mod.mValue;
            const_cast<u64*>(out.mCrtInvPunctured)[j] = inv.mOperand;
            const_cast<u64*>(out.mPShoup)[j] = pShoup;
            const_cast<u64*>(out.mFracLo)[j] = mod.mRatio0;
            const_cast<u64*>(out.mFracHi)[j] = mod.mRatio1;
            const_cast<ScaleRoundFastLimb*>(out.mFastLimbs)[j] =
                ScaleRoundFastLimb{mod.mValue, mod.mRatio1, inv.mOperand,
                    inv.mQuotient, pShoup, mod.mRatio0, mod.mRatio1};
        }

        bool log14H200Shape(const RingConstView& rc)
        {
            return rc.mH200Shared &&
                rc.mN == 16384u && rc.mLogN == 14u && rc.mRho == 8u;
        }

        inline bool check(cudaError_t e, const char* where)
        {
            if (e != cudaSuccess)
            {
                // Consume only this reported failure, preserving any distinct
                // asynchronous error for its own operation boundary.
                if (cudaPeekAtLastError() == e) (void)cudaGetLastError();
                throw std::runtime_error(std::string(where) + " (CUDA " + std::to_string(static_cast<int>(e)) + "): " + cudaGetErrorString(e));
            }
            return true;
        }

        inline cudaStream_t asStream(void* s)
        {
            return static_cast<cudaStream_t>(s);
        }



        bool configureH200RootPersistence(const RingConstView& rc, void* stream, bool inverse)
        {
#if CUDART_VERSION >= 11000
            const u32 mode = rc.mKernelOptions.mNoGoldH200RootL2Mode;
            if (!(mode & (inverse ? 1u : 2u)) || !log14H200Shape(rc)) return true;
            const size_t maxWindow = rc.mH200RootL2MaxWindow;
            if (!maxWindow) return true;
            const double* packed = inverse ? rc.mFp52InvRoots : nullptr;
            const void* roots = packed ? static_cast<const void*>(packed) : inverse ? rc.mInvRoots : rc.mRoots;
            const size_t bytes = static_cast<size_t>(rc.mRho) * rc.mN * (packed ? sizeof(double) : sizeof(ShoupOperand));
            if (!roots || bytes > maxWindow) return true;
            cudaStreamAttrValue value{};
            value.accessPolicyWindow.base_ptr = const_cast<void*>(roots);
            value.accessPolicyWindow.num_bytes = bytes;
            value.accessPolicyWindow.hitRatio = rc.mKernelOptions.mRootL2HitPercent * 0.01f;
            value.accessPolicyWindow.hitProp = cudaAccessPropertyPersisting;
            value.accessPolicyWindow.missProp = cudaAccessPropertyNormal;
            // Include these per-launch host calls in every timed comparison;
            // there is no cache keyed by potentially recycled stream handles.
            return check(cudaStreamSetAttribute(asStream(stream), cudaStreamAttributeAccessPolicyWindow, &value),
                "root L2 stream window");
#else
            return true;
#endif
        }

        // ---- multi-precision device helpers (mirror seal::util) -----------

        // Every helper below is templated on the word count and takes the
        // register-resident values by reference to a fixed-size array, so that no
        // index into them is ever computed at run time.
        //
        // That is not a style preference. The gadget decomposition's shift amounts
        // come from kernel arguments (`digitBits`, `startLevel`), and the previous
        // runtime-`w` helpers indexed the local arrays by `i + wordShift`. A local
        // array with even one runtime index has to live in local memory, and
        // `gadgetDecomposeKernelT<4>` carried a **192-byte stack frame with zero
        // spills** as a result - the frame was not spilled registers, it was the
        // multi-precision temporaries themselves, and every access to them went to
        // L1. On a kernel that is compute bound (it runs at 239 GiB/s against a
        // ~600 GiB/s roof) that is the dominant cost.
        //
        // The fix is to replace dynamic indexing with an unrolled W-way predicated
        // select, which is W comparisons instead of a local-memory access. Results
        // are bit-identical: only where the words live changes.

        // v[idx], or 0 when idx is out of range. Unrolled, so every index is a
        // compile-time constant.
        template<u32 W>
        __device__ inline u64 mpPick(const u64 (&v)[W], u32 idx)
        {
            u64 r = 0;
#pragma unroll
            for (u32 k = 0; k < W; ++k)
            {
                if (k == idx) r = v[k];
            }
            return r;
        }

        template<u32 W>
        __device__ inline void mpSetZero(u64 (&a)[W])
        {
#pragma unroll
            for (u32 i = 0; i < W; ++i) a[i] = 0;
        }

        template<u32 W>
        __device__ inline void mpCopy(const u64 (&src)[W], u64 (&dst)[W])
        {
#pragma unroll
            for (u32 i = 0; i < W; ++i) dst[i] = src[i];
        }

        // Mirrors seal::util::add_uint; returns carry.
        template<u32 W>
        __device__ inline unsigned char mpAdd(const u64 (&a)[W], const u64 (&b)[W], u64 (&out)[W])
        {
            unsigned char carry = 0;
#pragma unroll
            for (u32 i = 0; i < W; ++i)
            {
                u64 t;
                unsigned char c0 = addU64(a[i], b[i], &t);
                u64 t2;
                unsigned char c1 = addU64(t, static_cast<u64>(carry), &t2);
                out[i] = t2;
                carry = static_cast<unsigned char>(c0 | c1);
            }
            return carry;
        }

        // Mirrors seal::util::sub_uint; returns borrow. The `G` suffix takes the
        // subtrahend from global memory (a ring constant), the plain form takes two
        // register values.
        template<u32 W>
        __device__ inline unsigned char mpSubG(const u64 (&a)[W], const u64* b, u64 (&out)[W])
        {
            unsigned char borrow = 0;
#pragma unroll
            for (u32 i = 0; i < W; ++i)
            {
                const u64 ai = a[i];
                const u64 bi = b[i];
                u64 d = ai - bi;
                unsigned char b0 = static_cast<unsigned char>(ai < bi);
                u64 d2 = d - static_cast<u64>(borrow);
                unsigned char b1 = static_cast<unsigned char>(d < static_cast<u64>(borrow));
                out[i] = d2;
                borrow = static_cast<unsigned char>(b0 | b1);
            }
            return borrow;
        }

        template<u32 W>
        __device__ inline unsigned char mpSub(const u64 (&a)[W], const u64 (&b)[W], u64 (&out)[W])
        {
            unsigned char borrow = 0;
#pragma unroll
            for (u32 i = 0; i < W; ++i)
            {
                const u64 ai = a[i];
                const u64 bi = b[i];
                u64 d = ai - bi;
                unsigned char b0 = static_cast<unsigned char>(ai < bi);
                u64 d2 = d - static_cast<u64>(borrow);
                unsigned char b1 = static_cast<unsigned char>(d < static_cast<u64>(borrow));
                out[i] = d2;
                borrow = static_cast<unsigned char>(b0 | b1);
            }
            return borrow;
        }

        // a >= b ? / a > b ?, with b in global memory.
        template<u32 W>
        __device__ inline bool mpGreaterEqualG(const u64 (&a)[W], const u64* b)
        {
#pragma unroll
            for (u32 i = W; i-- > 0;)
            {
                if (a[i] != b[i]) return a[i] > b[i];
            }
            return true;
        }

        template<u32 W>
        __device__ inline bool mpGreaterG(const u64 (&a)[W], const u64* b)
        {
#pragma unroll
            for (u32 i = W; i-- > 0;)
            {
                if (a[i] != b[i]) return a[i] > b[i];
            }
            return false;
        }

        // Mirrors seal::util::multiply_uint(op1[w], scalar, w, out): truncated
        // W-word product. `a` is a ring constant in global memory.
        template<u32 W>
        __device__ inline void mpMulScalarG(const u64* a, u64 scalar, u64 (&out)[W])
        {
            u64 carry = 0;
#pragma unroll
            for (u32 i = 0; i < W; ++i)
            {
                const u64 lo = a[i] * scalar;
                const u64 hi = mulHi64(a[i], scalar);
                u64 t;
                const unsigned char c = addU64(lo, carry, &t);
                out[i] = t;
                carry = hi + static_cast<u64>(c);
            }
        }

        // Same as mpMulScalarG for a register-resident multiplicand.
        template<u32 W>
        __device__ inline void mpMulScalar(const u64 (&a)[W], u64 scalar, u64 (&out)[W])
        {
            u64 carry = 0;
#pragma unroll
            for (u32 i = 0; i < W; ++i)
            {
                const u64 lo = a[i] * scalar;
                const u64 hi = mulHi64(a[i], scalar);
                u64 t;
                const unsigned char c = addU64(lo, carry, &t);
                out[i] = t;
                carry = hi + static_cast<u64>(c);
            }
        }

        // Mirrors seal::util::add_uint_uint_mod.
        template<u32 W>
        __device__ inline void mpAddMod(
            const u64 (&a)[W], const u64 (&b)[W], const u64* mod, u64 (&out)[W])
        {
            const unsigned char carry = mpAdd(a, b, out);
            if (carry || mpGreaterEqualG(out, mod))
            {
                mpSubG(out, mod, out);
            }
        }

        // Mirrors seal::util::right_shift_uint (logical). Word-shift selection is an
        // unrolled select rather than an index, see the note above.
        template<u32 W>
        __device__ inline void mpShiftRight(u64 (&v)[W], u32 shift)
        {
            if (shift == 0) return;
            const u32 wordShift = shift >> 6;
            const u32 bitShift = shift & 63u;
            u64 out[W];
#pragma unroll
            for (u32 i = 0; i < W; ++i)
            {
                // Out of range reads give zero, which is exactly the zero fill the
                // pointer version did in its trailing loop.
                u64 r = mpPick(v, i + wordShift);
                if (bitShift != 0)
                {
                    r >>= bitShift;
                    r |= mpPick(v, i + wordShift + 1u) << (64u - bitShift);
                }
                out[i] = r;
            }
#pragma unroll
            for (u32 i = 0; i < W; ++i) v[i] = out[i];
        }

        // Mirrors LogVoleRing.cpp arithmeticRightShift (sign-extending).
        template<u32 W>
        __device__ inline void mpShiftRightArith(u64 (&v)[W], u32 shift)
        {
            if (shift == 0) return;
            const bool negative = (v[W - 1] >> 63) != 0;
            constexpr u64 totalBits = static_cast<u64>(W) * 64ull;
            if (shift >= totalBits)
            {
                const u64 fill = negative ? ~u64(0) : u64(0);
#pragma unroll
                for (u32 i = 0; i < W; ++i) v[i] = fill;
                return;
            }
            mpShiftRight(v, shift);
            if (!negative) return;

            const u64 firstFillBit = totalBits - shift;
            const u32 firstFillLimb = static_cast<u32>(firstFillBit / 64ull);
            const u32 firstFillOffset = static_cast<u32>(firstFillBit % 64ull);
#pragma unroll
            for (u32 i = 0; i < W; ++i)
            {
                if (i == firstFillLimb)
                {
                    v[i] |= (firstFillOffset != 0) ? (~u64(0) << firstFillOffset) : ~u64(0);
                }
                else if (i > firstFillLimb)
                {
                    v[i] = ~u64(0);
                }
            }
        }

        // Mirrors LogVoleRing.cpp maskLowBits.
        template<u32 W>
        __device__ inline void mpMaskLowBits(u64 (&v)[W], u32 bitCount)
        {
#pragma unroll
            for (u32 i = 0; i < W; ++i)
            {
                const u64 bitOffset = static_cast<u64>(i) * 64ull;
                if (bitOffset >= bitCount)
                {
                    v[i] = 0;
                }
                else if (bitOffset + 64ull > bitCount)
                {
                    const u32 remaining = bitCount - static_cast<u32>(bitOffset);
                    v[i] &= (u64(1) << remaining) - 1ull;
                }
            }
        }

        // Mirrors seal::util::modulo_uint.
        template<u32 W>
        __device__ inline u64 mpModulo(const u64 (&v)[W], const GpuModulus& mod)
        {
            if constexpr (W == 1)
            {
                return (v[0] < mod.mValue) ? v[0] : barrettReduce64(v[0], mod);
            }
            else
            {
                u64 hi = v[W - 1];
#pragma unroll
                for (u32 k = W - 1; k-- > 0;)
                {
                    hi = barrettReduce128(v[k], hi, mod);
                }
                return hi;
            }
        }

        // A plaintext prime can be smaller than the top word of Q, especially
        // for dynamic mixed-width rings. Reduce that first word before the
        // 128-bit Barrett chain, exactly as seal::util::modulo_uint does.
        template<u32 W>
        __device__ inline u64 mpModuloPlain(const u64 (&v)[W], const GpuModulus& mod)
        {
            u64 hi = barrettReduce64(v[W - 1u], mod);
#pragma unroll
            for (u32 k = W - 1u; k-- > 0u;)
                hi = barrettReduce128(v[k], hi, mod);
            return hi;
        }

        // mpModulo for a value the caller knows fits in `words` low words: the
        // Barrett chain runs over those only. Same result, W - words fewer 128-bit
        // reductions.
        //
        // This is what the gadget decomposition needs. Its value is a full log q
        // wide (8 words at log q = 416), but the *digits* it reduces per limb are
        // only digitBits wide - 208 bits, so 4 words - and the chain was running
        // over all 8 regardless. `words` comes from a kernel argument, so it is
        // uniform across the grid and the skipped iterations are uniform branches.
        template<u32 W>
        __device__ inline u64 mpModuloBounded(const u64 (&v)[W], const GpuModulus& mod, u32 words)
        {
            if constexpr (W == 1)
            {
                return (v[0] < mod.mValue) ? v[0] : barrettReduce64(v[0], mod);
            }
            else
            {
                u64 hi = mpPick(v, words - 1u);
#pragma unroll
                for (u32 k = W - 1; k-- > 0;)
                {
                    if (k + 1u < words) hi = barrettReduce128(v[k], hi, mod);
                }
                return hi;
            }
        }

        // Mixed-radix (Garner) composition of the same integer crtCompose produces.
        //
        //   v_0 = x_0
        //   v_i = ((x_i - v_0) q_0^-1 - v_1) q_1^-1 - ... mod q_i
        //   x   = v_0 + q_0 (v_1 + q_1 (v_2 + ...))
        //
        // The first pass is rho(rho-1)/2 single-word modular multiplies, against
        // crtCompose's one Shoup multiply plus a W-word multiply-accumulate and a
        // W-word conditional subtract per limb. The second pass is a W-word Horner
        // chain with no reduction at all, because Garner's form is already the
        // unique representative below the base product.
        //
        // Same integer, so every digit downstream is identical.
        template<u32 W>
        __device__ inline void garnerCompose(
            const u64* residues,     // [rho], stride applied
            u32 stride,
            const GpuModulus* mods,
            const ShoupOperand* garnerInv,  // [rho][rho], q_j^-1 mod q_i at [i*W + j]
            u64 (&out)[W])
        {
            u64 v[W];
#pragma unroll
            for (u32 i = 0; i < W; ++i)
            {
                const GpuModulus mod = mods[i];
                u64 t = barrettReduce64(residues[static_cast<size_t>(i) * stride], mod);
#pragma unroll
                for (u32 j = 0; j < W; ++j)
                {
                    if (j < i)
                    {
                        const u64 vj = barrettReduce64(mpPick(v, j), mod);
                        t = mulShoup(subMod(t, vj, mod.mValue), garnerInv[i * W + j], mod.mValue);
                    }
                }
                v[i] = t;
            }

            // Horner over the moduli, most significant digit first.
            mpSetZero(out);
#pragma unroll
            for (u32 i = W; i-- > 0;)
            {
                if (i + 1u < W)
                {
                    u64 scaled[W];
                    mpMulScalar(out, mods[i].mValue, scaled);
                    mpCopy(scaled, out);
                }
                u64 digit[W];
                mpSetZero(digit);
                digit[0] = v[i];
                u64 sum[W];
                mpAdd(out, digit, sum);
                mpCopy(sum, out);
            }
        }

        // Mirrors seal::util::RNSBase::compose_array for a single coefficient.
        template<u32 W>
        __device__ inline void crtCompose(
            const u64* residues,     // [rho], stride already applied
            u32 stride,
            const GpuModulus* mods,
            const ShoupOperand* invPunctured,
            const u64* puncturedProd, // [rho][rho]
            const u64* baseProd,      // [rho]
            u64 (&out)[W])
        {
            mpSetZero(out);
            u64 tmp[W];
#pragma unroll
            for (u32 j = 0; j < W; ++j)
            {
                const u64 v = residues[static_cast<size_t>(j) * stride];
                const u64 tempProd = mulShoup(v, invPunctured[j], mods[j].mValue);
                mpMulScalarG(puncturedProd + static_cast<size_t>(j) * W, tempProd, tmp);
                mpAddMod(out, tmp, baseProd, out);
            }
        }

        // Fixed rho=4, q_j<2^55 CRT helpers. For P_j=Q/q_j, P_j<2^165, so
        // P_j[3] is exactly zero. Multiplication still produces four words: the
        // final word is the carry/high half from P_j[2] * scalar.
        __device__ __forceinline__ void mpMulPuncturedRho4Compact55(
            const u64* punctured, u64 scalar, u64 (&out)[4])
        {
            u64 carry = 0;
#pragma unroll
            for (u32 i = 0; i < 3u; ++i)
            {
                const u64 a = punctured[i];
                const u64 lo = a * scalar;
                const u64 hi = mulHi64(a, scalar);
                u64 word;
                const unsigned char c = addU64(lo, carry, &word);
                out[i] = word;
                carry = hi + static_cast<u64>(c);
            }
            out[3] = carry;
        }

        // Both operands are canonical modulo Q and Q<2^220, hence their sum is
        // below 2^221. The word carry chain is still required, but a carry out of
        // word three is impossible and need not enter the reduction predicate.
        __device__ __forceinline__ void mpAddModRho4NoWideOverflow(
            const u64 (&a)[4], const u64 (&b)[4], const u64* mod, u64 (&out)[4])
        {
            unsigned char carry = 0;
#pragma unroll
            for (u32 i = 0; i < 4u; ++i)
            {
                u64 t;
                const unsigned char c0 = addU64(a[i], b[i], &t);
                u64 sum;
                const unsigned char c1 = addU64(t, static_cast<u64>(carry), &sum);
                out[i] = sum;
                carry = static_cast<unsigned char>(c0 | c1);
            }
            if (mpGreaterEqualG(out, mod))
            {
                mpSubG(out, mod, out);
            }
        }

        __device__ __forceinline__ void crtComposeRho4Compact55(
            const u64* residues,
            u32 stride,
            const GpuModulus* mods,
            const ShoupOperand* invPunctured,
            const u64* puncturedProd,
            const u64* baseProd,
            u64 (&out)[4])
        {
            // tempProd<q_0 makes tempProd*P_0<Q, so the first term is already a
            // canonical accumulator and needs neither an add nor a subtraction.
            const u64 first = mulShoup(
                residues[0], invPunctured[0], mods[0].mValue);
            mpMulPuncturedRho4Compact55(puncturedProd, first, out);

            u64 tmp[4];
#pragma unroll
            for (u32 j = 1; j < 4u; ++j)
            {
                const u64 v = residues[static_cast<size_t>(j) * stride];
                const u64 tempProd =
                    mulShoup(v, invPunctured[j], mods[j].mValue);
                mpMulPuncturedRho4Compact55(
                    puncturedProd + static_cast<size_t>(j) * 4u,
                    tempProd,
                    tmp);
                mpAddModRho4NoWideOverflow(out, tmp, baseProd, out);
            }
        }

        // The sparse recursive-leaf parent has one of two compile-time-fixed
        // active pairs. Each scaled punctured product is individually below Q,
        // so the first is already a canonical accumulator and the second needs
        // exactly one addition modulo Q. Compile-time limb indices are critical:
        // a runtime-indexed local array would move these words to local memory.
        template<u32 First>
        __device__ __forceinline__ void crtComposeRho4Compact55Pair(
            const u64* residues,
            u32 stride,
            const GpuModulus* mods,
            const ShoupOperand* invPunctured,
            const u64* puncturedProd,
            const u64* baseProd,
            u64 (&out)[4])
        {
            static_assert(First == 0u || First == 2u);
            constexpr u32 Second = First + 1u;

            const u64 first = mulShoup(
                residues[static_cast<size_t>(First) * stride],
                invPunctured[First],
                mods[First].mValue);
            mpMulPuncturedRho4Compact55(
                puncturedProd + static_cast<size_t>(First) * 4u,
                first,
                out);

            const u64 second = mulShoup(
                residues[static_cast<size_t>(Second) * stride],
                invPunctured[Second],
                mods[Second].mValue);
            u64 tmp[4];
            mpMulPuncturedRho4Compact55(
                puncturedProd + static_cast<size_t>(Second) * 4u,
                second,
                tmp);
            mpAddModRho4NoWideOverflow(out, tmp, baseProd, out);
        }

        // ---- NTT ----------------------------------------------------------

        struct DeviceRing
        {
            u32 mN;
            u32 mLogN;
            u32 mRho;
            const GpuModulus* mMods;
            const ShoupOperand* mRoots;
            const ShoupOperand* mInvRoots;
            const ShoupOperand* mInvDegree;
            const ShoupOperand* mScaledInvRoot;
            const u64* mBaseProd;
            const u64* mBaseProdHalf;
            const u64* mPuncturedProd;
            const ShoupOperand* mInvPuncturedProd;
            const ShoupOperand* mGarnerInv;
        };

        // Only the four tables used by a fixed inverse. Keeping the unrelated
        // ring pointers out of the sidecar kernels makes the load phase a hard,
        // compact lifetime before the 32-register transform body.
        struct DeviceInverseRho4
        {
            const GpuModulus* mMods;
            const ShoupOperand* mInvRoots;
            const ShoupOperand* mInvDegree;
            const ShoupOperand* mScaledInvRoot;
        };

        inline DeviceRing toDevice(const RingConstView& rc)
        {
            DeviceRing d{};
            d.mN = rc.mN;
            d.mLogN = rc.mLogN;
            d.mRho = rc.mRho;
            d.mMods = static_cast<const GpuModulus*>(rc.mMods);
            d.mRoots = static_cast<const ShoupOperand*>(rc.mRoots);
            d.mInvRoots = static_cast<const ShoupOperand*>(rc.mInvRoots);
            d.mInvDegree = static_cast<const ShoupOperand*>(rc.mInvDegree);
            d.mScaledInvRoot = static_cast<const ShoupOperand*>(rc.mScaledInvRoot);
            d.mBaseProd = rc.mBaseProd;
            d.mBaseProdHalf = rc.mBaseProdHalf;
            d.mPuncturedProd = rc.mPuncturedProd;
            d.mInvPuncturedProd = static_cast<const ShoupOperand*>(rc.mInvPuncturedProd);
            d.mGarnerInv = static_cast<const ShoupOperand*>(rc.mGarnerInv);
            return d;
        }

        inline DeviceInverseRho4 toDeviceInverseRho4(const RingConstView& rc)
        {
            DeviceInverseRho4 d{};
            d.mMods = static_cast<const GpuModulus*>(rc.mMods);
            d.mInvRoots = static_cast<const ShoupOperand*>(rc.mInvRoots);
            d.mInvDegree = static_cast<const ShoupOperand*>(rc.mInvDegree);
            d.mScaledInvRoot = static_cast<const ShoupOperand*>(rc.mScaledInvRoot);
            return d;
        }

        // Forward negacyclic NTT. Reproduces SEAL's DWTHandler::transform_to_rev
        // followed by the [0,4q) -> [0,q) fixup in ntt_negacyclic_harvey.
        //
        // "No fused operation" for the NTT pre/post hooks. ElemOp values 0..3 are
        // Add/Sub/Negate/Copy, so this is out of band.
        constexpr u32 kElemOpNone = 0xFFFFFFFFu;

        // Largest limb slice held in shared memory, in coefficients. 8192 u64 is
        // 64 KiB, which is the most a block can request on sm_75 and still the
        // largest power of two under the 100 KiB sm_89 opt-in cap. A ring degree
        // above this is transformed in `tiles = n / kNttMaxTileLen` slices; see
        // the tiling note on nttForwardKernel.
        constexpr u32 kNttMaxTileLen = 8192;

        __host__ __device__ inline u32 nttTileCount(u32 n)
        {
            return (n <= kNttMaxTileLen) ? 1u : (n / kNttMaxTileLen);
        }

        // Elements a thread parks in registers in the two-tile transforms: one
        // tile's worth spread over the block, so tileLen == kNttThreads * kInvRegs.
        constexpr u32 kInvRegs = kNttMaxTileLen / kNttThreads;   // 8

        // One block per (polynomial, limb, tile). A tile is a contiguous slice of
        // `tileLen = n / tiles` coefficients of one limb, held in shared memory for
        // the duration of the stages that stay inside it.
        //
        // Tiling works because of the shape of transform_to_rev: at stage s the
        // array is partitioned into m = 2^s contiguous groups and each group is
        // butterflied strictly within itself, so once s reaches log2(tiles) every
        // remaining stage is confined to one tile. The earlier, tile-crossing
        // stages are run by nttForwardCrossKernel in global memory - there are
        // log2(tiles) of them, one launch each.
        //
        // The root index of a local stage follows from the same identity:
        // i_global = tileIdx * m_local + i_local and m_global = tiles * m_local, so
        // roots[m_global + i_global] = roots[m_local * (tiles + tileIdx) + i_local].
        //
        // With tiles == 1 this is the original kernel: one block per (poly, limb),
        // rootIdx = m + i, no extra launches, bit-identical values.
        template<bool CenteredLimb, u32 FixedRho = 0u>
        __device__ __forceinline__ u64 nttForwardLoad(
            DeviceRing rg,
            const u64* sourceLimb,
            u32 selectedLimb,
            u32 targetLimb,
            u32 coeff)
        {
            if constexpr (!CenteredLimb)
            {
                return sourceLimb[coeff];
            }
            else
            {
                const u32 rho = FixedRho == 0u ? rg.mRho : FixedRho;
                if (selectedLimb >= rho) return 0;
                const u64 value = sourceLimb[coeff];
                const u64 qSelected = rg.mMods[selectedLimb].mValue;
                const bool negative = value > (qSelected >> 1u);
                const u64 magnitude = negative ? (qSelected - value) : value;
                const u64 qTarget = rg.mMods[targetLimb].mValue;
                return negative ? (qTarget - magnitude) : magnitude;
            }
        }

        template<bool VectorLoad>
        __device__ __forceinline__ ShoupOperand nttLoadShoup(
            const ShoupOperand* src)
        {
            if constexpr (VectorLoad)
            {
                static_assert(sizeof(ShoupOperand) == sizeof(ulonglong2));
                static_assert(alignof(ulonglong2) == 16u);
                const ulonglong2 packed =
                    *reinterpret_cast<const ulonglong2*>(src);
                return {packed.x, packed.y};
            }
            else
            {
                return *src;
            }
        }

        // One exact forward stage for the fixed one-tile N=8192 transform.
        // Stages 7..11 are warp-local; the other stages retain the block barrier.
        template<
            u32 Stage,
            bool SimpleIndex = false,
            bool VectorShoupLoads = false>
        __device__ __forceinline__ void nttForwardStage8192(
            u64* sh,
            const ShoupOperand* roots,
            u64 q,
            u64 twoQ)
        {
            static_assert(Stage < 13u);
            constexpr u32 logGap = 12u - Stage;
            constexpr u32 gap = 1u << logGap;
            constexpr u32 rootBase = 1u << Stage;
            for (u32 b = threadIdx.x; b < 4096u; b += blockDim.x)
            {
                const u32 i = b >> logGap;
                const u32 j = b & (gap - 1u);
                // b == i*gap + j, so b + i*gap == 2*i*gap + j. Restrict
                // the experiment to S0..S11; S12 either retains its original
                // expression or is owned by the direct-store specialization.
                const u32 ix = SimpleIndex && Stage < 12u
                    ? b + (i << logGap)
                    : (i << (logGap + 1u)) + j;
                const ShoupOperand r = nttLoadShoup<VectorShoupLoads>(
                    roots + rootBase + i);
                const u64 u = nttGuard(sh[ix], twoQ);
                const u64 v = mulShoupLazy(sh[ix + gap], r, q);
                sh[ix] = u + v;
                sh[ix + gap] = u + twoQ - v;
            }
            if constexpr (Stage >= 7u && Stage <= 11u)
                __syncwarp();
            else
                __syncthreads();
        }

        template<
            bool OutOfPlace,
            bool CenteredLimb,
            bool GatherOutput = false,
            bool Fixed8192 = false,
            u32 FixedRho = 0u,
            bool SimpleIndex = false,
            bool VectorShoupLoads = false,
            bool CrossingPrepared = false>
        __global__ void nttForwardKernel(
            DeviceRing rg,
            u64* data,
            const u32* polyIdx,
            u32 logTiles,
            const u64* input,
            const u32* inputIdx,
            const u32* inputLimb,
            const u32* inverseSlotMap = nullptr,
            u32 slotCount = 0,
            u64* gathered = nullptr,
            u64 gatheredCount = 0,
            bool fusedFirstStage = false)
        {
            static_assert(OutOfPlace || !CenteredLimb);
            static_assert(!GatherOutput || (!OutOfPlace && !CenteredLimb));
            static_assert(
                (!Fixed8192 && FixedRho == 0u) ||
                (Fixed8192 && (FixedRho == 1u || FixedRho == 4u)));
            static_assert(!SimpleIndex || Fixed8192);
            static_assert(!VectorShoupLoads || (Fixed8192 && SimpleIndex));
            static_assert(!CrossingPrepared ||
                (!OutOfPlace && !Fixed8192 && !GatherOutput));
            extern __shared__ u64 sh[];

            const u32 n = Fixed8192 ? 8192u : rg.mN;
            const u32 tiles = Fixed8192 ? 1u : (1u << logTiles);
            const u32 tileLen = Fixed8192 ? 8192u : (n >> logTiles);
            const u32 logTileLen = Fixed8192 ? 13u : (rg.mLogN - logTiles);

            const u32 tileIdx = Fixed8192 ? 0u : (blockIdx.x & (tiles - 1u));
            const u32 rest = Fixed8192 ? blockIdx.x : (blockIdx.x >> logTiles);
            const u32 rho = FixedRho == 0u ? rg.mRho : FixedRho;
            u32 limb;
            u32 batchSlot;
            if constexpr (FixedRho == 1u)
            {
                limb = 0u;
                batchSlot = rest;
            }
            else if constexpr (FixedRho == 4u)
            {
                limb = rest & 3u;
                batchSlot = rest >> 2u;
            }
            else
            {
                limb = rest % rho;
                batchSlot = rest / rho;
            }
            const u32 poly = polyIdx ? polyIdx[batchSlot] : batchSlot;
            u32 inPoly = poly;
            if constexpr (OutOfPlace) inPoly = inputIdx ? inputIdx[batchSlot] : batchSlot;

            u32 selectedLimb = limb;
            if constexpr (CenteredLimb)
                selectedLimb = inputLimb ? inputLimb[batchSlot] : rho;
            const u32 sourceLimb = selectedLimb < rho ? selectedLimb : 0u;

            const u64* inLimbBase = OutOfPlace
                ? input + (static_cast<size_t>(inPoly) * rho + sourceLimb) * n
                : data + (static_cast<size_t>(poly) * rho + limb) * n;
            u64* limbBase = data + (static_cast<size_t>(poly) * rho + limb) * n;
            const u64* src = inLimbBase + static_cast<size_t>(tileIdx) * tileLen;
            u64* dst = limbBase + static_cast<size_t>(tileIdx) * tileLen;
            const ShoupOperand* roots = rg.mRoots + static_cast<size_t>(limb) * n;
            const u64 q = rg.mMods[limb].mValue;
            const u64 twoQ = q << 1;

            if constexpr (Fixed8192)
            {
                if constexpr (CenteredLimb)
                {
                    // A fused centred load keeps one lifted residue live while
                    // reconstructing the other and raises the common kernel
                    // above the 32-register/two-CTA boundary. Preserve the
                    // accepted centred path; the toggle deliberately targets
                    // fixed non-centred transforms only.
                    for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                        sh[t] =
                            nttForwardLoad<
                                CenteredLimb, FixedRho>(
                                rg, src, selectedLimb, limb, t);
                    __syncthreads();
                }
                else if (fusedFirstStage)
                {
                    // S0 has m=1 and gap=4096. Each thread owns both global
                    // inputs of a butterfly, so the raw coefficients never need
                    // to be materialized in shared memory. This is the identical
                    // load/guard/Shoup/add sequence used by nttForwardStage8192<0>.
                    constexpr u32 gap = 4096u;
                    const ShoupOperand r =
                        nttLoadShoup<VectorShoupLoads>(roots + 1u);
                    for (u32 b = threadIdx.x; b < gap; b += blockDim.x)
                    {
                        const u64 u = nttGuard(
                            nttForwardLoad<
                                CenteredLimb, FixedRho>(
                                rg, src, selectedLimb, limb, b),
                            twoQ);
                        const u64 v = mulShoupLazy(
                            nttForwardLoad<
                                CenteredLimb, FixedRho>(
                                rg, src, selectedLimb, limb, b + gap),
                            r, q);
                        sh[b] = u + v;
                        sh[b + gap] = u + twoQ - v;
                    }
                    // This is S0's original trailing barrier and hands its
                    // outputs to S1. No input-materialization barrier is needed.
                    __syncthreads();
                }
                else
                {
                    for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                        sh[t] =
                            nttForwardLoad<
                                CenteredLimb, FixedRho>(
                                rg, src, selectedLimb, limb, t);
                    __syncthreads();
                }
            }
            else if (logTiles == 1u)
            {
                if constexpr (CrossingPrepared)
                {
                    // The in-place crossing stage ran as a separate kernel, which
                    // provides the grid-wide boundary required before either tile
                    // may overwrite coefficients the sibling tile still needs.
                    for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                        sh[t] = src[t];
                }
                else
                {
                    // Out-of-place transforms may safely recompute the crossing
                    // butterfly in both blocks because their source is immutable.
                    const ShoupOperand r = roots[1];
                    for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                    {
                        const u64 u = nttGuard(
                            nttForwardLoad<CenteredLimb, FixedRho>(
                                rg, inLimbBase, selectedLimb, limb, t),
                            twoQ);
                        const u64 v = mulShoupLazy(
                            nttForwardLoad<CenteredLimb, FixedRho>(
                                rg, inLimbBase, selectedLimb, limb, t + tileLen),
                            r, q);
                        sh[t] = (tileIdx == 0u) ? (u + v) : (u + twoQ - v);
                    }
                }
                __syncthreads();
            }
            else
            {
                for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                    sh[t] = nttForwardLoad<CenteredLimb, FixedRho>(
                        rg, src, selectedLimb, limb, t);
                __syncthreads();
            }

            if constexpr (Fixed8192)
            {
                if constexpr (CenteredLimb)
                {
                    nttForwardStage8192<0, SimpleIndex, VectorShoupLoads>(
                        sh, roots, q, twoQ);
                }
                else if (!fusedFirstStage)
                {
                    nttForwardStage8192<0, SimpleIndex, VectorShoupLoads>(
                        sh, roots, q, twoQ);
                }
                nttForwardStage8192<1, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttForwardStage8192<2, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttForwardStage8192<3, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttForwardStage8192<4, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttForwardStage8192<5, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttForwardStage8192<6, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttForwardStage8192<7, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttForwardStage8192<8, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttForwardStage8192<9, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttForwardStage8192<10, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttForwardStage8192<11, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttForwardStage8192<12, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);

            }
            else
            {
                const u32 half = tileLen >> 1;
                for (u32 s = 0; s < logTileLen; ++s)
                {
                    const u32 m = 1u << s;
                    const u32 logGap = logTileLen - 1u - s;
                    const u32 gap = 1u << logGap;
                    const u32 rootBase = m * (tiles + tileIdx);
                    for (u32 b = threadIdx.x; b < half; b += blockDim.x)
                    {
                        const u32 i = b >> logGap;
                        const u32 j = b & (gap - 1u);
                        const u32 ix = (i << (logGap + 1u)) + j;
                        const ShoupOperand r = roots[rootBase + i];
                        const u64 u = nttGuard(sh[ix], twoQ);
                        const u64 v = mulShoupLazy(sh[ix + gap], r, q);
                        sh[ix] = u + v;
                        sh[ix + gap] = u + twoQ - v;
                    }
                    __syncthreads();
                }
            }

            for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
            {
                u64 x = sh[t];
                if (x >= twoQ) x -= twoQ;
                if (x >= q) x -= q;
                if constexpr (GatherOutput)
                {
                    const u32 coeff = tileIdx * tileLen + t;
                    const u64 outIdx =
                        static_cast<u64>(batchSlot) * slotCount + inverseSlotMap[coeff];
                    if (outIdx < gatheredCount) gathered[outIdx] = x;
                }
                else
                {
                    dst[t] = x;
                }
            }

        }


        // One exact warp-register transition after forward stage S7. At stage
        // s, butterfly b owns the values at
        //   I_s(b) = b + floor(b / 2^(12-s)) * 2^(12-s)
        // and I_s(b) + 2^(12-s). The next stage pairs owners that differ only
        // in lane bit 12-s, so one xor shuffle supplies both lanes' remote
        // input while retaining the accepted guard/Shoup/add order.
        template<u32 Stage>
        __device__ __forceinline__ void nttForwardWarpStage8192(
            u64& lo,
            u64& hi,
            const ShoupOperand* roots,
            u32 butterfly,
            u64 q,
            u64 twoQ)
        {
            static_assert(Stage >= 8u && Stage <= 12u);
            constexpr u32 logGap = 12u - Stage;
            constexpr u32 laneMask = 1u << logGap;
            constexpr u32 rootBase = 1u << Stage;

            const bool upper = (butterfly & laneMask) != 0u;
            const u64 outbound = upper ? lo : hi;
            const u64 remote = __shfl_xor_sync(
                0xffffffffu, outbound, laneMask);
            const u64 left = upper ? remote : lo;
            const u64 right = upper ? hi : remote;
            const ShoupOperand r = nttLoadShoup<true>(
                roots + rootBase + (butterfly >> logGap));
            const u64 u = nttGuard(left, twoQ);
            const u64 v = mulShoupLazy(right, r, q);
            lo = u + v;
            hi = u + twoQ - v;
        }

        // Consume the immutable S6 shared layout once, execute S7 locally and
        // S8--S12 through warp exchange, then retain the accepted canonical
        // vector store. Relative to the accepted S11/S12 tail this removes four
        // complete shared read/write rounds, exactly 512 KiB per CTA.
        __device__ __forceinline__ void
        nttForwardWarpStages712Store8192(
            const u64* sh,
            const ShoupOperand* roots,
            u64 q,
            u64 twoQ,
            u64* dst)
        {
            constexpr u32 half = 4096u;
            constexpr u32 s7Gap = 32u;
            constexpr u32 s7RootBase = 128u;
            for (u32 butterfly = threadIdx.x;
                 butterfly < half;
                 butterfly += blockDim.x)
            {
                const u32 i = butterfly >> 5u;
                const u32 ix = butterfly + (i << 5u);
                const ShoupOperand r =
                    nttLoadShoup<true>(roots + s7RootBase + i);
                const u64 u = nttGuard(sh[ix], twoQ);
                const u64 v = mulShoupLazy(sh[ix + s7Gap], r, q);
                u64 lo = u + v;
                u64 hi = u + twoQ - v;

                nttForwardWarpStage8192<8u>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttForwardWarpStage8192<9u>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttForwardWarpStage8192<10u>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttForwardWarpStage8192<11u>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttForwardWarpStage8192<12u>(
                    lo, hi, roots, butterfly, q, twoQ);

                if (lo >= twoQ) lo -= twoQ;
                if (lo >= q) lo -= q;
                if (hi >= twoQ) hi -= twoQ;
                if (hi >= q) hi -= q;
                const u32 outIx = butterfly << 1u;
                asm volatile(
                    "st.global.v2.u64 [%0], {%1, %2};"
                    :
                    : "l"(dst + outIx), "l"(lo), "l"(hi)
                    : "memory");
            }
        }

        // Fixed-log13 forward with warp-local S7..S12.
        __global__ __launch_bounds__(kNttThreads, 2)
        void nttForwardWarpStages7128192Rho4Kernel(
            DeviceRing rg,
            u64* data,
            const u32* polyIdx)
        {
            extern __shared__ u64 sh[];
            constexpr u32 n = 8192u;
            constexpr u32 rho = 4u;
            constexpr u32 half = n >> 1u;

            const u32 limb = blockIdx.x & (rho - 1u);
            const u32 batchSlot = blockIdx.x >> 2u;
            const u32 poly = polyIdx ? polyIdx[batchSlot] : batchSlot;
            u64* dst = data +
                (static_cast<size_t>(poly) * rho + limb) * n;
            const ShoupOperand* roots =
                rg.mRoots + static_cast<size_t>(limb) * n;
            const u64 q = rg.mMods[limb].mValue;
            const u64 twoQ = q << 1u;

            const ShoupOperand r = nttLoadShoup<true>(roots + 1u);
            for (u32 b = threadIdx.x; b < half; b += blockDim.x)
            {
                const u64 u = nttGuard(dst[b], twoQ);
                const u64 v = mulShoupLazy(dst[b + half], r, q);
                sh[b] = u + v;
                sh[b + half] = u + twoQ - v;
            }
            __syncthreads();

            nttForwardStage8192<1u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<2u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<3u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<4u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<5u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<6u, true, true>(sh, roots, q, twoQ);
            nttForwardWarpStages712Store8192(
                sh, roots, q, twoQ, dst);
        }

        __global__ __launch_bounds__(kNttThreads, 2)
        void nttForwardFromPlainBroadcastWarpStages7128192Rho4Kernel(
            DeviceRing rg,
            const u64* input,
            const u32* inputIdx,
            u64* output,
            const u32* outputIdx)
        {
            extern __shared__ u64 sh[];
            constexpr u32 n = 8192u;
            constexpr u32 rho = 4u;
            constexpr u32 half = n >> 1u;

            const u32 limb = blockIdx.x & (rho - 1u);
            const u32 batchSlot = blockIdx.x >> 2u;
            const u32 inPoly = inputIdx ? inputIdx[batchSlot] : batchSlot;
            const u32 outPoly = outputIdx ? outputIdx[batchSlot] : batchSlot;
            const u64* src = input +
                (static_cast<size_t>(inPoly) * rho) * n;
            u64* dst = output +
                (static_cast<size_t>(outPoly) * rho + limb) * n;
            const ShoupOperand* roots =
                rg.mRoots + static_cast<size_t>(limb) * n;
            const u64 q = rg.mMods[limb].mValue;
            const u64 twoQ = q << 1u;

            const ShoupOperand r = nttLoadShoup<true>(roots + 1u);
            for (u32 b = threadIdx.x; b < half; b += blockDim.x)
            {
                const u64 u = nttGuard(src[b], twoQ);
                const u64 v = mulShoupLazy(src[b + half], r, q);
                sh[b] = u + v;
                sh[b + half] = u + twoQ - v;
            }
            __syncthreads();

            nttForwardStage8192<1u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<2u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<3u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<4u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<5u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<6u, true, true>(sh, roots, q, twoQ);
            nttForwardWarpStages712Store8192(
                sh, roots, q, twoQ, dst);
        }

        __global__ __launch_bounds__(kNttThreads, 2)
        void nttForwardCenteredLimbFromWarpStages7128192Rho4Kernel(
            DeviceRing rg,
            const u64* input,
            const u32* inputIdx,
            const u32* inputLimb,
            u64* output,
            const u32* outputIdx)
        {
            extern __shared__ u64 sh[];
            constexpr u32 n = 8192u;
            constexpr u32 rho = 4u;

            const u32 limb = blockIdx.x & (rho - 1u);
            const u32 batchSlot = blockIdx.x >> 2u;
            const u32 inPoly = inputIdx ? inputIdx[batchSlot] : batchSlot;
            const u32 outPoly = outputIdx ? outputIdx[batchSlot] : batchSlot;
            const u32 selectedLimb = inputLimb[batchSlot];
            const u32 sourceLimb =
                selectedLimb < rho ? selectedLimb : 0u;
            const u64* src = input +
                (static_cast<size_t>(inPoly) * rho + sourceLimb) * n;
            u64* dst = output +
                (static_cast<size_t>(outPoly) * rho + limb) * n;
            const ShoupOperand* roots =
                rg.mRoots + static_cast<size_t>(limb) * n;
            const u64 q = rg.mMods[limb].mValue;
            const u64 twoQ = q << 1u;

            {
                for (u32 t = threadIdx.x; t < n; t += blockDim.x)
                    sh[t] = nttForwardLoad<true, 4u>(
                        rg, src, selectedLimb, limb, t);
            }
            __syncthreads();

            nttForwardStage8192<0u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<1u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<2u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<3u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<4u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<5u, true, true>(sh, roots, q, twoQ);
            nttForwardStage8192<6u, true, true>(sh, roots, q, twoQ);
            nttForwardWarpStages712Store8192(
                sh, roots, q, twoQ, dst);
        }

        // Two-tile forward in one launch, the mirror of nttInverseTwoTileKernel.
        //
        // The crossing stage is the *first* one here, and it pairs element j with
        // element j + n/2, so a thread that owns the strided set { t + i*threads }
        // holds both members of every pair it needs. It therefore computes the whole
        // crossing stage while loading, keeps the first half's outputs in shared
        // memory and the second half's in registers, transforms the first half,
        // writes it out, then moves the registers into shared and transforms the
        // second half.
        //
        // Against the split version (a crossing kernel over the whole limb plus a
        // tiled kernel) this reads each element once instead of twice: 2n of traffic
        // rather than 3n. The split version was measured at the DRAM roof, so the
        // traffic is what its time was made of.
        __global__ __launch_bounds__(kNttThreads) void nttForwardTwoTileKernel(
            DeviceRing rg, u64* data, const u32* polyIdx)
        {
            extern __shared__ u64 sh[];

            const u32 n = rg.mN;
            const u32 tileLen = n >> 1;
            const u32 logTileLen = rg.mLogN - 1u;
            const u32 limb = blockIdx.x % rg.mRho;
            const u32 slot = blockIdx.x / rg.mRho;
            const u32 poly = polyIdx ? polyIdx[slot] : slot;

            u64* limbBase = data + (static_cast<size_t>(poly) * rg.mRho + limb) * n;
            const ShoupOperand* roots = rg.mRoots + static_cast<size_t>(limb) * n;
            const u64 q = rg.mMods[limb].mValue;
            const u64 twoQ = q << 1;
            const u32 half = tileLen >> 1;

            // The crossing stage: m = 1, i = 0, so a single root for the whole limb.
            u64 hi[kInvRegs];
            {
                const ShoupOperand r = roots[1];
#pragma unroll
                for (u32 i = 0; i < kInvRegs; ++i)
                {
                    const u32 j = threadIdx.x + i * kNttThreads;
                    const u64 u = nttGuard(limbBase[j], twoQ);
                    const u64 v = mulShoupLazy(limbBase[j + tileLen], r, q);
                    sh[j] = u + v;
                    hi[i] = u + twoQ - v;
                }
            }
            __syncthreads();

            for (u32 tileIdx = 0u;; tileIdx = 1u)
            {
                for (u32 s = 0; s < logTileLen; ++s)
                {
                    const u32 m = 1u << s;
                    const u32 logGap = logTileLen - 1u - s;
                    const u32 gap = 1u << logGap;
                    const u32 rootBase = m * (2u + tileIdx);
                    for (u32 b = threadIdx.x; b < half; b += blockDim.x)
                    {
                        const u32 i = b >> logGap;
                        const u32 j = b & (gap - 1u);
                        const u32 ix = (i << (logGap + 1u)) + j;
                        const ShoupOperand r = roots[rootBase + i];
                        const u64 u = nttGuard(sh[ix], twoQ);
                        const u64 v = mulShoupLazy(sh[ix + gap], r, q);
                        sh[ix] = u + v;
                        sh[ix + gap] = u + twoQ - v;
                    }
                    __syncthreads();
                }

                u64* dst = limbBase + static_cast<size_t>(tileIdx) * tileLen;
                for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                {
                    u64 x = sh[t];
                    if (x >= twoQ) x -= twoQ;
                    if (x >= q) x -= q;
                    dst[t] = x;
                }
                if (tileIdx == 1u) break;

                // Hand the second half over to shared memory for its own pass.
                __syncthreads();
#pragma unroll
                for (u32 i = 0; i < kInvRegs; ++i) sh[threadIdx.x + i * kNttThreads] = hi[i];
                __syncthreads();
            }
        }

        // Fixed tile-local stage for the N=16384 transform. After the crossing
        // stage, the low and high 8192-word halves use disjoint root subtrees:
        // rootBase is m*2 for tile 0 and m*3 for tile 1. Making both values
        // compile-time constants removes the generic stage loop and its dynamic
        // shift/mask/root arithmetic.
        template<u32 Stage, u32 RootFactor>
        __device__ __forceinline__ void nttForwardLog14TileStage(
            u64* sh,
            const ShoupOperand* roots,
            u64 q,
            u64 twoQ)
        {
            static_assert(Stage < 13u);
            static_assert(RootFactor == 2u || RootFactor == 3u);
            constexpr u32 logGap = 12u - Stage;
            constexpr u32 gap = 1u << logGap;
            constexpr u32 rootBase = (1u << Stage) * RootFactor;
            for (u32 b = threadIdx.x; b < 4096u; b += blockDim.x)
            {
                const u32 i = b >> logGap;
                const u32 ix = b + (i << logGap);
                const ShoupOperand r = nttLoadShoup<true>(
                    roots + rootBase + i);
                const u64 u = nttGuard(sh[ix], twoQ);
                const u64 v = mulShoupLazy(sh[ix + gap], r, q);
                sh[ix] = u + v;
                sh[ix + gap] = u + twoQ - v;
            }
            if constexpr (Stage >= 7u && Stage <= 11u)
                __syncwarp();
            else
                __syncthreads();
        }

        // Two descending-gap stages share four values. Keep the first stage's
        // two butterfly results in registers until the second stage publishes
        // them, retaining every original guard and lazy Shoup multiplication.
        template<u32 Stage, u32 RootFactor>
        __device__ __forceinline__ void nttForwardLog14TileStagePair(
            u64* sh, const ShoupOperand* roots, u64 q, u64 twoQ)
        {
            static_assert(Stage <= 5u);
            static_assert(RootFactor == 2u || RootFactor == 3u);
            constexpr u32 logGap = 11u - Stage;
            constexpr u32 gap = 1u << logGap;
            constexpr u32 rootBase = (1u << Stage) * RootFactor;
            for (u32 j = threadIdx.x; j < 2048u; j += blockDim.x)
            {
                const u32 group = Stage == 0u ? 0u : j >> logGap;
                const u32 ix = j + (group << logGap) * 3u;
                u64 lo0, hi0, lo1, hi1;
                {
                    const ShoupOperand r = nttLoadShoup<true>(
                        roots + rootBase + group);
                    const u64 u0 = nttGuard(sh[ix], twoQ);
                    const u64 v0 = mulShoupLazy(sh[ix + 2u * gap], r, q);
                    lo0 = u0 + v0;
                    hi0 = u0 + twoQ - v0;
                    const u64 u1 = nttGuard(sh[ix + gap], twoQ);
                    const u64 v1 = mulShoupLazy(sh[ix + 3u * gap], r, q);
                    lo1 = u1 + v1;
                    hi1 = u1 + twoQ - v1;
                }
                {
                    const ShoupOperand r = nttLoadShoup<true>(
                        roots + 2u * rootBase + 2u * group);
                    const u64 u = nttGuard(lo0, twoQ);
                    const u64 v = mulShoupLazy(lo1, r, q);
                    sh[ix] = u + v;
                    sh[ix + gap] = u + twoQ - v;
                }
                {
                    const ShoupOperand r = nttLoadShoup<true>(
                        roots + 2u * rootBase + 2u * group + 1u);
                    const u64 u = nttGuard(hi0, twoQ);
                    const u64 v = mulShoupLazy(hi1, r, q);
                    sh[ix + 2u * gap] = u + v;
                    sh[ix + 3u * gap] = u + twoQ - v;
                }
            }
            __syncthreads();
        }

        template<u32 RootFactor, bool PairedPrefix = false>
        __device__ __forceinline__ void nttForwardLog14TilePrefix06(
            u64* sh,
            const ShoupOperand* roots,
            u64 q,
            u64 twoQ)
        {
            if constexpr (PairedPrefix)
            {
                nttForwardLog14TileStagePair<0u, RootFactor>(sh, roots, q, twoQ);
                nttForwardLog14TileStagePair<2u, RootFactor>(sh, roots, q, twoQ);
                nttForwardLog14TileStagePair<4u, RootFactor>(sh, roots, q, twoQ);
            }
            else
            {
                nttForwardLog14TileStage<0u, RootFactor>(sh, roots, q, twoQ);
                nttForwardLog14TileStage<1u, RootFactor>(sh, roots, q, twoQ);
                nttForwardLog14TileStage<2u, RootFactor>(sh, roots, q, twoQ);
                nttForwardLog14TileStage<3u, RootFactor>(sh, roots, q, twoQ);
                nttForwardLog14TileStage<4u, RootFactor>(sh, roots, q, twoQ);
                nttForwardLog14TileStage<5u, RootFactor>(sh, roots, q, twoQ);
            }
            nttForwardLog14TileStage<6u, RootFactor>(sh, roots, q, twoQ);
        }

        template<u32 Stage, u32 RootFactor>
        __device__ __forceinline__ void nttForwardLog14WarpStage(
            u64& lo,
            u64& hi,
            const ShoupOperand* roots,
            u32 butterfly,
            u64 q,
            u64 twoQ)
        {
            static_assert(Stage >= 8u && Stage <= 12u);
            static_assert(RootFactor == 2u || RootFactor == 3u);
            constexpr u32 logGap = 12u - Stage;
            constexpr u32 laneMask = 1u << logGap;
            constexpr u32 rootBase = (1u << Stage) * RootFactor;

            const bool upper = (butterfly & laneMask) != 0u;
            const u64 outbound = upper ? lo : hi;
            const u64 remote = __shfl_xor_sync(
                0xffffffffu, outbound, laneMask);
            const u64 left = upper ? remote : lo;
            const u64 right = upper ? hi : remote;
            const ShoupOperand r = nttLoadShoup<true>(
                roots + rootBase + (butterfly >> logGap));
            const u64 u = nttGuard(left, twoQ);
            const u64 v = mulShoupLazy(right, r, q);
            lo = u + v;
            hi = u + twoQ - v;
        }

        template<u32 RootFactor>
        __device__ __forceinline__ void
        nttForwardLog14WarpStages712Store(
            const u64* sh,
            const ShoupOperand* roots,
            u64 q,
            u64 twoQ,
            u64* dst)
        {
            constexpr u32 s7Gap = 32u;
            constexpr u32 s7RootBase = 128u * RootFactor;
            for (u32 butterfly = threadIdx.x;
                 butterfly < 4096u;
                 butterfly += blockDim.x)
            {
                const u32 group = butterfly >> 5u;
                const u32 input = butterfly + (group << 5u);
                const ShoupOperand r = nttLoadShoup<true>(
                    roots + s7RootBase + group);
                const u64 u = nttGuard(sh[input], twoQ);
                const u64 v = mulShoupLazy(
                    sh[input + s7Gap], r, q);
                u64 lo = u + v;
                u64 hi = u + twoQ - v;

                nttForwardLog14WarpStage<8u, RootFactor>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttForwardLog14WarpStage<9u, RootFactor>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttForwardLog14WarpStage<10u, RootFactor>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttForwardLog14WarpStage<11u, RootFactor>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttForwardLog14WarpStage<12u, RootFactor>(
                    lo, hi, roots, butterfly, q, twoQ);

                if (lo >= twoQ) lo -= twoQ;
                if (lo >= q) lo -= q;
                if (hi >= twoQ) hi -= twoQ;
                if (hi >= q) hi -= q;
                const u32 output = butterfly << 1u;
                asm volatile(
                    "st.global.v2.u64 [%0], {%1, %2};"
                    :
                    : "l"(dst + output), "l"(lo), "l"(hi)
                    : "memory");
            }
        }

        // H200 no-golden-seed input specialization. The wrapped canonical
        // plaintext is physically present in source limb 0 only. One block per
        // target limb reads it once, parks the crossing stage's high half in
        // registers, and transforms both halves in turn. Compared with the
        // generic out-of-place tiled kernel this cuts traffic from 3N to 2N per
        // target limb and avoids materializing seven duplicate source limbs.
        template<bool PairedPrefix = false, u32 Threads = kNttThreads>
        __global__ __launch_bounds__(Threads, Threads == 512u ? 2u : 1u)
        void nttForwardFromPlainBroadcast16384Rho8Kernel(
            DeviceRing rg,
            const u64* input,
            const u32* inputIdx,
            u64* output,
            const u32* outputIdx)
        {
            extern __shared__ u64 sh[];
            constexpr u32 n = 16384u;
            constexpr u32 rho = 8u;
            constexpr u32 tileLen = 8192u;
            constexpr u32 parked = tileLen / Threads;
            static_assert(Threads == 512u || Threads == 1024u);

            const u32 limb = blockIdx.x & (rho - 1u);
            const u32 batchSlot = blockIdx.x >> 3u;
            const u32 inPoly = inputIdx ? inputIdx[batchSlot] : batchSlot;
            const u32 outPoly = outputIdx ? outputIdx[batchSlot] : batchSlot;
            const u64* src = input +
                static_cast<size_t>(inPoly) * rho * n;
            u64* dst = output +
                (static_cast<size_t>(outPoly) * rho + limb) * n;
            const ShoupOperand* roots =
                rg.mRoots + static_cast<size_t>(limb) * n;
            const u64 q = rg.mMods[limb].mValue;
            const u64 twoQ = q << 1u;
            const ShoupOperand crossing = nttLoadShoup<true>(roots + 1u);

            u64 hi[parked];
#pragma unroll
            for (u32 i = 0; i < parked; ++i)
            {
                const u32 j = threadIdx.x + i * Threads;
                const u64 u = nttGuard(src[j], twoQ);
                const u64 v = mulShoupLazy(src[j + tileLen], crossing, q);
                sh[j] = u + v;
                hi[i] = u + twoQ - v;
            }
            __syncthreads();

            nttForwardLog14TilePrefix06<2u, PairedPrefix>(
                sh, roots, q, twoQ);
            nttForwardLog14WarpStages712Store<2u>(
                sh, roots, q, twoQ, dst);

            __syncthreads();
#pragma unroll
            for (u32 i = 0; i < parked; ++i)
                sh[threadIdx.x + i * Threads] = hi[i];
            __syncthreads();

            nttForwardLog14TilePrefix06<3u, PairedPrefix>(
                sh, roots, q, twoQ);
            nttForwardLog14WarpStages712Store<3u>(
                sh, roots, q, twoQ, dst + tileLen);

        }

        // Fixed out-of-place centred-limb transform for NoGoldenSeed. Every
        // target limb reads the selected source limb, reconstructs the same
        // signed representative as nttForwardLoad<true>, and parks the crossing
        // stage's high half so both 8192-word tiles complete in one CTA.
        template<bool PairedPrefix = false, u32 Threads = kNttThreads>
        __global__ __launch_bounds__(Threads, Threads == 512u ? 2u : 1u)
        void nttForwardCenteredLimbFrom16384Rho8Kernel(
            DeviceRing rg,
            const u64* input,
            const u32* inputIdx,
            const u32* inputLimb,
            u64* output,
            const u32* outputIdx)
        {
            extern __shared__ u64 sh[];
            constexpr u32 n = 16384u;
            constexpr u32 rho = 8u;
            constexpr u32 tileLen = 8192u;
            constexpr u32 parked = tileLen / Threads;
            static_assert(Threads == 512u || Threads == 1024u);

            const u32 limb = blockIdx.x & (rho - 1u);
            const u32 batchSlot = blockIdx.x >> 3u;
            const u32 inPoly = inputIdx ? inputIdx[batchSlot] : batchSlot;
            const u32 outPoly = outputIdx ? outputIdx[batchSlot] : batchSlot;
            const u32 selected = inputLimb ? inputLimb[batchSlot] : rho;
            const u32 sourceLimb = selected < rho ? selected : 0u;
            const u64* src = input +
                (static_cast<size_t>(inPoly) * rho + sourceLimb) * n;
            u64* dst = output +
                (static_cast<size_t>(outPoly) * rho + limb) * n;
            const ShoupOperand* roots =
                rg.mRoots + static_cast<size_t>(limb) * n;
            const u64 q = rg.mMods[limb].mValue;
            const u64 twoQ = q << 1u;
            const ShoupOperand crossing = nttLoadShoup<true>(roots + 1u);

            u64 hi[parked];
#pragma unroll
            for (u32 i = 0u; i < parked; ++i)
            {
                const u32 j = threadIdx.x + i * Threads;
                const u64 low = nttForwardLoad<true>(
                    rg, src, selected, limb, j);
                const u64 high = nttForwardLoad<true>(
                    rg, src, selected, limb, j + tileLen);
                const u64 u = nttGuard(low, twoQ);
                const u64 v = mulShoupLazy(high, crossing, q);
                sh[j] = u + v;
                hi[i] = u + twoQ - v;
            }
            __syncthreads();

            nttForwardLog14TilePrefix06<2u, PairedPrefix>(
                sh, roots, q, twoQ);
            nttForwardLog14WarpStages712Store<2u>(
                sh, roots, q, twoQ, dst);

            __syncthreads();
#pragma unroll
            for (u32 i = 0u; i < parked; ++i)
                sh[threadIdx.x + i * Threads] = hi[i];
            __syncthreads();

            nttForwardLog14TilePrefix06<3u, PairedPrefix>(
                sh, roots, q, twoQ);
            nttForwardLog14WarpStages712Store<3u>(
                sh, roots, q, twoQ, dst + tileLen);

        }

        // Fixed in-place counterpart used by every sufficiently wide
        // NoGoldenSeed forward transform. It preserves the accepted
        // register-parked two-tile dataflow while removing DeviceRing geometry,
        // the dynamic stage loop and scalar Shoup loads from its hot body.
        template<bool PairedPrefix = false, u32 Threads = kNttThreads>
        __global__ __launch_bounds__(Threads, Threads == 512u ? 2u : 1u)
        void nttForwardTwoTile16384Rho8Kernel(
            DeviceRing rg, u64* data, const u32* polyIdx)
        {
            extern __shared__ u64 sh[];
            constexpr u32 n = 16384u;
            constexpr u32 rho = 8u;
            constexpr u32 tileLen = 8192u;
            constexpr u32 parked = tileLen / Threads;
            static_assert(Threads == 512u || Threads == 1024u);

            const u32 limb = blockIdx.x & (rho - 1u);
            const u32 slot = blockIdx.x >> 3u;
            const u32 poly = polyIdx ? polyIdx[slot] : slot;
            u64* limbBase = data +
                (static_cast<size_t>(poly) * rho + limb) * n;
            const ShoupOperand* roots =
                rg.mRoots + static_cast<size_t>(limb) * n;
            const u64 q = rg.mMods[limb].mValue;
            const u64 twoQ = q << 1u;
            const ShoupOperand crossing = nttLoadShoup<true>(roots + 1u);

            u64 hi[parked];
#pragma unroll
            for (u32 i = 0; i < parked; ++i)
            {
                const u32 j = threadIdx.x + i * Threads;
                const u64 u = nttGuard(limbBase[j], twoQ);
                const u64 v = mulShoupLazy(
                    limbBase[j + tileLen], crossing, q);
                sh[j] = u + v;
                hi[i] = u + twoQ - v;
            }
            __syncthreads();

            nttForwardLog14TilePrefix06<2u, PairedPrefix>(
                sh, roots, q, twoQ);
            nttForwardLog14WarpStages712Store<2u>(
                sh, roots, q, twoQ, limbBase);

            __syncthreads();
#pragma unroll
            for (u32 i = 0; i < parked; ++i)
                sh[threadIdx.x + i * Threads] = hi[i];
            __syncthreads();

            nttForwardLog14TilePrefix06<3u, PairedPrefix>(
                sh, roots, q, twoQ);
            nttForwardLog14WarpStages712Store<3u>(
                sh, roots, q, twoQ, limbBase + tileLen);

        }

        // One tile-crossing forward stage, in global memory. Only used when
        // tiles > 1, for stages s < log2(tiles). Values are left in [0, 4q), which
        // is what the shared-memory stages already accept as input.
        __global__ void nttForwardCrossKernel(DeviceRing rg, u64* data, const u32* polyIdx, u32 stage)
        {
            const u32 n = rg.mN;
            const u32 half = n >> 1;
            const u32 b = blockIdx.x * blockDim.x + threadIdx.x;
            if (b >= half) return;

            const u32 limb = blockIdx.y % rg.mRho;
            const u32 slot = blockIdx.y / rg.mRho;
            const u32 poly = polyIdx ? polyIdx[slot] : slot;

            u64* src = data + (static_cast<size_t>(poly) * rg.mRho + limb) * n;
            const ShoupOperand* roots = rg.mRoots + static_cast<size_t>(limb) * n;
            const u64 q = rg.mMods[limb].mValue;
            const u64 twoQ = q << 1;

            const u32 m = 1u << stage;
            const u32 logGap = rg.mLogN - 1u - stage;
            const u32 gap = 1u << logGap;
            const u32 i = b >> logGap;
            const u32 j = b & (gap - 1u);
            const u32 ix = (i << (logGap + 1u)) + j;
            const ShoupOperand r = roots[m + i];
            const u64 u = nttGuard(src[ix], twoQ);
            const u64 v = mulShoupLazy(src[ix + gap], r, q);
            src[ix] = u + v;
            src[ix + gap] = u + twoQ - v;
        }

        // One exact non-final inverse stage for the fixed one-tile N=8192
        // transform. The scaled m=1 stage remains in nttInverseKernel so its
        // pre/post hooks and final reduction are shared with the generic path.
        template<
            u32 Stage,
            bool SimpleIndex = false,
            bool VectorShoupLoads = false>
        __device__ __forceinline__ void nttInverseStage8192(
            u64* sh,
            const ShoupOperand* roots,
            u64 q,
            u64 twoQ)
        {
            static_assert(Stage < 12u);
            constexpr u32 logGap = Stage;
            constexpr u32 gap = 1u << logGap;
            constexpr u32 m = 8192u >> (Stage + 1u);
            constexpr u32 rootBase = 8192u - 2u * m + 1u;
            for (u32 b = threadIdx.x; b < 4096u; b += blockDim.x)
            {
                const u32 i = b >> logGap;
                const u32 j = b & (gap - 1u);
                const u32 ix = SimpleIndex
                    ? b + (i << logGap)
                    : (i << (logGap + 1u)) + j;
                const ShoupOperand r = nttLoadShoup<VectorShoupLoads>(
                    roots + rootBase + i);
                const u64 u = sh[ix];
                const u64 v = sh[ix + gap];
                sh[ix] = nttGuard(u + v, twoQ);
                sh[ix + gap] = mulShoupLazy(u + twoQ - v, r, q);
            }
            if constexpr (Stage <= 4u)
                __syncwarp();
            else
                __syncthreads();
        }

        template<u32 PostOp>
        __device__ __forceinline__ u64 nttInverseFixedPost8192(
            u64 x,
            const u64* b,
            u32 index,
            u64 q)
        {
            static_assert(
                PostOp == 0u || PostOp == 2u || PostOp == 4u);
            if constexpr (PostOp == 2u)
                return x == 0u ? 0u : q - x;
            else if constexpr (PostOp == 0u)
                return addMod(x, b[index], q);
            else
                return subMod(b[index], x, q);
        }

        // Fuse fixed inverse stage S11 with the scaled m=1 stage and direct
        // post-op. For SimpleIndex, b=j and b=2048+j are the two S11
        // butterflies whose respective outputs are paired by the final stage.
        // Feeding each independent sum/difference pair through immediately
        // removes S11's shared stores, the following shared loads, and its
        // trailing CTA barrier.
        template<u32 PostOp, bool VectorShoupLoads = false>
        __device__ __forceinline__ void nttInverseFusedTail8192(
            u64* sh,
            u64* dst,
            const u64* b,
            const ShoupOperand* roots,
            ShoupOperand scalar,
            ShoupOperand scaledR,
            u64 q,
            u64 twoQ)
        {
            static_assert(PostOp == 0u || PostOp == 2u || PostOp == 4u);
            constexpr u32 s11Gap = 2048u;
            constexpr u32 finalGap = 4096u;

            // Finish the two S11 sums first. Re-reading the four immutable S10
            // inputs for the differences below shortens live ranges enough to
            // preserve the fixed kernel's occupancy/resource gate; it still
            // removes all four S11 stores, all four final-stage shared loads,
            // and the CTA barrier between the stages.
            for (u32 j = threadIdx.x; j < s11Gap; j += blockDim.x)
            {
                const u64 lo = nttGuard(
                    sh[j] + sh[j + s11Gap], twoQ);
                const u64 hi = nttGuard(
                    sh[j + finalGap] + sh[j + finalGap + s11Gap], twoQ);
                const u64 u = nttGuard(lo, twoQ);

                u64 x = mulShoupLazy(
                    nttGuard(u + hi, twoQ), scalar, q);
                if (x >= q) x -= q;
                dst[j] = nttInverseFixedPost8192<PostOp>(x, b, j, q);

                x = mulShoupLazy(u + twoQ - hi, scaledR, q);
                if (x >= q) x -= q;
                dst[j + finalGap] = nttInverseFixedPost8192<PostOp>(
                    x, b, j + finalGap, q);
            }

            // Preserve the staged kernel's exact Shoup operation and final
            // guard for each S11 difference.
            for (u32 j = threadIdx.x; j < s11Gap; j += blockDim.x)
            {
                u64 lo;
                {
                    const u64 u = sh[j];
                    const u64 v = sh[j + s11Gap];
                    lo = mulShoupLazy(
                        u + twoQ - v,
                        nttLoadShoup<VectorShoupLoads>(roots + 8189u), q);
                }
                u64 hi;
                {
                    const u64 u = sh[j + finalGap];
                    const u64 v = sh[j + finalGap + s11Gap];
                    hi = mulShoupLazy(
                        u + twoQ - v,
                        nttLoadShoup<VectorShoupLoads>(roots + 8190u), q);
                }
                const u64 u = nttGuard(lo, twoQ);

                u64 x = mulShoupLazy(
                    nttGuard(u + hi, twoQ), scalar, q);
                if (x >= q) x -= q;
                dst[j + s11Gap] = nttInverseFixedPost8192<PostOp>(
                    x, b, j + s11Gap, q);

                x = mulShoupLazy(u + twoQ - hi, scaledR, q);
                if (x >= q) x -= q;
                dst[j + finalGap + s11Gap] =
                    nttInverseFixedPost8192<PostOp>(
                        x, b, j + finalGap + s11Gap, q);
            }
        }

        __device__ __forceinline__ void
        nttInverseFusedLastThreeFinalReverseSub8192(
            u64 lo,
            u64 hi,
            u32 index,
            u64* dst,
            const u64* b,
            ShoupOperand scalar,
            ShoupOperand scaledR,
            u64 q,
            u64 twoQ)
        {
            // Match the accepted staged final butterfly exactly: guard the low
            // input and the positive sum, but feed the negative difference to
            // its scaled Shoup multiply without an extra guard.
            const u64 u = nttGuard(lo, twoQ);
            u64 x = mulShoupLazy(nttGuard(u + hi, twoQ), scalar, q);
            if (x >= q) x -= q;
            dst[index] = subMod(b[index], x, q);

            x = mulShoupLazy(u + twoQ - hi, scaledR, q);
            if (x >= q) x -= q;
            dst[index + 4096u] = subMod(b[index + 4096u], x, q);
        }

        // Consume one S10 parity directly from immutable S9 shared state. The
        // sum pass uses the even S10 output from each adjacent 1024-word pair;
        // the difference pass re-reads the same inputs and uses the odd output.
        // Within a pass, retain only S11's low sum/difference while forming the
        // high pair, then serialize the two final butterflies. In particular,
        // no runtime-indexed local array is introduced at the 40-register gate.
        template<bool S10Difference>
        __device__ __forceinline__ void
        nttInverseFusedLastThreeParityReverseSub8192(
            const u64* sh,
            u64* dst,
            const u64* b,
            const ShoupOperand* roots,
            ShoupOperand scalar,
            ShoupOperand scaledR,
            u64 q,
            u64 twoQ)
        {
            constexpr u32 s10Gap = 1024u;
            constexpr u32 s11Gap = 2048u;
            constexpr u32 parityOffset = S10Difference ? s10Gap : 0u;

            // This symbol is dispatched with exactly 512 threads. Two bases per
            // thread cover each of the 1024 independent eight-word S9 groups.
            for (u32 j = threadIdx.x; j < s10Gap; j += 512u)
            {
                u64 lowSum;
                u64 lowDifference;
                {
                    u64 a0;
                    u64 a1;
                    if constexpr (S10Difference)
                    {
                        const u64 u0 = sh[j];
                        const u64 v0 = sh[j + s10Gap];
                        a0 = mulShoupLazy(
                            u0 + twoQ - v0,
                            nttLoadShoup<true>(roots + 8185u), q);

                        const u64 u1 = sh[j + 2u * s10Gap];
                        const u64 v1 = sh[j + 3u * s10Gap];
                        a1 = mulShoupLazy(
                            u1 + twoQ - v1,
                            nttLoadShoup<true>(roots + 8186u), q);
                    }
                    else
                    {
                        a0 = nttGuard(sh[j] + sh[j + s10Gap], twoQ);
                        a1 = nttGuard(
                            sh[j + 2u * s10Gap] + sh[j + 3u * s10Gap],
                            twoQ);
                    }
                    lowSum = nttGuard(a0 + a1, twoQ);
                    lowDifference = mulShoupLazy(
                        a0 + twoQ - a1,
                        nttLoadShoup<true>(roots + 8189u), q);
                }

                u64 a2;
                u64 a3;
                if constexpr (S10Difference)
                {
                    const u64 u2 = sh[j + 4u * s10Gap];
                    const u64 v2 = sh[j + 5u * s10Gap];
                    a2 = mulShoupLazy(
                        u2 + twoQ - v2,
                        nttLoadShoup<true>(roots + 8187u), q);

                    const u64 u3 = sh[j + 6u * s10Gap];
                    const u64 v3 = sh[j + 7u * s10Gap];
                    a3 = mulShoupLazy(
                        u3 + twoQ - v3,
                        nttLoadShoup<true>(roots + 8188u), q);
                }
                else
                {
                    a2 = nttGuard(
                        sh[j + 4u * s10Gap] + sh[j + 5u * s10Gap],
                        twoQ);
                    a3 = nttGuard(
                        sh[j + 6u * s10Gap] + sh[j + 7u * s10Gap],
                        twoQ);
                }

                const u32 sumIndex = j + parityOffset;
                const u64 highSum = nttGuard(a2 + a3, twoQ);
                const u64 highDifference = mulShoupLazy(
                    a2 + twoQ - a3,
                    nttLoadShoup<true>(roots + 8190u), q);
                nttInverseFusedLastThreeFinalReverseSub8192(
                    lowSum, highSum, sumIndex, dst, b, scalar, scaledR, q,
                    twoQ);

                nttInverseFusedLastThreeFinalReverseSub8192(
                    lowDifference, highDifference, sumIndex + s11Gap, dst, b,
                    scalar, scaledR, q, twoQ);
            }
        }

        // Fixed production sidecar for N=8192, rho=4, simple indexing,
        // ReverseSub, vector Shoup loads, and the accepted fused first stage.
        // Stage 9's trailing CTA barrier makes sh[] immutable for both parity
        // passes. Their eight output classes are disjoint, so neither pass needs
        // a shared publication or another inter-thread handoff.
        __global__ __maxnreg__(40) void
        nttInverseFusedLastThree8192Rho4ReverseSubKernel(
            DeviceInverseRho4 iv,
            u64* data,
            const u32* polyIdx,
            const u64* postB)
        {
            extern __shared__ u64 sh[];

            const u32 limb = blockIdx.x & 3u;
            const u32 slot = blockIdx.x >> 2u;
            const u32 poly = polyIdx ? polyIdx[slot] : slot;
            const size_t off =
                (static_cast<size_t>(poly) * 4u + limb) * 8192u;
            u64* dst = data + off;
            const u64* b = postB + off;
            const ShoupOperand* roots =
                iv.mInvRoots + static_cast<size_t>(limb) * 8192u;
            const u64 q = iv.mMods[limb].mValue;
            const u64 twoQ = q << 1u;

            // Accepted global-load + S0 fusion. The dispatch below requires the
            // 512-thread production geometry and its enabled fused-first route.
            for (u32 butterfly = threadIdx.x;
                 butterfly < 4096u;
                 butterfly += 512u)
            {
                const u32 ix = butterfly << 1u;
                const ShoupOperand r =
                    nttLoadShoup<true>(roots + 1u + butterfly);
                const u64 u = dst[ix];
                const u64 v = dst[ix + 1u];
                sh[ix] = nttGuard(u + v, twoQ);
                sh[ix + 1u] = mulShoupLazy(u + twoQ - v, r, q);
            }
            __syncwarp();

            nttInverseStage8192<1u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<2u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<3u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<4u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<5u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<6u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<7u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<8u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<9u, true, true>(sh, roots, q, twoQ);

            const ShoupOperand scalar =
                nttLoadShoup<true>(iv.mInvDegree + limb);
            const ShoupOperand scaledR =
                nttLoadShoup<true>(iv.mScaledInvRoot + limb);
            nttInverseFusedLastThreeParityReverseSub8192<false>(
                sh, dst, b, roots, scalar, scaledR, q, twoQ);
            nttInverseFusedLastThreeParityReverseSub8192<true>(
                sh, dst, b, roots, scalar, scaledR, q, twoQ);
        }

        // Add and Negate have the same fixed transform and output ownership as
        // the accepted ReverseSub sidecar above. Keep ReverseSub's helpers and
        // kernel untouched, and instantiate separate symbols for these two post
        // operations so each can independently satisfy the 40-register gate and
        // the preceding fused-tail kernels remain exact same-binary fallbacks.
        template<u32 PostOp>
        __device__ __forceinline__ void nttInverseFusedLastThreeFinalPost8192(
            u64 lo,
            u64 hi,
            u32 index,
            u64* dst,
            const u64* b,
            ShoupOperand scalar,
            ShoupOperand scaledR,
            u64 q,
            u64 twoQ)
        {
            static_assert(PostOp == 0u || PostOp == 2u);
            const u64 u = nttGuard(lo, twoQ);
            u64 x = mulShoupLazy(nttGuard(u + hi, twoQ), scalar, q);
            if (x >= q) x -= q;
            if constexpr (PostOp == 0u)
                dst[index] = addMod(x, b[index], q);
            else
                dst[index] = x == 0u ? 0u : q - x;

            x = mulShoupLazy(u + twoQ - hi, scaledR, q);
            if (x >= q) x -= q;
            if constexpr (PostOp == 0u)
                dst[index + 4096u] = addMod(x, b[index + 4096u], q);
            else
                dst[index + 4096u] = x == 0u ? 0u : q - x;
        }

        template<u32 PostOp, bool S10Difference>
        __device__ __forceinline__ void nttInverseFusedLastThreeParityPost8192(
            const u64* sh,
            u64* dst,
            const u64* b,
            const ShoupOperand* roots,
            ShoupOperand scalar,
            ShoupOperand scaledR,
            u64 q,
            u64 twoQ)
        {
            static_assert(PostOp == 0u || PostOp == 2u);
            constexpr u32 s10Gap = 1024u;
            constexpr u32 s11Gap = 2048u;
            constexpr u32 parityOffset = S10Difference ? s10Gap : 0u;

            #pragma unroll 2
            for (u32 j = threadIdx.x; j < s10Gap; j += 512u)
            {
                u64 lowSum;
                u64 lowDifference;
                {
                    u64 a0;
                    u64 a1;
                    if constexpr (S10Difference)
                    {
                        const u64 u0 = sh[j];
                        const u64 v0 = sh[j + s10Gap];
                        a0 = mulShoupLazy(
                            u0 + twoQ - v0,
                            nttLoadShoup<true>(roots + 8185u), q);

                        const u64 u1 = sh[j + 2u * s10Gap];
                        const u64 v1 = sh[j + 3u * s10Gap];
                        a1 = mulShoupLazy(
                            u1 + twoQ - v1,
                            nttLoadShoup<true>(roots + 8186u), q);
                    }
                    else
                    {
                        a0 = nttGuard(sh[j] + sh[j + s10Gap], twoQ);
                        a1 = nttGuard(
                            sh[j + 2u * s10Gap] + sh[j + 3u * s10Gap],
                            twoQ);
                    }
                    lowSum = nttGuard(a0 + a1, twoQ);
                    lowDifference = mulShoupLazy(
                        a0 + twoQ - a1,
                        nttLoadShoup<true>(roots + 8189u), q);
                }

                u64 a2;
                u64 a3;
                if constexpr (S10Difference)
                {
                    const u64 u2 = sh[j + 4u * s10Gap];
                    const u64 v2 = sh[j + 5u * s10Gap];
                    a2 = mulShoupLazy(
                        u2 + twoQ - v2,
                        nttLoadShoup<true>(roots + 8187u), q);

                    const u64 u3 = sh[j + 6u * s10Gap];
                    const u64 v3 = sh[j + 7u * s10Gap];
                    a3 = mulShoupLazy(
                        u3 + twoQ - v3,
                        nttLoadShoup<true>(roots + 8188u), q);
                }
                else
                {
                    a2 = nttGuard(
                        sh[j + 4u * s10Gap] + sh[j + 5u * s10Gap],
                        twoQ);
                    a3 = nttGuard(
                        sh[j + 6u * s10Gap] + sh[j + 7u * s10Gap],
                        twoQ);
                }

                const u32 sumIndex = j + parityOffset;
                const u64 highSum = nttGuard(a2 + a3, twoQ);
                const u64 highDifference = mulShoupLazy(
                    a2 + twoQ - a3,
                    nttLoadShoup<true>(roots + 8190u), q);
                nttInverseFusedLastThreeFinalPost8192<PostOp>(
                    lowSum, highSum, sumIndex, dst, b, scalar, scaledR, q,
                    twoQ);
                nttInverseFusedLastThreeFinalPost8192<PostOp>(
                    lowDifference, highDifference, sumIndex + s11Gap, dst, b,
                    scalar, scaledR, q, twoQ);
            }
        }

        template<u32 PostOp>
        __global__ __maxnreg__(40) void
        nttInverseFusedLastThree8192Rho4PostKernel(
            DeviceInverseRho4 iv,
            u64* data,
            const u32* polyIdx,
            const u64* postB)
        {
            static_assert(PostOp == 0u || PostOp == 2u);
            extern __shared__ u64 sh[];

            const u32 limb = blockIdx.x & 3u;
            const u32 slot = blockIdx.x >> 2u;
            const u32 poly = polyIdx ? polyIdx[slot] : slot;
            const size_t off =
                (static_cast<size_t>(poly) * 4u + limb) * 8192u;
            u64* dst = data + off;
            const u64* b = nullptr;
            if constexpr (PostOp == 0u) b = postB + off;
            const ShoupOperand* roots =
                iv.mInvRoots + static_cast<size_t>(limb) * 8192u;
            const u64 q = iv.mMods[limb].mValue;
            const u64 twoQ = q << 1u;

            for (u32 butterfly = threadIdx.x;
                 butterfly < 4096u;
                 butterfly += 512u)
            {
                const u32 ix = butterfly << 1u;
                const ShoupOperand r =
                    nttLoadShoup<true>(roots + 1u + butterfly);
                const u64 u = dst[ix];
                const u64 v = dst[ix + 1u];
                sh[ix] = nttGuard(u + v, twoQ);
                sh[ix + 1u] = mulShoupLazy(u + twoQ - v, r, q);
            }
            __syncwarp();

            nttInverseStage8192<1u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<2u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<3u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<4u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<5u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<6u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<7u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<8u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<9u, true, true>(sh, roots, q, twoQ);

            const ShoupOperand scalar =
                nttLoadShoup<true>(iv.mInvDegree + limb);
            const ShoupOperand scaledR =
                nttLoadShoup<true>(iv.mScaledInvRoot + limb);
            nttInverseFusedLastThreeParityPost8192<PostOp, false>(
                sh, dst, b, roots, scalar, scaledR, q, twoQ);
            nttInverseFusedLastThreeParityPost8192<PostOp, true>(
                sh, dst, b, roots, scalar, scaledR, q, twoQ);
        }

        // Shared transform tail for the two exact fixed-IP sidecars below. The
        // caller has already filled sh[] with the canonical materialized inner
        // product. PostOp remains at the inverse boundary: tree products negate
        // after the transform, while sender expansion computes ct2 - INTT(A*sk).
        template<u32 PostOp, bool SimpleIndex, bool FirstStageDone = false>
        __device__ __forceinline__ void nttInverseFixedIpTransform8192(
            DeviceInverseRho4 iv,
            u64* sh,
            u64* out,
            const u64* postB,
            u32 limb,
            u32 slot)
        {
            static_assert(PostOp == 0u || PostOp == 2u || PostOp == 4u);
            const u64 q = iv.mMods[limb].mValue;
            const u64 twoQ = q << 1u;
            const ShoupOperand* roots =
                iv.mInvRoots + (static_cast<size_t>(limb) << 13u);

            if constexpr (!FirstStageDone)
                nttInverseStage8192<0, SimpleIndex>(sh, roots, q, twoQ);
            nttInverseStage8192<1, SimpleIndex>(sh, roots, q, twoQ);
            nttInverseStage8192<2, SimpleIndex>(sh, roots, q, twoQ);
            nttInverseStage8192<3, SimpleIndex>(sh, roots, q, twoQ);
            nttInverseStage8192<4, SimpleIndex>(sh, roots, q, twoQ);
            nttInverseStage8192<5, SimpleIndex>(sh, roots, q, twoQ);
            nttInverseStage8192<6, SimpleIndex>(sh, roots, q, twoQ);
            nttInverseStage8192<7, SimpleIndex>(sh, roots, q, twoQ);
            nttInverseStage8192<8, SimpleIndex>(sh, roots, q, twoQ);
            nttInverseStage8192<9, SimpleIndex>(sh, roots, q, twoQ);
            nttInverseStage8192<10, SimpleIndex>(sh, roots, q, twoQ);
            nttInverseStage8192<11, SimpleIndex>(sh, roots, q, twoQ);

            constexpr u32 gap = 4096u;
            const ShoupOperand scalar = iv.mInvDegree[limb];
            const ShoupOperand scaledR = iv.mScaledInvRoot[limb];
            const size_t off =
                (static_cast<size_t>(slot) << 15u) +
                (static_cast<size_t>(limb) << 13u);
            u64* dst = out + off;
            const u64* b = nullptr;
            if constexpr (PostOp == 0u || PostOp == 4u) b = postB + off;
            for (u32 j = threadIdx.x; j < gap; j += 512u)
            {
                const u64 u = nttGuard(sh[j], twoQ);
                const u64 v = sh[j + gap];

                // Match the existing direct-final lifetime discipline: finish
                // and publish one output before creating the other.
                u64 x = mulShoupLazy(nttGuard(u + v, twoQ), scalar, q);
                if (x >= q) x -= q;
                dst[j] = nttInverseFixedPost8192<PostOp>(x, b, j, q);

                x = mulShoupLazy(u + twoQ - v, scaledR, q);
                if (x >= q) x -= q;
                dst[j + gap] =
                    nttInverseFixedPost8192<PostOp>(x, b, j + gap, q);
            }
        }


        // Exact canonical reduction for a sum of one, two, or six products
        // under q=2^55-c, 0<c<2^21.  If P=sum(a_i*b_i), then P<K*2^110.
        // Splitting twice in radix R=2^55 gives
        //
        //   P = s0+s1*R = s0+s1*c (mod q)
        //     = t0+t1*R = t0+t1*c (mod q).
        //
        // For K<=6 the final value is below R+K*c^2<2q, so one subtraction
        // is both necessary and sufficient.  c*s1 is expressed through two
        // native 32x32 partial products to avoid recreating a generic 64-bit
        // Barrett chain on sm90.
        template<u32 MaxTerms>
        __device__ __forceinline__ u64
        pointwisePseudo55ReduceWideCanonical(Wide value, u64 q, u32 c)
        {
            static_assert(
                MaxTerms == 1u || MaxTerms == 2u || MaxTerms == 6u);
            constexpr u64 kRadix55 = u64{ 1 } << 55u;
            constexpr u64 kMask55 = kRadix55 - 1u;

            const u64 s0 = value.mLo & kMask55;
            const u64 s1 =
                (value.mLo >> 55u) | (value.mHi << 9u);
            const u64 p0 =
                static_cast<u64>(static_cast<u32>(s1)) * c;
            const u64 p1 =
                static_cast<u64>(static_cast<u32>(s1 >> 32u)) * c;

            u64 tLo = p0 + (p1 << 32u);
            u64 tHi =
                (p1 >> 32u) + static_cast<u64>(tLo < p0);
            const u64 oldTLo = tLo;
            tLo += s0;
            tHi += static_cast<u64>(tLo < oldTLo);

            const u64 t0 = tLo & kMask55;
            // t1 <= MaxTerms*c < 6*2^21, hence it fits in u32.
            const u32 t1 = static_cast<u32>(
                (tLo >> 55u) | (tHi << 9u));
            u64 residue = t0 + static_cast<u64>(t1) * c;
            if (residue >= q) residue -= q;
            return residue;
        }




        // Compute the two adjacent canonical products directly in inverse S0.
        __global__ __launch_bounds__(512, 3)
        void nttInverseTreePairNegateFusedFirstStageKernel(
            DeviceInverseRho4 iv,
            u64* out,
            const u64* publicB,
            const u64* nodes,
            u32 depth,
            u32 nodeCount,
            u32 publicCol)
        {
            extern __shared__ u64 sh[];
            const u32 limb = blockIdx.x & 3u;
            const u32 slot = blockIdx.x >> 2u;

            {
                const u32 nodesAtDepth = 1u << depth;
                const u32 chunk = slot >> depth;
                const u32 k = slot & (nodesAtDepth - 1u);
                const u32 left = (nodesAtDepth << 1u) + (k << 1u) - 1u;
                const size_t leftSlot =
                    static_cast<size_t>(chunk) * nodeCount + left;
                const size_t limbOff = static_cast<size_t>(limb) << 13u;
                const u64* a0 =
                    publicB + (static_cast<size_t>(publicCol) << 15u) + limbOff;
                const u64* a1 =
                    publicB + (static_cast<size_t>(publicCol + 2u) << 15u) + limbOff;
                const u64* b0 = nodes + (leftSlot << 15u) + limbOff;
                const u64* b1 = b0 + (size_t(1) << 15u);
                const GpuModulus mod = iv.mMods[limb];
                const u64 q = mod.mValue;
                const u64 twoQ = q << 1u;
                const ShoupOperand* roots =
                    iv.mInvRoots + (static_cast<size_t>(limb) << 13u);

                // Inverse S0 has gap=1. The same thread owns both exact
                // two-product reductions and both butterfly outputs, so the
                // canonical products never need a raw shared-memory image.
#pragma unroll 1
                for (u32 butterfly = threadIdx.x;
                     butterfly < 4096u;
                     butterfly += 512u)
                {
                    const u32 ix = butterfly << 1u;

                    Wide sum0 = wideMul(a0[ix], b0[ix]);
                    sum0 = wideAdd(sum0, wideMul(a1[ix], b1[ix]));
                    const u64 u =
                        barrettReduce128(sum0.mLo, sum0.mHi, mod);

                    Wide sum1 = wideMul(a0[ix + 1u], b0[ix + 1u]);
                    sum1 = wideAdd(sum1, wideMul(a1[ix + 1u], b1[ix + 1u]));
                    const u64 v =
                        barrettReduce128(sum1.mLo, sum1.mHi, mod);

                    sh[ix] = nttGuard(u + v, twoQ);
                    const ShoupOperand r = roots[1u + butterfly];
                    sh[ix + 1u] = mulShoupLazy(u + twoQ - v, r, q);
                }
            }
            // S0..S4 are warp-private for the fixed butterfly mapping.
            __syncwarp();
            nttInverseFixedIpTransform8192<2u, true, true>(
                iv, sh, out, nullptr, limb, slot);
        }

        // One warp-register transition for inverse stage S1 through S5.
        // After stage s, butterfly b owns the two values at
        //   I_s(b) = b + floor(b / 2^s) * 2^s, I_s(b) + 2^s.
        // For s <= 5 the preceding owners differ only in lane bit s-1.  The
        // lower lane sends its high value and the upper lane sends its low
        // value, so one 64-bit xor shuffle supplies exactly the remote input
        // required by both owners while every lane still evaluates one complete
        // accepted butterfly.
        template<u32 Stage>
        __device__ __forceinline__ void nttInverseWarpStage8192(
            u64& lo,
            u64& hi,
            const ShoupOperand* roots,
            u32 butterfly,
            u64 q,
            u64 twoQ)
        {
            static_assert(Stage >= 1u && Stage <= 5u);
            constexpr u32 laneMask = 1u << (Stage - 1u);
            constexpr u32 m = 8192u >> (Stage + 1u);
            constexpr u32 rootBase = 8192u - 2u * m + 1u;

            const bool upper = (threadIdx.x & laneMask) != 0u;
            const u64 outbound = upper ? lo : hi;
            const u64 remote = __shfl_xor_sync(
                0xffffffffu, outbound, laneMask);
            const u64 u = upper ? remote : lo;
            const u64 v = upper ? hi : remote;
            const ShoupOperand r = nttLoadShoup<true>(
                roots + rootBase + (butterfly >> Stage));
            lo = nttGuard(u + v, twoQ);
            hi = mulShoupLazy(u + twoQ - v, r, q);
        }

        __device__ __forceinline__ u64 nttLoadPostBIndexedLate8192(
            const u64* b,
            u32 index)
        {
            unsigned long long value;
            // Keep the indexed B address out of the live set while the S10/S11
            // roots are loaded.  A C++ indexed load is hoisted across those
            // loads by ptxas and costs one 64-bit spill at the 40-register
            // occupancy gate; this candidate-only PTX forms and consumes the
            // address at the exact post-op use instead.
            asm volatile(
                "{ .reg .u64 address;\n\t"
                "mad.wide.u32 address, %1, 8, %2;\n\t"
                "ld.global.u64 %0, [address];\n\t"
                "}"
                : "=l"(value)
                : "r"(index), "l"(b)
                : "memory");
            return value;
        }

        __device__ __forceinline__ void
        nttInverseFusedLastThreeFinalAddLate8192(
            u64 lo,
            u64 hi,
            u32 index,
            u64* dst,
            const u64* b,
            ShoupOperand scalar,
            ShoupOperand scaledR,
            u64 q,
            u64 twoQ)
        {
            const u64 u = nttGuard(lo, twoQ);
            u64 x = mulShoupLazy(
                nttGuard(u + hi, twoQ), scalar, q);
            if (x >= q) x -= q;
            const u64 b0 = nttLoadPostBIndexedLate8192(b, index);
            dst[index] = addMod(x, b0, q);

            x = mulShoupLazy(u + twoQ - hi, scaledR, q);
            if (x >= q) x -= q;
            const u32 highIndex = index + 4096u;
            const u64 b1 = nttLoadPostBIndexedLate8192(b, highIndex);
            dst[highIndex] = addMod(x, b1, q);
        }

        // Candidate-only Add/ReverseSub tail with the two j values kept as a
        // counted loop. The accepted symbols deliberately retain their prior
        // helpers; this lower-liveness copy lets the longer Stage-110 prefix
        // stay within the same 40-register, zero-stack contract.
        template<u32 PostOp, bool S10Difference>
        __device__ __forceinline__ void
        nttInverseFusedLastThreeParityPostLowRegs8192(
            const u64* sh,
            u64* dst,
            const u64* b,
            const ShoupOperand* roots,
            const ShoupOperand* scalarSrc,
            const ShoupOperand* scaledRSrc,
            u64 q,
            u64 twoQ)
        {
            static_assert(PostOp == 0u || PostOp == 4u);
            constexpr u32 s10Gap = 1024u;
            constexpr u32 s11Gap = 2048u;
            constexpr u32 parityOffset = S10Difference ? s10Gap : 0u;

#pragma unroll 1
            for (u32 j = threadIdx.x; j < s10Gap; j += 512u)
            {
                u64 lowSum;
                u64 lowDifference;
                {
                    u64 a0;
                    u64 a1;
                    if constexpr (S10Difference)
                    {
                        const u64 u0 = sh[j];
                        const u64 v0 = sh[j + s10Gap];
                        a0 = mulShoupLazy(
                            u0 + twoQ - v0,
                            nttLoadShoup<true>(roots + 8185u), q);

                        const u64 u1 = sh[j + 2u * s10Gap];
                        const u64 v1 = sh[j + 3u * s10Gap];
                        a1 = mulShoupLazy(
                            u1 + twoQ - v1,
                            nttLoadShoup<true>(roots + 8186u), q);
                    }
                    else
                    {
                        a0 = nttGuard(sh[j] + sh[j + s10Gap], twoQ);
                        a1 = nttGuard(
                            sh[j + 2u * s10Gap] + sh[j + 3u * s10Gap],
                            twoQ);
                    }
                    lowSum = nttGuard(a0 + a1, twoQ);
                    lowDifference = mulShoupLazy(
                        a0 + twoQ - a1,
                        nttLoadShoup<true>(roots + 8189u), q);
                }

                u64 a2;
                u64 a3;
                if constexpr (S10Difference)
                {
                    const u64 u2 = sh[j + 4u * s10Gap];
                    const u64 v2 = sh[j + 5u * s10Gap];
                    a2 = mulShoupLazy(
                        u2 + twoQ - v2,
                        nttLoadShoup<true>(roots + 8187u), q);

                    const u64 u3 = sh[j + 6u * s10Gap];
                    const u64 v3 = sh[j + 7u * s10Gap];
                    a3 = mulShoupLazy(
                        u3 + twoQ - v3,
                        nttLoadShoup<true>(roots + 8188u), q);
                }
                else
                {
                    a2 = nttGuard(
                        sh[j + 4u * s10Gap] + sh[j + 5u * s10Gap],
                        twoQ);
                    a3 = nttGuard(
                        sh[j + 6u * s10Gap] + sh[j + 7u * s10Gap],
                        twoQ);
                }

                const u64 highSum = nttGuard(a2 + a3, twoQ);
                const u64 highDifference = mulShoupLazy(
                    a2 + twoQ - a3,
                    nttLoadShoup<true>(roots + 8190u), q);
                const u32 sumIndex = j + parityOffset;
                // Load the scaled final operands only after all S10/S11 roots
                // for this j have been consumed.
                const ShoupOperand scalar =
                    nttLoadShoup<true>(scalarSrc);
                const ShoupOperand scaledR =
                    nttLoadShoup<true>(scaledRSrc);
                if constexpr (PostOp == 0u)
                {
                    nttInverseFusedLastThreeFinalAddLate8192(
                        lowSum, highSum, sumIndex, dst, b, scalar, scaledR, q,
                        twoQ);
                    nttInverseFusedLastThreeFinalAddLate8192(
                        lowDifference, highDifference, sumIndex + s11Gap, dst,
                        b, scalar, scaledR, q, twoQ);
                }
                else
                {
                    nttInverseFusedLastThreeFinalReverseSub8192(
                        lowSum, highSum, sumIndex, dst, b, scalar, scaledR, q,
                        twoQ);
                    nttInverseFusedLastThreeFinalReverseSub8192(
                        lowDifference, highDifference, sumIndex + s11Gap, dst,
                        b, scalar, scaledR, q, twoQ);
                }
            }
        }

        // Stage-110 alpha=2 sidecar. Each lane owns one aligned S0 input pair.
        // The eight butterfly iterations per lane are independent 64-word warp
        // tiles, so S1--S5 need only xor shuffles. Publishing the simple-index
        // S5 pair once gives the accepted S6--S9 suffix and fused S10--S12 tail
        // exactly the shared layout they already consume.
        template<u32 PostOp>
        __device__ __forceinline__ void nttInversePostWarpStages05Body8192(
            DeviceInverseRho4 iv,
            u64* data,
            const u32* polyIdx,
            const u64* postB,
            u64* sh)
        {
            static_assert(PostOp == 0u || PostOp == 2u || PostOp == 4u);
            const u32 limb = blockIdx.x & 3u;
            const u32 slot = blockIdx.x >> 2u;
            const u32 poly = polyIdx ? polyIdx[slot] : slot;
            const size_t off =
                (static_cast<size_t>(poly) * 4u + limb) * 8192u;
            u64* dst = data + off;
            const ShoupOperand* roots =
                iv.mInvRoots + static_cast<size_t>(limb) * 8192u;
            const u64 q = iv.mMods[limb].mValue;
            const u64 twoQ = q << 1u;
#pragma unroll 1
            for (u32 butterfly = threadIdx.x;
                 butterfly < 4096u;
                 butterfly += 512u)
            {
                // data is CUDA-allocated and every fixed polynomial/limb
                // offset is a multiple of 64 KiB, so every S0 pair is aligned
                // for one vector global load.
                const ulonglong2 input =
                    reinterpret_cast<const ulonglong2*>(dst)[butterfly];
                const ShoupOperand r =
                    nttLoadShoup<true>(roots + 1u + butterfly);
                u64 lo = nttGuard(input.x + input.y, twoQ);
                u64 hi = mulShoupLazy(input.x + twoQ - input.y, r, q);

                nttInverseWarpStage8192<1u>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttInverseWarpStage8192<2u>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttInverseWarpStage8192<3u>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttInverseWarpStage8192<4u>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttInverseWarpStage8192<5u>(
                    lo, hi, roots, butterfly, q, twoQ);

                constexpr u32 gap = 32u;
                const u32 ix = butterfly + ((butterfly >> 5u) << 5u);
                sh[ix] = lo;
                sh[ix + gap] = hi;
            }
            __syncthreads();

            nttInverseStage8192<6u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<7u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<8u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<9u, true, true>(sh, roots, q, twoQ);

            const u64* b = nullptr;
            if constexpr (PostOp == 0u || PostOp == 4u)
                b = postB + off;
            if constexpr (PostOp == 4u)
            {
                nttInverseFusedLastThreeParityPostLowRegs8192<4u, false>(
                    sh, dst, b, roots, iv.mInvDegree + limb,
                    iv.mScaledInvRoot + limb, q, twoQ);
                nttInverseFusedLastThreeParityPostLowRegs8192<4u, true>(
                    sh, dst, b, roots, iv.mInvDegree + limb,
                    iv.mScaledInvRoot + limb, q, twoQ);
            }
            else
            {
                if constexpr (PostOp == 0u)
                {
                    nttInverseFusedLastThreeParityPostLowRegs8192<0u, false>(
                        sh, dst, b, roots, iv.mInvDegree + limb,
                        iv.mScaledInvRoot + limb, q, twoQ);
                    nttInverseFusedLastThreeParityPostLowRegs8192<0u, true>(
                        sh, dst, b, roots, iv.mInvDegree + limb,
                        iv.mScaledInvRoot + limb, q, twoQ);
                }
                else
                {
                    const ShoupOperand scalar =
                        nttLoadShoup<true>(iv.mInvDegree + limb);
                    const ShoupOperand scaledR =
                        nttLoadShoup<true>(iv.mScaledInvRoot + limb);
                    nttInverseFusedLastThreeParityPost8192<PostOp, false>(
                        sh, dst, b, roots, scalar, scaledR, q, twoQ);
                    nttInverseFusedLastThreeParityPost8192<PostOp, true>(
                        sh, dst, b, roots, scalar, scaledR, q, twoQ);
                }
            }
        }

        __global__ __maxnreg__(40) void
        nttInversePostWarpStages05Add8192Rho4Kernel(
            DeviceInverseRho4 iv,
            u64* data,
            const u32* polyIdx,
            const u64* postB)
        {
            extern __shared__ u64 sh[];
            nttInversePostWarpStages05Body8192<0u>(
                iv, data, polyIdx, postB, sh);
        }

        __global__ __maxnreg__(40) void
        nttInversePostWarpStages05Negate8192Rho4Kernel(
            DeviceInverseRho4 iv,
            u64* data,
            const u32* polyIdx,
            const u64* postB)
        {
            extern __shared__ u64 sh[];
            nttInversePostWarpStages05Body8192<2u>(
                iv, data, polyIdx, postB, sh);
        }

        __global__ __maxnreg__(40) void
        nttInversePostWarpStages05ReverseSub8192Rho4Kernel(
            DeviceInverseRho4 iv,
            u64* data,
            const u32* polyIdx,
            const u64* postB)
        {
            extern __shared__ u64 sh[];
            nttInversePostWarpStages05Body8192<4u>(
                iv, data, polyIdx, postB, sh);
        }

        __device__ __forceinline__ ulonglong2
        nttLoadSharedPair8192(const u64* pair)
        {
            unsigned long long lo;
            unsigned long long hi;
            const u32 address =
                static_cast<u32>(__cvta_generic_to_shared(pair));
            // S0 pairs begin at an even u64 index in a CUDA-aligned dynamic
            // shared allocation.  Spell the vector load in PTX so scalarization
            // is an explicit Stage-104b SASS-gate failure.
            asm volatile(
                "ld.shared.v2.u64 {%0, %1}, [%2];"
                : "=l"(lo), "=l"(hi)
                : "r"(address)
                : "memory");
            return make_ulonglong2(lo, hi);
        }

        // Stage-104 accepted path. Keep the preceding pseudo-55 product and S0
        // materialization above byte-for-byte as the rollback symbol.  This
        // separate kernel reads each S0 pair once, carries its exact S1..S5
        // butterfly state in two registers, and publishes the exact S5 layout
        // once for the unchanged CTA-wide S6..S11 suffix and final negate.
        __global__ __launch_bounds__(512, 3)
        void nttInverseTreePairNegateWarpStagesPseudo55Kernel(
            DeviceInverseRho4 iv,
            u64* out,
            const u64* publicB,
            const u64* nodes,
            u32 depth,
            u32 nodeCount,
            u32 publicCol)
        {
            extern __shared__ u64 sh[];
            const u32 limb = blockIdx.x & 3u;
            const u32 slot = blockIdx.x >> 2u;

            {
                constexpr u64 kRadix55 = u64{ 1 } << 55u;
                const u32 nodesAtDepth = 1u << depth;
                const u32 chunk = slot >> depth;
                const u32 k = slot & (nodesAtDepth - 1u);
                const u32 left = (nodesAtDepth << 1u) + (k << 1u) - 1u;
                const size_t leftSlot =
                    static_cast<size_t>(chunk) * nodeCount + left;
                const size_t limbOff = static_cast<size_t>(limb) << 13u;
                const u64* a0 =
                    publicB + (static_cast<size_t>(publicCol) << 15u) + limbOff;
                const u64* a1 =
                    publicB + (static_cast<size_t>(publicCol + 2u) << 15u) + limbOff;
                const u64* b0 = nodes + (leftSlot << 15u) + limbOff;
                const u64* b1 = b0 + (size_t(1) << 15u);
                const u64 q = iv.mMods[limb].mValue;
                const u32 c = static_cast<u32>(kRadix55 - q);
                const u64 twoQ = q << 1u;
                const ShoupOperand* roots =
                    iv.mInvRoots + (static_cast<size_t>(limb) << 13u);

#pragma unroll 1
                for (u32 butterfly = threadIdx.x;
                     butterfly < 4096u;
                     butterfly += 512u)
                {
                    const u32 ix = butterfly << 1u;

                    Wide sum0 = wideMul(a0[ix], b0[ix]);
                    sum0 = wideAdd(sum0, wideMul(a1[ix], b1[ix]));
                    const u64 u =
                        pointwisePseudo55ReduceWideCanonical<2u>(
                            sum0, q, c);

                    Wide sum1 = wideMul(a0[ix + 1u], b0[ix + 1u]);
                    sum1 = wideAdd(
                        sum1, wideMul(a1[ix + 1u], b1[ix + 1u]));
                    const u64 v =
                        pointwisePseudo55ReduceWideCanonical<2u>(
                            sum1, q, c);

                    sh[ix] = nttGuard(u + v, twoQ);
                    const ShoupOperand r = roots[1u + butterfly];
                    sh[ix + 1u] =
                        mulShoupLazy(u + twoQ - v, r, q);
                }
            }
            __syncwarp();

            const u64 q = iv.mMods[limb].mValue;
            const u64 twoQ = q << 1u;
            const ShoupOperand* roots =
                iv.mInvRoots + (static_cast<size_t>(limb) << 13u);
#pragma unroll 1
            for (u32 butterfly = threadIdx.x;
                 butterfly < 4096u;
                 butterfly += 512u)
            {
                const u32 s0Ix = butterfly << 1u;
                const ulonglong2 s0 = nttLoadSharedPair8192(sh + s0Ix);
                u64 lo = s0.x;
                u64 hi = s0.y;
                nttInverseWarpStage8192<1u>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttInverseWarpStage8192<2u>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttInverseWarpStage8192<3u>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttInverseWarpStage8192<4u>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttInverseWarpStage8192<5u>(
                    lo, hi, roots, butterfly, q, twoQ);

                constexpr u32 gap = 32u;
                const u32 i = butterfly >> 5u;
                const u32 ix = butterfly + (i << 5u);
                sh[ix] = lo;
                sh[ix + gap] = hi;
            }
            __syncthreads();

            nttInverseStage8192<6u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<7u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<8u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<9u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<10u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<11u, true, true>(sh, roots, q, twoQ);

            constexpr u32 gap = 4096u;
            const ShoupOperand scalar =
                nttLoadShoup<true>(iv.mInvDegree + limb);
            const ShoupOperand scaledR =
                nttLoadShoup<true>(iv.mScaledInvRoot + limb);
            const size_t off =
                (static_cast<size_t>(slot) << 15u) +
                (static_cast<size_t>(limb) << 13u);
            u64* dst = out + off;
            for (u32 j = threadIdx.x; j < gap; j += 512u)
            {
                const u64 u = nttGuard(sh[j], twoQ);
                const u64 v = sh[j + gap];

                u64 x = mulShoupLazy(
                    nttGuard(u + v, twoQ), scalar, q);
                if (x >= q) x -= q;
                dst[j] = nttInverseFixedPost8192<2u>(
                    x, nullptr, j, q);

                x = mulShoupLazy(u + twoQ - v, scaledR, q);
                if (x >= q) x -= q;
                dst[j + gap] = nttInverseFixedPost8192<2u>(
                    x, nullptr, j + gap, q);
            }
        }

        // Stage-112 alpha=2 candidate. The two exact pseudo-55 product
        // reductions are already owned by the lane that evaluates S0, so feed
        // that pair directly into the accepted warp-private S1--S5 prefix.
        // Only S5 is published for the byte-identical CTA-wide suffix. This
        // removes the S0 shared stores, the vector S0 reload, and the intervening
        // warp barrier while preserving all roots, lazy ranges, and final stores.
        __global__ __launch_bounds__(512, 3)
        void nttInverseTreePairNegateProductWarpStages05Pseudo55Kernel(
            DeviceInverseRho4 iv,
            u64* out,
            const u64* publicB,
            const u64* nodes,
            u32 depth,
            u32 nodeCount,
            u32 publicCol)
        {
            extern __shared__ u64 sh[];
            const u32 limb = blockIdx.x & 3u;
            const u32 slot = blockIdx.x >> 2u;

            {
                constexpr u64 kRadix55 = u64{ 1 } << 55u;
                const u32 nodesAtDepth = 1u << depth;
                const u32 chunk = slot >> depth;
                const u32 k = slot & (nodesAtDepth - 1u);
                const u32 left = (nodesAtDepth << 1u) + (k << 1u) - 1u;
                const size_t leftSlot =
                    static_cast<size_t>(chunk) * nodeCount + left;
                const size_t limbOff = static_cast<size_t>(limb) << 13u;
                const u64* a0 =
                    publicB + (static_cast<size_t>(publicCol) << 15u) + limbOff;
                const u64* a1 =
                    publicB + (static_cast<size_t>(publicCol + 2u) << 15u) + limbOff;
                const u64* b0 = nodes + (leftSlot << 15u) + limbOff;
                const u64* b1 = b0 + (size_t(1) << 15u);
                const u64 q = iv.mMods[limb].mValue;
                const u32 c = static_cast<u32>(kRadix55 - q);
                const u64 twoQ = q << 1u;
                const ShoupOperand* roots =
                    iv.mInvRoots + (static_cast<size_t>(limb) << 13u);

#pragma unroll 1
                for (u32 butterfly = threadIdx.x;
                     butterfly < 4096u;
                     butterfly += 512u)
                {
                    const u32 ix = butterfly << 1u;

                    Wide sum0 = wideMul(a0[ix], b0[ix]);
                    sum0 = wideAdd(sum0, wideMul(a1[ix], b1[ix]));
                    const u64 u =
                        pointwisePseudo55ReduceWideCanonical<2u>(
                            sum0, q, c);

                    Wide sum1 = wideMul(a0[ix + 1u], b0[ix + 1u]);
                    sum1 = wideAdd(
                        sum1, wideMul(a1[ix + 1u], b1[ix + 1u]));
                    const u64 v =
                        pointwisePseudo55ReduceWideCanonical<2u>(
                            sum1, q, c);

                    const ShoupOperand r = roots[1u + butterfly];
                    u64 lo = nttGuard(u + v, twoQ);
                    u64 hi = mulShoupLazy(u + twoQ - v, r, q);
                    nttInverseWarpStage8192<1u>(
                        lo, hi, roots, butterfly, q, twoQ);
                    nttInverseWarpStage8192<2u>(
                        lo, hi, roots, butterfly, q, twoQ);
                    nttInverseWarpStage8192<3u>(
                        lo, hi, roots, butterfly, q, twoQ);
                    nttInverseWarpStage8192<4u>(
                        lo, hi, roots, butterfly, q, twoQ);
                    nttInverseWarpStage8192<5u>(
                        lo, hi, roots, butterfly, q, twoQ);

                    constexpr u32 gap = 32u;
                    const u32 s5Ix =
                        butterfly + ((butterfly >> 5u) << 5u);
                    sh[s5Ix] = lo;
                    sh[s5Ix + gap] = hi;
                }
            }
            __syncthreads();

            const u64 q = iv.mMods[limb].mValue;
            const u64 twoQ = q << 1u;
            const ShoupOperand* roots =
                iv.mInvRoots + (static_cast<size_t>(limb) << 13u);
            nttInverseStage8192<6u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<7u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<8u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<9u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<10u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<11u, true, true>(sh, roots, q, twoQ);

            constexpr u32 gap = 4096u;
            const ShoupOperand scalar =
                nttLoadShoup<true>(iv.mInvDegree + limb);
            const ShoupOperand scaledR =
                nttLoadShoup<true>(iv.mScaledInvRoot + limb);
            const size_t off =
                (static_cast<size_t>(slot) << 15u) +
                (static_cast<size_t>(limb) << 13u);
            u64* dst = out + off;
            for (u32 j = threadIdx.x; j < gap; j += 512u)
            {
                const u64 u = nttGuard(sh[j], twoQ);
                const u64 v = sh[j + gap];

                u64 x = mulShoupLazy(
                    nttGuard(u + v, twoQ), scalar, q);
                if (x >= q) x -= q;
                dst[j] = nttInverseFixedPost8192<2u>(
                    x, nullptr, j, q);

                x = mulShoupLazy(u + twoQ - v, scaledR, q);
                if (x >= q) x -= q;
                dst[j + gap] = nttInverseFixedPost8192<2u>(
                    x, nullptr, j + gap, q);
            }
        }

        // Stage-112b keeps Stage-112a's transform exactly but fetches each
        // adjacent coefficient pair with one aligned vector transaction. All
        // polynomial and limb strides are multiples of 64 KiB and CUDA device
        // allocations satisfy the remaining base-alignment requirement.
        __global__ __launch_bounds__(512, 3)
        void nttInverseTreePairNegateProductWarpStages05VectorPairsPseudo55Kernel(
            DeviceInverseRho4 iv,
            u64* out,
            const u64* publicB,
            const u64* nodes,
            u32 depth,
            u32 nodeCount,
            u32 publicCol)
        {
            extern __shared__ u64 sh[];
            const u32 limb = blockIdx.x & 3u;
            const u32 slot = blockIdx.x >> 2u;

            {
                constexpr u64 kRadix55 = u64{ 1 } << 55u;
                const u32 nodesAtDepth = 1u << depth;
                const u32 chunk = slot >> depth;
                const u32 k = slot & (nodesAtDepth - 1u);
                const u32 left = (nodesAtDepth << 1u) + (k << 1u) - 1u;
                const size_t leftSlot =
                    static_cast<size_t>(chunk) * nodeCount + left;
                const size_t limbOff = static_cast<size_t>(limb) << 13u;
                const u64* a0 =
                    publicB + (static_cast<size_t>(publicCol) << 15u) + limbOff;
                const u64* a1 =
                    publicB + (static_cast<size_t>(publicCol + 2u) << 15u) + limbOff;
                const u64* b0 = nodes + (leftSlot << 15u) + limbOff;
                const u64* b1 = b0 + (size_t(1) << 15u);
                const u64 q = iv.mMods[limb].mValue;
                const u32 c = static_cast<u32>(kRadix55 - q);
                const u64 twoQ = q << 1u;
                const ShoupOperand* roots =
                    iv.mInvRoots + (static_cast<size_t>(limb) << 13u);

#pragma unroll 1
                for (u32 butterfly = threadIdx.x;
                     butterfly < 4096u;
                     butterfly += 512u)
                {
                    Wide sum0;
                    Wide sum1;
                    {
                        const ulonglong2 aPair =
                            reinterpret_cast<const ulonglong2*>(a0)[butterfly];
                        const ulonglong2 bPair =
                            reinterpret_cast<const ulonglong2*>(b0)[butterfly];
                        sum0 = wideMul(aPair.x, bPair.x);
                        sum1 = wideMul(aPair.y, bPair.y);
                    }
                    {
                        const ulonglong2 aPair =
                            reinterpret_cast<const ulonglong2*>(a1)[butterfly];
                        const ulonglong2 bPair =
                            reinterpret_cast<const ulonglong2*>(b1)[butterfly];
                        sum0 = wideAdd(
                            sum0, wideMul(aPair.x, bPair.x));
                        sum1 = wideAdd(
                            sum1, wideMul(aPair.y, bPair.y));
                    }
                    const u64 u =
                        pointwisePseudo55ReduceWideCanonical<2u>(
                            sum0, q, c);
                    const u64 v =
                        pointwisePseudo55ReduceWideCanonical<2u>(
                            sum1, q, c);

                    const ShoupOperand r = roots[1u + butterfly];
                    u64 lo = nttGuard(u + v, twoQ);
                    u64 hi = mulShoupLazy(u + twoQ - v, r, q);
                    nttInverseWarpStage8192<1u>(
                        lo, hi, roots, butterfly, q, twoQ);
                    nttInverseWarpStage8192<2u>(
                        lo, hi, roots, butterfly, q, twoQ);
                    nttInverseWarpStage8192<3u>(
                        lo, hi, roots, butterfly, q, twoQ);
                    nttInverseWarpStage8192<4u>(
                        lo, hi, roots, butterfly, q, twoQ);
                    nttInverseWarpStage8192<5u>(
                        lo, hi, roots, butterfly, q, twoQ);

                    constexpr u32 gap = 32u;
                    const u32 s5Ix =
                        butterfly + ((butterfly >> 5u) << 5u);
                    sh[s5Ix] = lo;
                    sh[s5Ix + gap] = hi;
                }
            }
            __syncthreads();

            const u64 q = iv.mMods[limb].mValue;
            const u64 twoQ = q << 1u;
            const ShoupOperand* roots =
                iv.mInvRoots + (static_cast<size_t>(limb) << 13u);
            nttInverseStage8192<6u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<7u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<8u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<9u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<10u, true, true>(sh, roots, q, twoQ);
            nttInverseStage8192<11u, true, true>(sh, roots, q, twoQ);

            constexpr u32 gap = 4096u;
            const ShoupOperand scalar =
                nttLoadShoup<true>(iv.mInvDegree + limb);
            const ShoupOperand scaledR =
                nttLoadShoup<true>(iv.mScaledInvRoot + limb);
            const size_t off =
                (static_cast<size_t>(slot) << 15u) +
                (static_cast<size_t>(limb) << 13u);
            u64* dst = out + off;
            for (u32 j = threadIdx.x; j < gap; j += 512u)
            {
                const u64 u = nttGuard(sh[j], twoQ);
                const u64 v = sh[j + gap];

                u64 x = mulShoupLazy(
                    nttGuard(u + v, twoQ), scalar, q);
                if (x >= q) x -= q;
                dst[j] = nttInverseFixedPost8192<2u>(
                    x, nullptr, j, q);

                x = mulShoupLazy(u + twoQ - v, scaledR, q);
                if (x >= q) x -= q;
                dst[j + gap] = nttInverseFixedPost8192<2u>(
                    x, nullptr, j + gap, q);
            }
        }

        // Fixed recursive-leaf sidecar for the production rho4/eight-leaf tree.
        // One CTA owns one logical leaf and therefore exactly one active parent
        // limb plus its XOR-2 zero limb. It also caches the diagonal NTT digit
        // back into the compact recursive input for the matching expand.
        __global__ __launch_bounds__(512, 3)
        void nttInverseRecursiveLeafSparseNegateKernel(
            DeviceInverseRho4 iv,
            const u64* nodes,
            const u64* leafB,
            u64* packed,
            u64* out)
        {
            extern __shared__ u64 sh[];
            const u32 logical = blockIdx.x;
            const u32 leaf = logical & 7u;
            const u32 limb = leaf & 3u;
            const u32 parent = logical >> 1u;

            {
                constexpr size_t perPoly = size_t(4u) << 13u;
                const u32 chunk = logical >> 3u;
                const u32 physical = logical >> 2u;
                const size_t nodeSlot =
                    static_cast<size_t>(chunk) * 15u + 7u + leaf;
                const size_t limbOff = static_cast<size_t>(limb) << 13u;
                const u64* digit = nodes + nodeSlot * perPoly + limbOff;
                u64* packedDst =
                    packed + static_cast<size_t>(physical) * perPoly + limbOff;
                const u64* b = leafB +
                    static_cast<size_t>(leaf & 1u) * perPoly + limbOff;
                const GpuModulus mod = iv.mMods[limb];
                const u64 q = mod.mValue;
                const u64 twoQ = q << 1u;
                const ShoupOperand* roots =
                    iv.mInvRoots + (static_cast<size_t>(limb) << 13u);

                // Fold the two canonical products directly into inverse S0,
                // matching the accepted fixed tree sidecar's lazy ranges and
                // root index exactly.
#pragma unroll 1
                for (u32 butterfly = threadIdx.x;
                     butterfly < 4096u;
                     butterfly += 512u)
                {
                    const u32 ix = butterfly << 1u;
                    const u64 d0 = digit[ix];
                    const u64 d1 = digit[ix + 1u];
                    packedDst[ix] = d0;
                    packedDst[ix + 1u] = d1;

                    const u64 u = mulMod(b[ix], d0, mod);
                    const u64 v = mulMod(b[ix + 1u], d1, mod);
                    sh[ix] = nttGuard(u + v, twoQ);
                    const ShoupOperand r = roots[1u + butterfly];
                    sh[ix + 1u] =
                        mulShoupLazy(u + twoQ - v, r, q);
                }
            }
            // S0..S4 are warp-private for the fixed simple-index mapping.
            __syncwarp();
            nttInverseFixedIpTransform8192<2u, true, true>(
                iv, sh, out, nullptr, limb, parent);

            // The legacy self-zero sidecar transforms a literal-zero opposite
            // limb. INTT(0) followed by zero-safe negation is still exactly zero.
            constexpr size_t perPoly = size_t(4u) << 13u;
            u64* zeroDst =
                out + static_cast<size_t>(parent) * perPoly +
                (static_cast<size_t>(limb ^ 2u) << 13u);
#pragma unroll 1
            for (u32 coeff = threadIdx.x; coeff < 8192u; coeff += 512u)
                zeroDst[coeff] = 0u;
        }

        // Candidate producer for the sparse-pair Hi110 consumer. This is kept as
        // a separate symbol so the accepted kernel above remains codegen-stable.
        // It materializes the active inverse limb and the complete packed NTT
        // digit exactly as above, but deliberately leaves the algebraically-zero
        // complementary output limb untouched.
        __global__ __launch_bounds__(512, 3)
        void nttInverseRecursiveLeafSparseNegateNoZeroKernel(
            DeviceInverseRho4 iv,
            const u64* nodes,
            const u64* leafB,
            u64* packed,
            u64* out)
        {
            extern __shared__ u64 sh[];
            const u32 logical = blockIdx.x;
            const u32 leaf = logical & 7u;
            const u32 limb = leaf & 3u;
            const u32 parent = logical >> 1u;

            {
                constexpr size_t perPoly = size_t(4u) << 13u;
                const u32 chunk = logical >> 3u;
                const u32 physical = logical >> 2u;
                const size_t nodeSlot =
                    static_cast<size_t>(chunk) * 15u + 7u + leaf;
                const size_t limbOff = static_cast<size_t>(limb) << 13u;
                const u64* digit = nodes + nodeSlot * perPoly + limbOff;
                u64* packedDst =
                    packed + static_cast<size_t>(physical) * perPoly + limbOff;
                const u64* b = leafB +
                    static_cast<size_t>(leaf & 1u) * perPoly + limbOff;
                const GpuModulus mod = iv.mMods[limb];
                const u64 q = mod.mValue;
                const u64 twoQ = q << 1u;
                const ShoupOperand* roots =
                    iv.mInvRoots + (static_cast<size_t>(limb) << 13u);

#pragma unroll 1
                for (u32 butterfly = threadIdx.x;
                     butterfly < 4096u;
                     butterfly += 512u)
                {
                    const u32 ix = butterfly << 1u;
                    const u64 d0 = digit[ix];
                    const u64 d1 = digit[ix + 1u];
                    packedDst[ix] = d0;
                    packedDst[ix + 1u] = d1;

                    const u64 u = mulMod(b[ix], d0, mod);
                    const u64 v = mulMod(b[ix + 1u], d1, mod);
                    sh[ix] = nttGuard(u + v, twoQ);
                    const ShoupOperand r = roots[1u + butterfly];
                    sh[ix + 1u] =
                        mulShoupLazy(u + twoQ - v, r, q);
                }
            }
            __syncwarp();
            nttInverseFixedIpTransform8192<2u, true, true>(
                iv, sh, out, nullptr, limb, parent);
        }

        // Candidate-only copy of the accepted no-zero sparse-leaf producer.
        // Only its two independent canonical products use the pseudo55 fold;
        // packed ownership, inverse stages and the intentionally untouched
        // complementary limb remain identical.
        __global__ __launch_bounds__(512, 3)
        void nttInverseRecursiveLeafSparseNegateNoZeroPseudo55Kernel(
            DeviceInverseRho4 iv,
            const u64* nodes,
            const u64* leafB,
            u64* packed,
            u64* out)
        {
            extern __shared__ u64 sh[];
            const u32 logical = blockIdx.x;
            const u32 leaf = logical & 7u;
            const u32 limb = leaf & 3u;
            const u32 parent = logical >> 1u;

            {
                constexpr size_t perPoly = size_t(4u) << 13u;
                constexpr u64 kRadix55 = u64{ 1 } << 55u;
                const u32 chunk = logical >> 3u;
                const u32 physical = logical >> 2u;
                const size_t nodeSlot =
                    static_cast<size_t>(chunk) * 15u + 7u + leaf;
                const size_t limbOff = static_cast<size_t>(limb) << 13u;
                const u64* digit = nodes + nodeSlot * perPoly + limbOff;
                u64* packedDst =
                    packed + static_cast<size_t>(physical) * perPoly + limbOff;
                const u64* b = leafB +
                    static_cast<size_t>(leaf & 1u) * perPoly + limbOff;
                const u64 q = iv.mMods[limb].mValue;
                const u32 c = static_cast<u32>(kRadix55 - q);
                const u64 twoQ = q << 1u;
                const ShoupOperand* roots =
                    iv.mInvRoots + (static_cast<size_t>(limb) << 13u);

#pragma unroll 1
                for (u32 butterfly = threadIdx.x;
                     butterfly < 4096u;
                     butterfly += 512u)
                {
                    const u32 ix = butterfly << 1u;
                    const u64 d0 = digit[ix];
                    const u64 d1 = digit[ix + 1u];
                    packedDst[ix] = d0;
                    packedDst[ix + 1u] = d1;

                    const u64 u =
                        pointwisePseudo55ReduceWideCanonical<1u>(
                            wideMul(b[ix], d0), q, c);
                    const u64 v =
                        pointwisePseudo55ReduceWideCanonical<1u>(
                            wideMul(b[ix + 1u], d1), q, c);
                    sh[ix] = nttGuard(u + v, twoQ);
                    const ShoupOperand r = roots[1u + butterfly];
                    sh[ix + 1u] =
                        mulShoupLazy(u + twoQ - v, r, q);
                }
            }
            __syncwarp();
            nttInverseFixedIpTransform8192<2u, true, true>(
                iv, sh, out, nullptr, limb, parent);
        }

        // Inverse negacyclic NTT. Reproduces DWTHandler::transform_from_rev with
        // the inv_degree scalar merged into the last stage, then the single
        // conditional subtraction from inverse_ntt_negacyclic_harvey.
        //
        // Optionally fuses one elementwise operation into the shared-memory load
        // and one into the store:
        //     sh   = preOp(src, preB)      before the transform
        //     src  = postOp(result, postB) after it
        // The kernel already streams the whole limb through shared memory, so a
        // fused operation costs one extra global read and nothing else, against a
        // separate elementwiseKernel launch that reads two arrays and writes a
        // third. Semantics match elementwiseKernel exactly (ElemOp encoding).
        // Tiled the same way as the forward kernel, mirrored: transform_from_rev
        // starts with gap = 1, so it is the *last* log2(tiles) stages that cross
        // tiles. Those are run by nttInverseCrossKernel and nttInverseFinalKernel,
        // and with tiles > 1 this kernel leaves its tile in the lazy [0, 2q)
        // representation those kernels expect, deferring the 1/n scalar and the
        // fused post-operation to the final stage.
        //
        // Root index of a local stage: i_global = tileIdx * m_local + i_local with
        // m_global = tiles * m_local, so the global rootBase n - 2*m_global + 1
        // becomes n - 2*tiles*m_local + 1 + tileIdx*m_local + i_local.
        template<
            bool HasFusedIp,
            bool Fixed8192 = false,
            u32 FixedRho = 0u,
            bool SimpleIndex = false,
            u32 FixedPostOp = kElemOpNone,
            bool FusedLastTwoStages = false,
            bool VectorShoupLoads = false>
        __device__ __forceinline__ void nttInverseBody(
            DeviceRing rg,
            u64* data,
            const u32* polyIdx,
            u32 preOp,
            const u64* preB,
            u32 postOp,
            const u64* postB,
            NttFusedIp ip,
            u32 logTiles,
            bool fusedFirstStage = false)
        {
            extern __shared__ u64 sh[];

            static_assert(!Fixed8192 || !HasFusedIp);
            static_assert(
                (!Fixed8192 && FixedRho == 0u) ||
                (Fixed8192 && (FixedRho == 1u || FixedRho == 4u)));
            static_assert(!SimpleIndex || Fixed8192);
            static_assert(
                FixedPostOp == kElemOpNone || FixedPostOp == 0u ||
                FixedPostOp == 2u || FixedPostOp == 4u);
            static_assert(
                FixedPostOp == kElemOpNone ||
                (Fixed8192 && FixedRho == 4u && !HasFusedIp));
            static_assert(
                !FusedLastTwoStages ||
                (Fixed8192 && FixedRho == 4u && SimpleIndex && !HasFusedIp &&
                 (FixedPostOp == 0u || FixedPostOp == 2u ||
                  FixedPostOp == 4u)));
            static_assert(!VectorShoupLoads || (Fixed8192 && SimpleIndex));
            const u32 n = Fixed8192 ? 8192u : rg.mN;
            const u32 tiles = Fixed8192 ? 1u : (1u << logTiles);
            const u32 tileLen = Fixed8192 ? 8192u : (n >> logTiles);
            const u32 logTileLen = Fixed8192 ? 13u : (rg.mLogN - logTiles);

            const u32 tileIdx = Fixed8192 ? 0u : (blockIdx.x & (tiles - 1u));
            const u32 rest = Fixed8192 ? blockIdx.x : (blockIdx.x >> logTiles);
            const u32 rho = FixedRho == 0u ? rg.mRho : FixedRho;
            u32 limb;
            u32 slot;
            if constexpr (FixedRho == 1u)
            {
                limb = 0u;
                slot = rest;
            }
            else if constexpr (FixedRho == 4u)
            {
                limb = rest & 3u;
                slot = rest >> 2u;
            }
            else
            {
                limb = rest % rho;
                slot = rest / rho;
            }
            const u32 poly = polyIdx ? polyIdx[slot] : slot;

            const u32 tileBase = tileIdx * tileLen;
            const size_t off =
                (static_cast<size_t>(poly) * rho + limb) * n + static_cast<size_t>(tileBase);
            u64* src = data + off;
            const ShoupOperand* roots = rg.mInvRoots + static_cast<size_t>(limb) * n;
            const u64 q = rg.mMods[limb].mValue;
            const u64 twoQ = q << 1;

            if constexpr (Fixed8192 && FixedPostOp != kElemOpNone)
            {
                // Every fixed direct-store tuple is dispatched only with
                // pre=None. Its inverse S0 has gap=1, so one thread can load
                // both adjacent coefficients and publish S0 directly. The
                // warp handoff is the exact trailing synchronization used by
                // nttInverseStage8192<0>.
                if (fusedFirstStage)
                {
                    constexpr u32 gap = 1u;
                    constexpr u32 rootBase = 1u;
                    for (u32 butterfly = threadIdx.x;
                         butterfly < 4096u;
                         butterfly += blockDim.x)
                    {
                        const u32 ix = butterfly << 1u;
                        const ShoupOperand r = nttLoadShoup<VectorShoupLoads>(
                            roots + rootBase + butterfly);
                        const u64 u = src[ix];
                        const u64 v = src[ix + gap];
                        sh[ix] = nttGuard(u + v, twoQ);
                        sh[ix + gap] = mulShoupLazy(u + twoQ - v, r, q);
                    }
                    __syncwarp();
                }
                else
                {
                    for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                        sh[t] = src[t];
                    __syncthreads();
                }
            }
            else if constexpr (HasFusedIp)
            {
                // The inner product this transform's input used to come from,
                // evaluated in place. Same accumulation order and helpers as
                // innerProductKernel, so sh[] receives exactly the words that
                // kernel would have written to `src`.
                const GpuModulus mod = rg.mMods[limb];
                const size_t perPoly = static_cast<size_t>(rho) * n;
                const size_t limbOff = static_cast<size_t>(limb) * n + tileBase;
                const size_t idxBase = static_cast<size_t>(slot) * ip.mTerms;
                const u32 terms = ip.mTerms;
                for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                {
                    u64 acc = 0;
                    for (u32 k = 0; k < terms; ++k)
                    {
                        const u32 ai = ip.mAIdx ? ip.mAIdx[idxBase + k] : k;
                        const u32 bi = ip.mBIdx ? ip.mBIdx[idxBase + k] : k;
                        const u64 av = ip.mA[static_cast<size_t>(ai) * perPoly + limbOff + t];
                        const u64 bv = ip.mB[static_cast<size_t>(bi) * perPoly + limbOff + t];
                        acc = mulAddMod(av, bv, acc, mod);
                    }
                    if (ip.mMode == NttFusedIp::Accumulate)
                        acc = addMod(src[t], acc, q);
                    else if (ip.mMode == NttFusedIp::Subtract)
                        acc = subMod(src[t], acc, q);
                    sh[t] = acc;
                }
            }
            else
            {
                if (preOp == kElemOpNone)
                {
                    for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x) sh[t] = src[t];
                }
                else
                {
                    const u64* b = preB + off;
                    for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                    {
                        const u64 av = src[t];
                        sh[t] = (preOp == 0u) ? addMod(av, b[t], q) : subMod(av, b[t], q);
                    }
                }
                __syncthreads();
            }

            if constexpr (HasFusedIp)
                __syncthreads();

            const u32 half = tileLen >> 1;
            if constexpr (Fixed8192)
            {
                if constexpr (FixedPostOp != kElemOpNone)
                {
                    if (!fusedFirstStage)
                        nttInverseStage8192<0, SimpleIndex, VectorShoupLoads>(
                            sh, roots, q, twoQ);
                }
                else
                {
                    nttInverseStage8192<0, SimpleIndex, VectorShoupLoads>(
                        sh, roots, q, twoQ);
                }
                nttInverseStage8192<1, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttInverseStage8192<2, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttInverseStage8192<3, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttInverseStage8192<4, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttInverseStage8192<5, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttInverseStage8192<6, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttInverseStage8192<7, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttInverseStage8192<8, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttInverseStage8192<9, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                nttInverseStage8192<10, SimpleIndex, VectorShoupLoads>(
                    sh, roots, q, twoQ);
                if constexpr (!FusedLastTwoStages)
                    nttInverseStage8192<11, SimpleIndex, VectorShoupLoads>(
                        sh, roots, q, twoQ);
            }
            else
            {
                // Stages with local m = tileLen/2 down to m = 1 (tiles == 1) or down to
                // m = 1 within the tile (tiles > 1, where the crossing stages follow).
                const u32 localStages = (tiles == 1u) ? (logTileLen - 1u) : logTileLen;
                for (u32 s = 0; s < localStages; ++s)
                {
                    const u32 m = tileLen >> (s + 1u);
                    const u32 logGap = s;
                    const u32 gap = 1u << logGap;
                    const u32 rootBase = n - 2u * tiles * m + 1u + tileIdx * m;
                    for (u32 b = threadIdx.x; b < half; b += blockDim.x)
                    {
                        const u32 i = b >> logGap;
                        const u32 j = b & (gap - 1u);
                        const u32 ix = (i << (logGap + 1u)) + j;
                        const ShoupOperand r = roots[rootBase + i];
                        const u64 u = sh[ix];
                        const u64 v = sh[ix + gap];
                        sh[ix] = nttGuard(u + v, twoQ);
                        sh[ix + gap] = mulShoupLazy(u + twoQ - v, r, q);
                    }
                    __syncthreads();
                }
            }

            if (tiles != 1u)
            {
                // Hand the tile over in the same lazy [0, 2q) representation the
                // shared-memory stages use internally, so the crossing stages see
                // exactly the words they would have read from shared memory.
                for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x) src[t] = sh[t];
                return;
            }

            if constexpr (FixedPostOp != kElemOpNone)
            {
                // Fixed N=8192 final stage: every j owns both coefficients. The
                // staged body consumes S11 shared output after its block barrier;
                // the fused body consumes its private S11 results directly.
                constexpr u32 gap = 4096u;
                const ShoupOperand scalar = nttLoadShoup<VectorShoupLoads>(
                    rg.mInvDegree + limb);
                const ShoupOperand scaledR = nttLoadShoup<VectorShoupLoads>(
                    rg.mScaledInvRoot + limb);
                const u64* b = nullptr;
                if constexpr (FixedPostOp == 0u || FixedPostOp == 4u)
                    b = postB + off;
                if constexpr (FusedLastTwoStages)
                {
                    nttInverseFusedTail8192<FixedPostOp, VectorShoupLoads>(
                        sh, src, b, roots, scalar, scaledR, q, twoQ);
                }
                else
                {
                    for (u32 j = threadIdx.x; j < gap; j += blockDim.x)
                    {
                        const u64 u = nttGuard(sh[j], twoQ);
                        const u64 v = sh[j + gap];

                        // Serialize the two output lifetimes: this fixed inverse is
                        // hard-capped at 32 registers, and the B-using post-ops must
                        // not make both canonical results and operands live together.
                        u64 x = mulShoupLazy(nttGuard(u + v, twoQ), scalar, q);
                        if (x >= q) x -= q;
                        src[j] = nttInverseFixedPost8192<FixedPostOp>(x, b, j, q);

                        x = mulShoupLazy(u + twoQ - v, scaledR, q);
                        if (x >= q) x -= q;
                        src[j + gap] = nttInverseFixedPost8192<FixedPostOp>(
                            x, b, j + gap, q);
                    }
                }
            }
            else
            {
                // Final stage: m = 1, gap = n/2, with the 1/n scalar folded in.
                {
                    const u32 gap = half;
                    const ShoupOperand scalar = nttLoadShoup<VectorShoupLoads>(
                        rg.mInvDegree + limb);
                    const ShoupOperand scaledR = nttLoadShoup<VectorShoupLoads>(
                        rg.mScaledInvRoot + limb);
                    for (u32 j = threadIdx.x; j < gap; j += blockDim.x)
                    {
                        const u64 u = nttGuard(sh[j], twoQ);
                        const u64 v = sh[j + gap];
                        sh[j] = mulShoupLazy(nttGuard(u + v, twoQ), scalar, q);
                        sh[j + gap] = mulShoupLazy(u + twoQ - v, scaledR, q);
                    }
                    __syncthreads();
                }

                if (postOp == kElemOpNone)
                {
                    for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                    {
                        u64 x = sh[t];
                        if (x >= q) x -= q;
                        src[t] = x;
                    }
                }
                else
                {
                    const u64* b = postB ? postB + off : nullptr;
                    for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                    {
                        u64 x = sh[t];
                        if (x >= q) x -= q;
                        if (postOp == 2u)
                            x = (x == 0) ? 0 : (q - x);
                        else if (postOp == 4u)
                            x = subMod(b[t], x, q);
                        else
                            x = (postOp == 0u) ? addMod(x, b[t], q) : subMod(x, b[t], q);
                        src[t] = x;
                    }
                }
            }
        }

        // Keep the generic kernel unconstrained. __maxnreg__(0) is invalid,
        // and substituting 255 would override a caller's --maxrregcount.
        // Both entry points inline the same butterfly body with no device call.
        template<bool HasFusedIp>
        __global__ void nttInverseKernel(
            DeviceRing rg,
            u64* data,
            const u32* polyIdx,
            u32 preOp,
            const u64* preB,
            u32 postOp,
            const u64* postB,
            NttFusedIp ip,
            u32 logTiles,
            bool fusedFirstStage = false)
        {
            nttInverseBody<HasFusedIp>(rg, data, polyIdx, preOp, preB,
                postOp, postB, ip, logTiles, fusedFirstStage);
        }

        template<u32 FixedRho, bool SimpleIndex = false,
            u32 FixedPostOp = kElemOpNone, bool FusedLastTwoStages = false,
            bool VectorShoupLoads = false>
        __global__ __maxnreg__(FusedLastTwoStages ? 40 : 32)
        void nttInverseFixed8192Kernel(
            DeviceRing rg,
            u64* data,
            const u32* polyIdx,
            u32 preOp,
            const u64* preB,
            u32 postOp,
            const u64* postB,
            NttFusedIp ip,
            u32 logTiles,
            bool fusedFirstStage = false)
        {
            nttInverseBody<false, true, FixedRho, SimpleIndex, FixedPostOp,
                FusedLastTwoStages, VectorShoupLoads>(rg, data, polyIdx,
                    preOp, preB, postOp, postB, ip, logTiles, fusedFirstStage);
        }

        // The one-tile plaintext inverse used by the common wrap path, with both
        // adjacent materialisations removed. Legacy scatter establishes
        //
        //   plain[slotMap[i]] = labels[i],
        //
        // so coefficient k can be loaded directly from labels[inverseSlotMap[k]].
        // Once the final inverse stage owns a canonical coefficient, the unscaled
        // CRT lift is only a byte-for-byte broadcast to every output limb. Doing
        // both at the transform boundaries removes four N-word scratch passes and
        // the N-word-per-chunk allocation without changing any butterfly.
        //
        // This intentionally handles one shared-memory tile only. The N=16384
        // NoGolden transform has a crossing stage and keeps the materialised
        // fallback until it gets its own register-parked implementation.
        __device__ __forceinline__ u64 garbledInputSlot(
            const u64* labels, u64 count, u32 chunk, u32 n, u32 slot)
        {
            const u32 perRing = n / 3;
            const u64 src = static_cast<u64>(chunk) * perRing + slot / 3;
            return slot < perRing * 3 && src < count ? labels[src] : 0;
        }

        __global__ __launch_bounds__(kNttThreads) void nttInverseScatterBroadcastKernel(
            DeviceRing rg,
            const u64* __restrict__ labels,
            u64 labelCount,
            u64 padValue,
            const u32* __restrict__ inverseSlotMap,
            u32 storageRho,
            u32 writeRho,
            u64* __restrict__ out,
            bool garbledInput)
        {
            extern __shared__ u64 sh[];

            const u32 n = rg.mN;
            const u32 chunk = blockIdx.x;
            const size_t labelBase = static_cast<size_t>(chunk) * n;
            const bool fullChunk = labelBase + n <= labelCount;

            for (u32 t = threadIdx.x; t < n; t += blockDim.x)
            {
                const size_t src = labelBase + inverseSlotMap[t];
                sh[t] = garbledInput
                    ? garbledInputSlot(labels, labelCount, chunk, n, inverseSlotMap[t])
                    : ((fullChunk || src < labelCount) ? labels[src] : padValue);
            }
            __syncthreads();

            const ShoupOperand* roots = rg.mInvRoots;
            const u64 q = rg.mMods[0].mValue;
            const u64 twoQ = q << 1;
            const u32 half = n >> 1;

            // Same stages, root indices, lazy ranges and barriers as the tiles==1
            // specialization of nttInverseKernel<false>. Leave m=1 for the final
            // scaled stage below.
            for (u32 s = 0; s + 1u < rg.mLogN; ++s)
            {
                const u32 m = n >> (s + 1u);
                const u32 gap = 1u << s;
                const u32 rootBase = n - 2u * m + 1u;
                for (u32 b = threadIdx.x; b < half; b += blockDim.x)
                {
                    const u32 i = b >> s;
                    const u32 j = b & (gap - 1u);
                    const u32 ix = (i << (s + 1u)) + j;
                    const ShoupOperand r = roots[rootBase + i];
                    const u64 u = sh[ix];
                    const u64 v = sh[ix + gap];
                    sh[ix] = nttGuard(u + v, twoQ);
                    sh[ix + gap] = mulShoupLazy(u + twoQ - v, r, q);
                }
                __syncthreads();
            }

            // Final m=1 stage with 1/n folded in, followed by the same single
            // conditional subtraction as inverse_ntt_negacyclic_harvey. Each
            // thread owns both outputs of its butterfly, so they can go straight
            // to every target limb without another shared-memory round trip.
            const ShoupOperand scalar = rg.mInvDegree[0];
            const ShoupOperand scaledR = rg.mScaledInvRoot[0];
            u64* const outBase =
                out + static_cast<size_t>(chunk) * storageRho * static_cast<size_t>(n);
            for (u32 j = threadIdx.x; j < half; j += blockDim.x)
            {
                const u64 u = nttGuard(sh[j], twoQ);
                const u64 v = sh[j + half];
                u64 x0 = mulShoupLazy(nttGuard(u + v, twoQ), scalar, q);
                u64 x1 = mulShoupLazy(u + twoQ - v, scaledR, q);
                if (x0 >= q) x0 -= q;
                if (x1 >= q) x1 -= q;

                u64* dst = outBase + j;
#pragma unroll 1
                for (u32 limb = 0; limb < writeRho; ++limb)
                {
                    dst[0] = x0;
                    dst[half] = x1;
                    dst += n;
                }
            }
        }

        // Fixed production shape of the plaintext wrap boundary above. The
        // permutation gather feeds inverse S0 directly, so its raw coefficients
        // never make a shared-memory round trip. S0..S4 are warp-local under the
        // fixed butterfly/thread mapping; only S5..S11 retain CTA barriers. The
        // final scaled stage broadcasts its two canonical outputs to four limbs
        // with no runtime loop or shared-memory tail.
        __global__ __launch_bounds__(kNttThreads, 2)
        void nttInverseScatterBroadcast8192Rho4Kernel(
            DeviceInverseRho4 iv,
            const u64* __restrict__ labels,
            u64 labelCount,
            u64 padValue,
            const u32* __restrict__ inverseSlotMap,
            u64* __restrict__ out,
            bool garbledInput)
        {
            extern __shared__ u64 sh[];

            constexpr u32 n = 8192u;
            constexpr u32 half = n >> 1u;
            const u32 chunk = blockIdx.x;
            const size_t labelBase = static_cast<size_t>(chunk) * n;
            const bool fullChunk = labelBase + n <= labelCount;
            const ShoupOperand* roots = iv.mInvRoots;
            const u64 q = iv.mMods[0].mValue;
            const u64 twoQ = q << 1u;

            // Fixed inverse S0 has gap=1 and one root per adjacent pair. Each
            // thread owns both permutation loads and both outputs. This is the
            // identical load/pad and butterfly arithmetic of the generic gather
            // followed by its first transform stage.
            for (u32 b = threadIdx.x; b < half; b += blockDim.x)
            {
                const u32 ix = b << 1u;
                const size_t src0 = labelBase + inverseSlotMap[ix];
                const size_t src1 = labelBase + inverseSlotMap[ix + 1u];
                const u64 u = garbledInput
                    ? garbledInputSlot(labels, labelCount, chunk, n, inverseSlotMap[ix])
                    : ((fullChunk || src0 < labelCount) ? labels[src0] : padValue);
                const u64 v = garbledInput
                    ? garbledInputSlot(labels, labelCount, chunk, n, inverseSlotMap[ix + 1u])
                    : ((fullChunk || src1 < labelCount) ? labels[src1] : padValue);
                const ShoupOperand r = roots[1u + b];
                sh[ix] = nttGuard(u + v, twoQ);
                sh[ix + 1u] = mulShoupLazy(u + twoQ - v, r, q);
            }
            __syncwarp();

            nttInverseStage8192<1u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<2u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<3u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<4u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<5u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<6u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<7u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<8u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<9u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<10u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<11u, true>(sh, roots, q, twoQ);

            const ShoupOperand scalar = iv.mInvDegree[0];
            const ShoupOperand scaledR = iv.mScaledInvRoot[0];
            u64* const outBase =
                out + static_cast<size_t>(chunk) * 4u * static_cast<size_t>(n);
            for (u32 j = threadIdx.x; j < half; j += blockDim.x)
            {
                const u64 u = nttGuard(sh[j], twoQ);
                const u64 v = sh[j + half];
                u64 x0 = mulShoupLazy(nttGuard(u + v, twoQ), scalar, q);
                u64 x1 = mulShoupLazy(u + twoQ - v, scaledR, q);
                if (x0 >= q) x0 -= q;
                if (x1 >= q) x1 -= q;

#pragma unroll
                for (u32 limb = 0u; limb < 4u; ++limb)
                {
                    const size_t limbBase = static_cast<size_t>(limb) * n;
                    outBase[limbBase + j] = x0;
                    outBase[limbBase + j + half] = x1;
                }
            }
        }

        // Candidate-only fixed wrap inverse. Arithmetic and synchronization are
        // identical to the accepted simple-index body above; its sole semantic
        // difference is that the byte-identical RNS broadcast is represented by
        // limb 0 until the proven identity-forward consumer reads it.
        __global__ __launch_bounds__(kNttThreads, 2)
        void nttInverseScatterSingleLimb8192Rho4Kernel(
            DeviceInverseRho4 iv,
            const u64* __restrict__ labels,
            u64 labelCount,
            u64 padValue,
            const u32* __restrict__ inverseSlotMap,
            u64* __restrict__ out,
            bool garbledInput)
        {
            extern __shared__ u64 sh[];

            constexpr u32 n = 8192u;
            constexpr u32 half = n >> 1u;
            const u32 chunk = blockIdx.x;
            const size_t labelBase = static_cast<size_t>(chunk) * n;
            const bool fullChunk = labelBase + n <= labelCount;
            const ShoupOperand* roots = iv.mInvRoots;
            const u64 q = iv.mMods[0].mValue;
            const u64 twoQ = q << 1u;

            for (u32 b = threadIdx.x; b < half; b += blockDim.x)
            {
                const u32 ix = b << 1u;
                const size_t src0 = labelBase + inverseSlotMap[ix];
                const size_t src1 = labelBase + inverseSlotMap[ix + 1u];
                const u64 u = garbledInput
                    ? garbledInputSlot(labels, labelCount, chunk, n, inverseSlotMap[ix])
                    : ((fullChunk || src0 < labelCount) ? labels[src0] : padValue);
                const u64 v = garbledInput
                    ? garbledInputSlot(labels, labelCount, chunk, n, inverseSlotMap[ix + 1u])
                    : ((fullChunk || src1 < labelCount) ? labels[src1] : padValue);
                const ShoupOperand r = roots[1u + b];
                sh[ix] = nttGuard(u + v, twoQ);
                sh[ix + 1u] = mulShoupLazy(u + twoQ - v, r, q);
            }
            __syncwarp();

            nttInverseStage8192<1u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<2u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<3u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<4u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<5u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<6u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<7u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<8u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<9u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<10u, true>(sh, roots, q, twoQ);
            nttInverseStage8192<11u, true>(sh, roots, q, twoQ);

            const ShoupOperand scalar = iv.mInvDegree[0];
            const ShoupOperand scaledR = iv.mScaledInvRoot[0];
            u64* const outBase =
                out + static_cast<size_t>(chunk) * 4u * static_cast<size_t>(n);
            for (u32 j = threadIdx.x; j < half; j += blockDim.x)
            {
                const u64 u = nttGuard(sh[j], twoQ);
                const u64 v = sh[j + half];
                u64 x0 = mulShoupLazy(nttGuard(u + v, twoQ), scalar, q);
                u64 x1 = mulShoupLazy(u + twoQ - v, scaledR, q);
                if (x0 >= q) x0 -= q;
                if (x1 >= q) x1 -= q;
                outBase[j] = x0;
                outBase[j + half] = x1;
            }
        }

        __global__ void materializePlainBroadcastKernel(
            u64* data, u32 polyCount, u32 n, u32 rho)
        {
            const size_t linear =
                static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
            const size_t count = static_cast<size_t>(polyCount) * n;
            if (linear >= count) return;
            const size_t poly = linear / n;
            const size_t coeff = linear - poly * n;
            u64* const base = data + poly * rho * n;
            const u64 value = base[coeff];
            for (u32 limb = 1u; limb < rho; ++limb)
                base[static_cast<size_t>(limb) * n + coeff] = value;
        }

        // Two-tile inverse in one launch: one block per (polynomial, limb), which
        // needs both halves of the limb but has shared memory for only one.
        //
        // The trick is that the single crossing stage (the last one, gap = n/2)
        // pairs element j of the first half with element j of the second half, and
        // if thread t owns the contiguous range [t*kInvRegs, (t+1)*kInvRegs) then
        // both members of every pair it has to combine are its own. So the second
        // half is transformed first and parked in registers - kInvRegs u64 per
        // thread - and the shared-memory buffer is then reused for the first half.
        //
        // That removes the intermediate write and re-read of the whole limb: traffic
        // is back to one read and one write, the same as the untiled kernel, at the
        // cost of kInvRegs registers per thread. Values are bit-identical: the
        // stages, their order and the lazy representation are unchanged.
        // Block count from which the register-parked inverse is preferred over the
        // split one (a crossing kernel plus the tiled kernel). Same tradeoff as the
        // forward: one block per (poly, limb) halves the traffic but also halves the
        // parallelism, so it wins only once the grid fills the device. Measured at
        // n = 2^24: 90.1 vs 89.8 M VOLE/s per party with and without the threshold.


        // Largest fused inner product whose operand pointers are hoisted into
        // shared memory. The protocol's inner products are over tau, rho or the
        // Root's randomizer width, all small; anything larger falls back to the
        // per-element index read.
        constexpr u32 kMaxFusedIpTerms = 32;

        __device__ __forceinline__ ShoupOperand inverseLog14Root(
            const ShoupOperand* roots, u32 index)
        {
            return nttLoadShoup<true>(roots + index);
        }

        template<u32 Stage, u32 TileIdx>
        __device__ __forceinline__ void nttInverseLog14TileStage(
            u64* sh,
            const ShoupOperand* roots,
            u64 q,
            u64 twoQ)
        {
            static_assert(Stage < 13u);
            static_assert(TileIdx < 2u);
            constexpr u32 gap = 1u << Stage;
            constexpr u32 m = 8192u >> (Stage + 1u);
            constexpr u32 rootBase =
                16384u - 4u * m + 1u + TileIdx * m;
            for (u32 b = threadIdx.x; b < 4096u; b += blockDim.x)
            {
                const u32 i = b >> Stage;
                const u32 ix = b + (i << Stage);
                const ShoupOperand r = inverseLog14Root(
                    roots, rootBase + i);
                const u64 u = sh[ix];
                const u64 v = sh[ix + gap];
                sh[ix] = nttGuard(u + v, twoQ);
                sh[ix + gap] = mulShoupLazy(u + twoQ - v, r, q);
            }
            if constexpr (Stage <= 4u)
                __syncwarp();
            else
                __syncthreads();
        }

        template<u32 Stage, u32 TileIdx>
        __device__ __forceinline__ void nttInverseLog14WarpStage(
            u64& lo,
            u64& hi,
            const ShoupOperand* roots,
            u32 butterfly,
            u64 q,
            u64 twoQ)
        {
            static_assert(Stage >= 1u && Stage <= 5u);
            static_assert(TileIdx < 2u);
            constexpr u32 laneMask = 1u << (Stage - 1u);
            constexpr u32 m = 8192u >> (Stage + 1u);
            constexpr u32 rootBase =
                16384u - 4u * m + 1u + TileIdx * m;

            const bool upper = (threadIdx.x & laneMask) != 0u;
            const u64 outbound = upper ? lo : hi;
            const u64 remote = __shfl_xor_sync(
                0xffffffffu, outbound, laneMask);
            const u64 u = upper ? remote : lo;
            const u64 v = upper ? hi : remote;
            const ShoupOperand r = inverseLog14Root(
                roots, rootBase + (butterfly >> Stage));
            lo = nttGuard(u + v, twoQ);
            hi = mulShoupLazy(u + twoQ - v, r, q);
        }

        // Adjacent stages share a four-value ownership group. Carry the first
        // stage directly into the second, eliminating one shared round trip
        // and one CTA barrier without changing the lazy-reduction order.
        template<u32 Stage, u32 TileIdx>
        __device__ __forceinline__ void nttInverseLog14TileStagePair(
            u64* sh, const ShoupOperand* roots, u64 q, u64 twoQ)
        {
            static_assert(Stage >= 6u && Stage <= 11u && TileIdx < 2u);
            constexpr u32 gap = 1u << Stage;
            constexpr u32 m = 8192u >> (Stage + 1u);
            constexpr u32 rootBase = 16384u - 4u * m + 1u + TileIdx * m;
            constexpr u32 nextRootBase =
                16384u - 2u * m + 1u + TileIdx * (m >> 1u);
            for (u32 j = threadIdx.x; j < 2048u; j += blockDim.x)
            {
                // j < 2048 makes the last group's index identically zero.
                // Expose it explicitly so the final twiddles stay uniform.
                const u32 group = Stage == 11u ? 0u : j >> Stage;
                const u32 ix = j + (group << Stage) * 3u;
                u64 lo0, hi0, lo1, hi1;
                {
                    const u64 u = sh[ix], v = sh[ix + gap];
                    const ShoupOperand r = inverseLog14Root(
                        roots, rootBase + group * 2u);
                    lo0 = nttGuard(u + v, twoQ);
                    hi0 = mulShoupLazy(u + twoQ - v, r, q);
                }
                {
                    const u64 u = sh[ix + 2u * gap], v = sh[ix + 3u * gap];
                    const ShoupOperand r = inverseLog14Root(
                        roots, rootBase + group * 2u + 1u);
                    lo1 = nttGuard(u + v, twoQ);
                    hi1 = mulShoupLazy(u + twoQ - v, r, q);
                }
                const ShoupOperand r = inverseLog14Root(
                    roots, nextRootBase + group);
                sh[ix] = nttGuard(lo0 + lo1, twoQ);
                sh[ix + 2u * gap] = mulShoupLazy(lo0 + twoQ - lo1, r, q);
                sh[ix + gap] = nttGuard(hi0 + hi1, twoQ);
                sh[ix + 3u * gap] = mulShoupLazy(hi0 + twoQ - hi1, r, q);
            }
            __syncthreads();
        }

        // The first six inverse stages operate entirely inside 64-value warp
        // tiles. Hold each S0 pair in registers through S5, publish only the S5
        // layout, then finish S6..S12 with either single or paired stages.
        template<u32 TileIdx, bool DirectLoad = false>
        __device__ __forceinline__ void nttInverseLog14TileWarp05(
            u64* sh,
            const ShoupOperand* roots,
            u64 q,
            u64 twoQ,
            const u64* src = nullptr,
            u32 preOp = kElemOpNone,
            const u64* preB = nullptr)
        {
            constexpr u32 s0RootBase = 1u + TileIdx * 4096u;
            for (u32 butterfly = threadIdx.x;
                 butterfly < 4096u;
                 butterfly += blockDim.x)
            {
                const u32 input = butterfly << 1u;
                u64 u, v;
                if constexpr (DirectLoad)
                {
                    // Adjacent global inputs feed S0 directly. The source
                    // remains untouched until both tile transforms finish;
                    // unlike the shared-input path there is no in-place
                    // load/store phase to synchronize inside this warp.
                    const ulonglong2 pair =
                        *reinterpret_cast<const ulonglong2*>(src + input);
                    u = pair.x;
                    v = pair.y;
                    if (preOp != kElemOpNone)
                    {
                        const ulonglong2 b =
                            *reinterpret_cast<const ulonglong2*>(preB + input);
                        u = preOp == 0u ? addMod(u, b.x, q) : subMod(u, b.x, q);
                        v = preOp == 0u ? addMod(v, b.y, q) : subMod(v, b.y, q);
                    }
                }
                else
                {
                    u = sh[input];
                    v = sh[input + 1u];
                    // Each warp owns a disjoint 64-value shared tile.
                    __syncwarp();
                }
                const ShoupOperand r = nttLoadShoup<true>(
                    roots + s0RootBase + butterfly);
                u64 lo = nttGuard(u + v, twoQ);
                u64 hi = mulShoupLazy(u + twoQ - v, r, q);

                nttInverseLog14WarpStage<1u, TileIdx>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttInverseLog14WarpStage<2u, TileIdx>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttInverseLog14WarpStage<3u, TileIdx>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttInverseLog14WarpStage<4u, TileIdx>(
                    lo, hi, roots, butterfly, q, twoQ);
                nttInverseLog14WarpStage<5u, TileIdx>(
                    lo, hi, roots, butterfly, q, twoQ);

                constexpr u32 gap = 32u;
                const u32 output =
                    butterfly + ((butterfly >> 5u) << 5u);
                sh[output] = lo;
                sh[output + gap] = hi;
            }
            __syncthreads();
            nttInverseLog14TileStage<6u, TileIdx>(
                sh, roots, q, twoQ);
            if constexpr (DirectLoad)
            {
                nttInverseLog14TileStagePair<7u, TileIdx>(sh, roots, q, twoQ);
                nttInverseLog14TileStagePair<9u, TileIdx>(sh, roots, q, twoQ);
                nttInverseLog14TileStagePair<11u, TileIdx>(sh, roots, q, twoQ);
            }
            else
            {
                nttInverseLog14TileStage<7u, TileIdx>(
                    sh, roots, q, twoQ);
                nttInverseLog14TileStage<8u, TileIdx>(
                    sh, roots, q, twoQ);
                nttInverseLog14TileStage<9u, TileIdx>(
                    sh, roots, q, twoQ);
                nttInverseLog14TileStage<10u, TileIdx>(
                    sh, roots, q, twoQ);
                nttInverseLog14TileStage<11u, TileIdx>(
                    sh, roots, q, twoQ);
                nttInverseLog14TileStage<12u, TileIdx>(
                    sh, roots, q, twoQ);
            }
        }

        // Fixed H200 NoGoldenSeed inverse. Fused inner products keep the generic
        // path; the production default uses separate high-occupancy IP kernels,
        // so all hot two-tile inverses reach this body. Pre/post operations keep
        // their accepted load/store order and modular arithmetic.
        template<bool DirectLoad>
        __global__ __launch_bounds__(512, 2)
        void nttInverseTwoTile16384Rho8Kernel(
            DeviceRing rg,
            u64* data,
            const u32* polyIdx,
            u32 preOp,
            const u64* preB,
            u32 postOp,
            const u64* postB)
        {
            extern __shared__ u64 sh[];
            constexpr u32 n = 16384u;
            constexpr u32 rho = 8u;
            constexpr u32 tileLen = 8192u;
            constexpr u32 Threads = 512u;
            constexpr u32 parked = tileLen / Threads;

            const u32 limb = blockIdx.x & (rho - 1u);
            const u32 slot = blockIdx.x >> 3u;
            const u32 poly = polyIdx ? polyIdx[slot] : slot;
            const size_t limbOff =
                (static_cast<size_t>(poly) * rho + limb) * n;
            u64* limbBase = data + limbOff;
            const ShoupOperand* roots =
                rg.mInvRoots + static_cast<size_t>(limb) * n;
            const u64 q = rg.mMods[limb].mValue;
            const u64 twoQ = q << 1u;
            u64 hi[parked];
            // Transform and park the high half first.
            {
                u64* src = limbBase + tileLen;
                if constexpr (DirectLoad)
                {
                    nttInverseLog14TileWarp05<1u, true>(
                        sh, roots, q, twoQ, src, preOp,
                        preOp == kElemOpNone ? nullptr : preB + limbOff + tileLen);
                }
                else
                {
                    if (preOp == kElemOpNone)
                    {
                        for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                            sh[t] = src[t];
                    }
                    else
                    {
                        const u64* b = preB + limbOff + tileLen;
                        for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                        {
                            const u64 av = src[t];
                            sh[t] = preOp == 0u
                                ? addMod(av, b[t], q)
                                : subMod(av, b[t], q);
                        }
                    }
                    __syncthreads();
                    nttInverseLog14TileWarp05<1u>(sh, roots, q, twoQ);
                }
#pragma unroll
                for (u32 i = 0; i < parked; ++i)
                    hi[i] = sh[threadIdx.x + i * Threads];
                __syncthreads();
            }

            // Transform the low half in the reused tile.
            {
                if constexpr (DirectLoad)
                {
                    nttInverseLog14TileWarp05<0u, true>(
                        sh, roots, q, twoQ, limbBase, preOp,
                        preOp == kElemOpNone ? nullptr : preB + limbOff);
                }
                else
                {
                    if (preOp == kElemOpNone)
                    {
                        for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                            sh[t] = limbBase[t];
                    }
                    else
                    {
                        const u64* b = preB + limbOff;
                        for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                        {
                            const u64 av = limbBase[t];
                            sh[t] = preOp == 0u
                                ? addMod(av, b[t], q)
                                : subMod(av, b[t], q);
                        }
                    }
                    __syncthreads();
                    nttInverseLog14TileWarp05<0u>(sh, roots, q, twoQ);
                }
            }

            const ShoupOperand scalar = nttLoadShoup<true>(
                rg.mInvDegree + limb);
            const ShoupOperand scaledR = nttLoadShoup<true>(
                rg.mScaledInvRoot + limb);
            const u64* b =
                (postOp != kElemOpNone && postB) ? postB + limbOff : nullptr;
#pragma unroll
            for (u32 i = 0; i < parked; ++i)
            {
                const u32 j = threadIdx.x + i * Threads;
                const u64 u = nttGuard(sh[j], twoQ);
                const u64 v = hi[i];
                u64 x0 = mulShoupLazy(
                    nttGuard(u + v, twoQ), scalar, q);
                u64 x1 = mulShoupLazy(u + twoQ - v, scaledR, q);
                if (x0 >= q) x0 -= q;
                if (x1 >= q) x1 -= q;
                if (postOp == 2u)
                {
                    x0 = x0 == 0u ? 0u : q - x0;
                    x1 = x1 == 0u ? 0u : q - x1;
                }
                else if (postOp == 4u)
                {
                    x0 = subMod(b[j], x0, q);
                    x1 = subMod(b[j + tileLen], x1, q);
                }
                else if (postOp != kElemOpNone)
                {
                    if (postOp == 0u)
                    {
                        x0 = addMod(x0, b[j], q);
                        x1 = addMod(x1, b[j + tileLen], q);
                    }
                    else
                    {
                        x0 = subMod(x0, b[j], q);
                        x1 = subMod(x1, b[j + tileLen], q);
                    }
                }
                limbBase[j] = x0;
                limbBase[j + tileLen] = x1;
            }
        }

        __device__ __forceinline__ double loadFp52Root(const ShoupOperand* roots, u32 index)
        {
            return static_cast<double>(roots[index].mOperand);
        }

        __device__ __forceinline__ double loadFp52Root(const double* roots, u32 index)
        {
            return roots[index];
        }

        template<bool Cached, u32 CacheBase = 8192u, class Root>
        __device__ __forceinline__ double inverseFp52Root(
            const Root* roots, const double* cachedRoots, u32 index)
        {
            if constexpr (Cached) return cachedRoots[index - CacheBase];
            else return loadFp52Root(roots, index);
        }

        template<u32 Stage, bool Cached, u32 TileIdx = 0u, bool TwoTile = false, u32 CacheStage = 2u, class Root>
        __device__ __forceinline__ void inverseFp52WarpStage(
            double& lo, double& hi, const Root* roots, const double* cachedRoots,
            u32 butterfly, double q, double invQ)
        {
            constexpr u32 mask = 1u << (Stage - 1u);
            constexpr u32 rootBase = 16384u - (16384u >> Stage) + 1u +
                (TwoTile ? TileIdx * (8192u >> (Stage + 1u)) : 0u);
            const bool upper = (threadIdx.x & mask) != 0u;
            const double remote = __shfl_xor_sync(0xffffffffu, upper ? lo : hi, mask);
            const double u = upper ? remote : lo, v = upper ? hi : remote;
            const double r = inverseFp52Root<Cached && (!TwoTile || Stage >= CacheStage),
                TwoTile ? 16384u - (16384u >> CacheStage) : 8192u>(
                roots, cachedRoots, rootBase + (butterfly >> Stage));
            lo = addModFp52(u, v, q);
            hi = mulModFp52(__dsub_rn(u, v), r, q, invQ);
        }

        template<u32 Stage, bool Cached, u32 Unroll, u32 TileIdx = 0u, bool TwoTile = false, u32 CacheStage = 2u, class Root>
        __device__ __forceinline__ void inverseFp52StagePair(
            double* sh, const Root* roots, const double* cachedRoots, double q, double invQ)
        {
            constexpr u32 gap = 1u << Stage;
            constexpr u32 rootBase = 16384u - (16384u >> Stage) + 1u +
                (TwoTile ? TileIdx * (8192u >> (Stage + 1u)) : 0u);
            constexpr u32 nextRootBase = 16384u - (16384u >> (Stage + 1u)) + 1u +
                (TwoTile ? TileIdx * (8192u >> (Stage + 2u)) : 0u);
            constexpr u32 pairs = TwoTile ? 2048u : 4096u;
            constexpr u32 cacheBase = TwoTile ? 16384u - (16384u >> CacheStage) : 8192u;
#pragma unroll Unroll
            for (u32 j = threadIdx.x; j < pairs; j += blockDim.x)
            {
                const u32 group = j >> Stage, ix = j + 3u * (group << Stage);
                const double r0 = inverseFp52Root<Cached, cacheBase>(roots, cachedRoots, rootBase + group * 2u);
                const double r1 = inverseFp52Root<Cached, cacheBase>(roots, cachedRoots, rootBase + group * 2u + 1u);
                const double r2 = inverseFp52Root<Cached, cacheBase>(roots, cachedRoots, nextRootBase + group);
                const double u0 = sh[ix], v0 = sh[ix + gap];
                const double u1 = sh[ix + 2u * gap], v1 = sh[ix + 3u * gap];
                const double lo0 = addModFp52(u0, v0, q), lo1 = addModFp52(u1, v1, q);
                const double hi0 = mulModFp52(__dsub_rn(u0, v0), r0, q, invQ);
                const double hi1 = mulModFp52(__dsub_rn(u1, v1), r1, q, invQ);
                sh[ix] = addModFp52(lo0, lo1, q);
                sh[ix + 2u * gap] = mulModFp52(__dsub_rn(lo0, lo1), r2, q, invQ);
                sh[ix + gap] = addModFp52(hi0, hi1, q);
                sh[ix + 3u * gap] = mulModFp52(__dsub_rn(hi0, hi1), r2, q, invQ);
            }
            __syncthreads();
        }

        __device__ __forceinline__ void loadInverseFp52Pair(const u64* src, u32 j, u64& u, u64& v)
        {
            u = src[j];
            v = src[j + 1u];
        }

        template<u32 Stage, u32 TileIdx, u32 CacheStage, u32 Threads, u32 Groups, class Root>
        __device__ __forceinline__ void inverseFp52WarpGroupStage(
            double (&lo)[Groups], double (&hi)[Groups], const Root* roots,
            const double* cache, u32 first, double q, double invQ)
        {
#pragma unroll
            for (u32 i = 0; i < Groups; ++i)
                inverseFp52WarpStage<Stage, true, TileIdx, true, CacheStage>(
                    lo[i], hi[i], roots, cache, first + i * Threads, q, invQ);
        }

        template<bool L2, class T>
        __device__ __forceinline__ void prefetchInverseFp52(const T* ptr)
        {
            if constexpr (L2) asm volatile("prefetch.global.L2 [%0];" :: "l"(ptr));
            else asm volatile("prefetch.global.L1 [%0];" :: "l"(ptr));
        }

        template<u32 TileIdx, u32 CacheStage, u32 Threads, class Root>
        __device__ __forceinline__ void inverseFp52InterleavedPrefix(
            double* sh, const Root* roots, const double* cache,
            const u64* src, const u64* preB, u32 preOp, u64 qi, double q, double invQ)
        {
            constexpr u32 Groups = 2u;
            static_assert(4096u % (Threads * Groups) == 0u);
            for (u32 first = threadIdx.x; first < 4096u; first += Threads * Groups)
            {
                const u32 upcoming = first + Threads * Groups;
                if (upcoming < 4096u)
                {
#pragma unroll
                    for (u32 i = 0; i < Groups; ++i)
                    {
                        const u32 b = upcoming + i * Threads;
                        prefetchInverseFp52<false>(roots + 1u + TileIdx * 4096u + b);
                        prefetchInverseFp52<false>(roots + 8193u + TileIdx * 2048u + (b >> 1u));
                        prefetchInverseFp52<false>(src + 2u * b);
                    }
                }
                double lo[Groups], hi[Groups];
                u64 us[Groups], vs[Groups];
#pragma unroll
                for (u32 i = 0; i < Groups; ++i)
                {
                    const u32 j = 2u * (first + i * Threads);
                    loadInverseFp52Pair(src, j, us[i], vs[i]);
                    if (preOp != kElemOpNone)
                    {
                        u64 bu, bv;
                        loadInverseFp52Pair(preB, j, bu, bv);
                        us[i] = preOp == 0u ? addMod(us[i], bu, qi) : subMod(us[i], bu, qi);
                        vs[i] = preOp == 0u ? addMod(vs[i], bv, qi) : subMod(vs[i], bv, qi);
                    }
                }
#pragma unroll
                for (u32 i = 0; i < Groups; ++i)
                {
                    const double u = static_cast<double>(us[i]), v = static_cast<double>(vs[i]);
                    const double r = loadFp52Root(roots, 1u + TileIdx * 4096u + first + i * Threads);
                    lo[i] = addModFp52(u, v, q);
                    hi[i] = mulModFp52(__dsub_rn(u, v), r, q, invQ);
                }
                inverseFp52WarpGroupStage<1u, TileIdx, CacheStage, Threads>(lo, hi, roots, cache, first, q, invQ);
                inverseFp52WarpGroupStage<2u, TileIdx, CacheStage, Threads>(lo, hi, roots, cache, first, q, invQ);
                inverseFp52WarpGroupStage<3u, TileIdx, CacheStage, Threads>(lo, hi, roots, cache, first, q, invQ);
                inverseFp52WarpGroupStage<4u, TileIdx, CacheStage, Threads>(lo, hi, roots, cache, first, q, invQ);
                inverseFp52WarpGroupStage<5u, TileIdx, CacheStage, Threads>(lo, hi, roots, cache, first, q, invQ);
#pragma unroll
                for (u32 i = 0; i < Groups; ++i)
                {
                    const u32 b = first + i * Threads;
                    const u32 output = b + ((b >> 5u) << 5u);
                    sh[output] = lo[i];
                    sh[output + 32u] = hi[i];
                }
            }
        }

        template<u32 TileIdx, u32 CacheStage, u32 Threads, bool InterleavedPrefetch, class Root>
        __device__ __forceinline__ void inverseFp52Tile(
            double* sh, const Root* roots, const double* cache,
            const u64* src, const u64* preB, u32 preOp, u64 qi, double q, double invQ)
        {
            if constexpr (InterleavedPrefetch)
            {
                inverseFp52InterleavedPrefix<TileIdx, CacheStage, Threads>(
                    sh, roots, cache, src, preB, preOp, qi, q, invQ);
            }
            else
            {
#pragma unroll 4
                for (u32 b = threadIdx.x; b < 4096u; b += Threads)
                {
                    const u32 j = b * 2u;
                    u64 ui, vi;
                    loadInverseFp52Pair(src, j, ui, vi);
                    if (preOp != kElemOpNone)
                    {
                        u64 bu, bv;
                        loadInverseFp52Pair(preB, j, bu, bv);
                        ui = preOp == 0u ? addMod(ui, bu, qi) : subMod(ui, bu, qi);
                        vi = preOp == 0u ? addMod(vi, bv, qi) : subMod(vi, bv, qi);
                    }
                    const double u = static_cast<double>(ui), v = static_cast<double>(vi);
                    const double r = loadFp52Root(roots, 1u + TileIdx * 4096u + b);
                    double lo = addModFp52(u, v, q), hi = mulModFp52(__dsub_rn(u, v), r, q, invQ);
                    inverseFp52WarpStage<1u, true, TileIdx, true, CacheStage>(lo, hi, roots, cache, b, q, invQ);
                    inverseFp52WarpStage<2u, true, TileIdx, true, CacheStage>(lo, hi, roots, cache, b, q, invQ);
                    inverseFp52WarpStage<3u, true, TileIdx, true, CacheStage>(lo, hi, roots, cache, b, q, invQ);
                    inverseFp52WarpStage<4u, true, TileIdx, true, CacheStage>(lo, hi, roots, cache, b, q, invQ);
                    inverseFp52WarpStage<5u, true, TileIdx, true, CacheStage>(lo, hi, roots, cache, b, q, invQ);
                    const u32 output = b + ((b >> 5u) << 5u);
                    sh[output] = lo;
                    sh[output + 32u] = hi;
                }
            }
            __syncthreads();
            for (u32 b = threadIdx.x; b < 4096u; b += Threads)
            {
                const u32 group = b >> 6u, ix = b + (group << 6u);
                const double r = inverseFp52Root<true, 16384u - (16384u >> CacheStage)>(
                    roots, cache, 16129u + TileIdx * 64u + group);
                const double u = sh[ix], v = sh[ix + 64u];
                sh[ix] = addModFp52(u, v, q);
                sh[ix + 64u] = mulModFp52(__dsub_rn(u, v), r, q, invQ);
            }
            __syncthreads();
            inverseFp52StagePair<7u, true, 1u, TileIdx, true, CacheStage>(sh, roots, cache, q, invQ);
            inverseFp52StagePair<9u, true, 1u, TileIdx, true, CacheStage>(sh, roots, cache, q, invQ);
            inverseFp52StagePair<11u, true, 1u, TileIdx, true, CacheStage>(sh, roots, cache, q, invQ);
        }


        // Two-tile FP64 layout: wide batches use 512 threads, a reused 64 KiB
        // tile, a 32 KiB root cache, and 16 parked doubles per thread. Narrow
        // batches use 1024 threads, a 64 KiB root cache, and eight parked doubles.
        template<u32 CacheStage, bool Packed, u32 Threads, bool InterleavedPrefetch = false>
        __global__ __launch_bounds__(Threads, Threads == 512u ? 2u : 1u)
        void nttInverseTwoTile16384Rho8Fp52Kernel(
            DeviceRing rg, u64* data, const u32* polyIdx, u32 preOp,
            const u64* preB, u32 postOp, const u64* postB, const double* packedRoots = nullptr)
        {
            extern __shared__ double tileSh[];
            const u32 limb = blockIdx.x & 7u, slot = blockIdx.x >> 3u;
            const u32 poly = polyIdx ? polyIdx[slot] : slot;
            const size_t off = (static_cast<size_t>(poly) * 8u + limb) * 16384u;
            const u64 qi = rg.mMods[limb].mValue;
            const double q = static_cast<double>(qi), invQ = __drcp_rn(q);
            using Root = std::conditional_t<Packed, double, ShoupOperand>;
            const Root* roots;
            if constexpr (Packed) roots = packedRoots + static_cast<size_t>(limb) * 16384u;
            else roots = rg.mInvRoots + static_cast<size_t>(limb) * 16384u;
            double* cache = tileSh + 8192u;
            constexpr u32 cachedCount = 16384u >> CacheStage;
            for (u32 i = threadIdx.x; i < cachedCount; i += Threads)
                cache[i] = loadFp52Root(roots, 16384u - cachedCount + i);
            __syncthreads();
            constexpr u32 parked = 8192u / Threads;
            double hi[parked];
            inverseFp52Tile<1u, CacheStage, Threads, InterleavedPrefetch>(tileSh, roots, cache, data + off + 8192u,
                preOp == kElemOpNone ? nullptr : preB + off + 8192u, preOp, qi, q, invQ);
#pragma unroll
            for (u32 i = 0u; i < parked; ++i) hi[i] = tileSh[threadIdx.x + i * Threads];
            __syncthreads();
            inverseFp52Tile<0u, CacheStage, Threads, InterleavedPrefetch>(tileSh, roots, cache, data + off,
                preOp == kElemOpNone ? nullptr : preB + off, preOp, qi, q, invQ);
            const double scalar = static_cast<double>(rg.mInvDegree[limb].mOperand);
            const double scaledR = static_cast<double>(rg.mScaledInvRoot[limb].mOperand);
#pragma unroll
            for (u32 i = 0u; i < parked; ++i)
            {
                const u32 j = threadIdx.x + i * Threads;
                const double u = tileSh[j], v = hi[i];
                u64 x0 = static_cast<u64>(mulModFp52(addModFp52(u, v, q), scalar, q, invQ));
                u64 x1 = static_cast<u64>(mulModFp52(__dsub_rn(u, v), scaledR, q, invQ));
                if (postOp == 2u)
                {
                    x0 = x0 == 0u ? 0u : qi - x0;
                    x1 = x1 == 0u ? 0u : qi - x1;
                }
                else if (postOp == 4u)
                {
                    x0 = subMod(postB[off + j], x0, qi);
                    x1 = subMod(postB[off + j + 8192u], x1, qi);
                }
                else if (postOp != kElemOpNone)
                {
                    x0 = postOp == 0u ? addMod(x0, postB[off + j], qi) : subMod(x0, postB[off + j], qi);
                    x1 = postOp == 0u ? addMod(x1, postB[off + j + 8192u], qi) : subMod(x1, postB[off + j + 8192u], qi);
                }
                data[off + j] = x0;
                data[off + j + 8192u] = x1;
            }
        }

        __device__ __forceinline__ double subModFp52(double a, double b, double q)
        {
            double r = __dsub_rn(a, b);
            if (r < 0.0) r = __dadd_rn(r, q);
            return r;
        }

        template<u32 Stage, u32 CacheLog, class Root>
        __device__ __forceinline__ double forwardFp52Root(
            const Root* roots, const double* cache, u32 index)
        {
            if constexpr (Stage + 2u <= CacheLog) return cache[index];
            else return loadFp52Root(roots, index);
        }

        template<u32 Stage, u32 Factor, u32 CacheLog, class Root>
        __device__ __forceinline__ void forwardFp52Pair(
            double* sh, const Root* roots, const double* cache, double q, double invQ)
        {
            constexpr u32 lg = 11u - Stage, gap = 1u << lg, rootBase = (1u << Stage) * Factor;
            for (u32 j = threadIdx.x; j < 2048u; j += 512u)
            {
                const u32 group = j >> lg, ix = j + 3u * (group << lg);
                const double r0 = forwardFp52Root<Stage, CacheLog>(roots, cache, rootBase + group);
                const double r1 = forwardFp52Root<Stage + 1u, CacheLog>(roots, cache, 2u * rootBase + 2u * group);
                const double r2 = forwardFp52Root<Stage + 1u, CacheLog>(roots, cache, 2u * rootBase + 2u * group + 1u);
                const double u0 = sh[ix], u1 = sh[ix + gap];
                const double v0 = mulModFp52(sh[ix + 2u * gap], r0, q, invQ);
                const double v1 = mulModFp52(sh[ix + 3u * gap], r0, q, invQ);
                const double lo0 = addModFp52(u0, v0, q), hi0 = subModFp52(u0, v0, q);
                const double lo1 = mulModFp52(addModFp52(u1, v1, q), r1, q, invQ);
                const double hi1 = mulModFp52(subModFp52(u1, v1, q), r2, q, invQ);
                sh[ix] = addModFp52(lo0, lo1, q);
                sh[ix + gap] = subModFp52(lo0, lo1, q);
                sh[ix + 2u * gap] = addModFp52(hi0, hi1, q);
                sh[ix + 3u * gap] = subModFp52(hi0, hi1, q);
            }
            __syncthreads();
        }

        template<u32 Stage, u32 Factor, u32 CacheLog, class Root>
        __device__ __forceinline__ void forwardFp52Warp(
            double& lo, double& hi, const Root* roots, const double* cache,
            u32 b, double q, double invQ)
        {
            constexpr u32 lg = 12u - Stage, mask = 1u << lg;
            const bool upper = (b & mask) != 0u;
            const double remote = __shfl_xor_sync(0xffffffffu, upper ? lo : hi, mask);
            const double u = upper ? remote : lo, right = upper ? hi : remote;
            const double r = forwardFp52Root<Stage, CacheLog>(roots, cache, (1u << Stage) * Factor + (b >> lg));
            const double v = mulModFp52(right, r, q, invQ);
            lo = addModFp52(u, v, q);
            hi = subModFp52(u, v, q);
        }

        template<u32 Stage, u32 Factor, u32 CacheLog, u32 Groups, class Root>
        __device__ __forceinline__ void forwardFp52WarpGroups(
            double (&lo)[Groups], double (&hi)[Groups], const Root* roots,
            const double* cache, u32 first, double q, double invQ)
        {
#pragma unroll
            for (u32 i = 0; i < Groups; ++i)
                forwardFp52Warp<Stage, Factor, CacheLog>(
                    lo[i], hi[i], roots, cache, first + i * 512u, q, invQ);
        }

        template<u32 Factor, u32 CacheLog, u32 Mode, class Root>
        __device__ __forceinline__ void forwardFp52InterleavedTail(
            const double* sh, const Root* roots, const double* cache, u64* dst, double q, double invQ)
        {
            constexpr u32 groups = Mode == 2u ? 4u : 2u;
            for (u32 first = threadIdx.x; first < 4096u; first += 512u * groups)
            {
                double lo[groups], hi[groups];
#pragma unroll
                for (u32 i = 0; i < groups; ++i)
                {
                    const u32 b = first + i * 512u;
                    const u32 group = b >> 5u, ix = b + (group << 5u);
                    const double r = forwardFp52Root<7u, CacheLog>(roots, cache, 128u * Factor + group);
                    const double u = sh[ix], v = mulModFp52(sh[ix + 32u], r, q, invQ);
                    lo[i] = addModFp52(u, v, q);
                    hi[i] = subModFp52(u, v, q);
                }
                forwardFp52WarpGroups<8u, Factor, CacheLog>(lo, hi, roots, cache, first, q, invQ);
                forwardFp52WarpGroups<9u, Factor, CacheLog>(lo, hi, roots, cache, first, q, invQ);
                forwardFp52WarpGroups<10u, Factor, CacheLog>(lo, hi, roots, cache, first, q, invQ);
                forwardFp52WarpGroups<11u, Factor, CacheLog>(lo, hi, roots, cache, first, q, invQ);
                forwardFp52WarpGroups<12u, Factor, CacheLog>(lo, hi, roots, cache, first, q, invQ);
#pragma unroll
                for (u32 i = 0; i < groups; ++i)
                {
                    const u32 b = first + i * 512u;
                    dst[b * 2u] = static_cast<u64>(lo[i]);
                    dst[b * 2u + 1u] = static_cast<u64>(hi[i]);
                }
            }
        }

        template<u32 Factor, u32 CacheLog, u32 TailMode, class Root>
        __device__ __forceinline__ void forwardFp52Tile(
            double* sh, const Root* roots, const double* cache, u64* dst, double q, double invQ)
        {
            forwardFp52Pair<0u, Factor, CacheLog>(sh, roots, cache, q, invQ);
            forwardFp52Pair<2u, Factor, CacheLog>(sh, roots, cache, q, invQ);
            forwardFp52Pair<4u, Factor, CacheLog>(sh, roots, cache, q, invQ);
            for (u32 b = threadIdx.x; b < 4096u; b += 512u)
            {
                const u32 group = b >> 6u, ix = b + (group << 6u);
                const double r = forwardFp52Root<6u, CacheLog>(roots, cache, 64u * Factor + group);
                const double u = sh[ix], v = mulModFp52(sh[ix + 64u], r, q, invQ);
                sh[ix] = addModFp52(u, v, q);
                sh[ix + 64u] = subModFp52(u, v, q);
            }
            __syncthreads();
            forwardFp52InterleavedTail<Factor, CacheLog, TailMode>(sh, roots, cache, dst, q, invQ);
        }

        template<u32 InputMode>
        __device__ __forceinline__ void forwardFp52Body(
            double* forwardSh, DeviceRing rg, const u64* input, const u32* inputIdx,
            const u32* inputLimb, u64* output, const u32* outputIdx)
        {
            static_assert(InputMode <= 2u);
            const u32 limb = blockIdx.x & 7u, slot = blockIdx.x >> 3u;
            const u32 inPoly = inputIdx ? inputIdx[slot] : slot;
            const u32 outPoly = outputIdx ? outputIdx[slot] : slot;
            const u32 selected = InputMode == 2u && inputLimb ? inputLimb[slot] : 8u;
            const u32 sourceLimb = InputMode == 0u ? limb :
                InputMode == 2u && selected < 8u ? selected : 0u;
            const u64* src = input + (static_cast<size_t>(inPoly) * 8u + sourceLimb) * 16384u;
            u64* base = output + (static_cast<size_t>(outPoly) * 8u + limb) * 16384u;
            const ShoupOperand* roots = rg.mRoots + static_cast<size_t>(limb) * 16384u;
            const u64 qi = rg.mMods[limb].mValue, twoQ = qi << 1u;
            const double q = static_cast<double>(qi), invQ = __drcp_rn(q);
            double* cache = forwardSh + 8192u;
            for (u32 i = threadIdx.x; i < (1u << 12u); i += 512u)
                cache[i] = loadFp52Root(roots, i);
            __syncthreads();
            const double crossing = cache[1];
            double hi[16];
#pragma unroll
            for (u32 i = 0u; i < 16u; ++i)
            {
                const u32 j = threadIdx.x + i * 512u;
                u64 ui, vi;
                if constexpr (InputMode == 2u)
                {
                    ui = nttForwardLoad<true, 8u>(rg, src, selected, limb, j);
                    vi = nttForwardLoad<true, 8u>(rg, src, selected, limb, j + 8192u);
                }
                else
                {
                    ui = src[j];
                    vi = src[j + 8192u];
                }
                ui = nttGuard(ui, twoQ);
                vi = nttGuard(vi, twoQ);
                if (ui >= qi) ui -= qi;
                if (vi >= qi) vi -= qi;
                const double u = static_cast<double>(ui);
                const double v = mulModFp52(static_cast<double>(vi), crossing, q, invQ);
                forwardSh[j] = addModFp52(u, v, q);
                hi[i] = subModFp52(u, v, q);
            }
            __syncthreads();
            // The first half keeps sixteen second-half values live. Retain
            // its four-group tail and the second half's two-group tail.
            forwardFp52Tile<2u, 12u, 2u>(forwardSh, roots, cache, base, q, invQ);
            __syncthreads();
#pragma unroll
            for (u32 i = 0u; i < 16u; ++i) forwardSh[threadIdx.x + i * 512u] = hi[i];
            __syncthreads();
            forwardFp52Tile<3u, 12u, 1u>(forwardSh, roots, cache, base + 8192u, q, invQ);
        }

        template<u32 InputMode>
        __global__ __launch_bounds__(512, 2)
        void nttForwardTail16384Fp52Kernel(DeviceRing rg, const u64* input,
            const u32* inputIdx, const u32* inputLimb, u64* output, const u32* outputIdx)
        {
            extern __shared__ double tailFpSh[];
            forwardFp52Body<InputMode>(
                tailFpSh, rg, input, inputIdx, inputLimb, output, outputIdx);
        }

        template<u32 InputMode>
        bool launchForwardFp52Tail(DeviceRing rg, const u64* input, const u32* inputIdx,
            const u32* inputLimb, u64* output, const u32* outputIdx, u32 polyCount, cudaStream_t stream)
        {
            constexpr int bytes = 12288u * sizeof(double);
            if (!check(cudaFuncSetAttribute(nttForwardTail16384Fp52Kernel<InputMode>,
                    cudaFuncAttributeMaxDynamicSharedMemorySize, bytes), "forward tail shared"))
                return false;
            nttForwardTail16384Fp52Kernel<InputMode><<<polyCount * 8u, 512u, bytes, stream>>>(
                rg, input, inputIdx, inputLimb, output, outputIdx);
            return check(cudaGetLastError(), "forward FP52 tail");
        }

        __global__ __launch_bounds__(kNttThreads) void nttInverseTwoTileKernel(
            DeviceRing rg,
            u64* data,
            const u32* polyIdx,
            u32 preOp,
            const u64* preB,
            u32 postOp,
            const u64* postB,
            NttFusedIp ip)
        {
            extern __shared__ u64 sh[];

            const u32 n = rg.mN;
            const u32 tileLen = n >> 1;
            const u32 logTileLen = rg.mLogN - 1u;
            const u32 limb = blockIdx.x % rg.mRho;
            const u32 slot = blockIdx.x / rg.mRho;
            const u32 poly = polyIdx ? polyIdx[slot] : slot;

            const size_t limbOff = (static_cast<size_t>(poly) * rg.mRho + limb) * n;
            u64* limbBase = data + limbOff;
            const ShoupOperand* roots = rg.mInvRoots + static_cast<size_t>(limb) * n;
            const GpuModulus mod = rg.mMods[limb];
            const u64 q = mod.mValue;
            const u64 twoQ = q << 1;
            const u32 half = tileLen >> 1;

            u64 hi[kInvRegs];

            // The fused inner product's operand base pointers, resolved once per
            // block. mAIdx/mBIdx depend only on `slot`, which is fixed for a block,
            // so the original per-element reload was `terms` pairs of L1 hits and
            // address computations for every one of the 16384 elements.
            __shared__ const u64* shIpA[kMaxFusedIpTerms];
            __shared__ const u64* shIpB[kMaxFusedIpTerms];
            const bool hoistIp = ip.mTerms != 0 && ip.mTerms <= kMaxFusedIpTerms;
            if (hoistIp)
            {
                const size_t perPoly = static_cast<size_t>(rg.mRho) * n;
                const size_t idxBase = static_cast<size_t>(slot) * ip.mTerms;
                for (u32 k = threadIdx.x; k < ip.mTerms; k += blockDim.x)
                {
                    const u32 ai = ip.mAIdx ? ip.mAIdx[idxBase + k] : k;
                    const u32 bi = ip.mBIdx ? ip.mBIdx[idxBase + k] : k;
                    const size_t base = static_cast<size_t>(limb) * n;
                    shIpA[k] = ip.mA + static_cast<size_t>(ai) * perPoly + base;
                    shIpB[k] = ip.mB + static_cast<size_t>(bi) * perPoly + base;
                }
                __syncthreads();
            }

            // Same body for both halves; `tileIdx` picks the slice and the roots.
            for (u32 tileIdx = 1u;; tileIdx = 0u)
            {
                const u32 tileBase = tileIdx * tileLen;
                u64* src = limbBase + tileBase;

                if (ip.mTerms != 0)
                {
                    const size_t perPoly = static_cast<size_t>(rg.mRho) * n;
                    const size_t ipOff = static_cast<size_t>(limb) * n + tileBase;
                    const size_t idxBase = static_cast<size_t>(slot) * ip.mTerms;
                    const u32 terms = ip.mTerms;
                    for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                    {
                        // Lazy accumulation: sum the exact 128-bit products and
                        // reduce once, instead of a Barrett reduction per term. The
                        // moduli are at most 60 bits and terms at most
                        // kMaxFusedIpTerms, so the sum is below 2^126 and cannot
                        // wrap; the reduced result is the same residue either way.
                        u64 acc = 0;
                        u32 k = 0;
                        if (hoistIp)
                        {
                            const u32 idx = tileBase + t;
                            Wide sum{ 0, 0 };
                            for (; k < terms; ++k)
                            {
                                sum = wideAdd(sum, wideMul(shIpA[k][idx], shIpB[k][idx]));
                            }
                            acc = barrettReduce128(sum.mLo, sum.mHi, mod);
                        }
                        else
                        {
                            for (; k < terms; ++k)
                            {
                                const u32 ai = ip.mAIdx ? ip.mAIdx[idxBase + k] : k;
                                const u32 bi = ip.mBIdx ? ip.mBIdx[idxBase + k] : k;
                                const u64 av = ip.mA[static_cast<size_t>(ai) * perPoly + ipOff + t];
                                const u64 bv = ip.mB[static_cast<size_t>(bi) * perPoly + ipOff + t];
                                acc = mulAddMod(av, bv, acc, mod);
                            }
                        }
                        if (ip.mMode == NttFusedIp::Accumulate)
                            acc = addMod(src[t], acc, q);
                        else if (ip.mMode == NttFusedIp::Subtract)
                            acc = subMod(src[t], acc, q);
                        sh[t] = acc;
                    }
                }
                else if (preOp == kElemOpNone)
                {
                    for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x) sh[t] = src[t];
                }
                else
                {
                    const u64* b = preB + limbOff + tileBase;
                    for (u32 t = threadIdx.x; t < tileLen; t += blockDim.x)
                    {
                        const u64 av = src[t];
                        sh[t] = (preOp == 0u) ? addMod(av, b[t], q) : subMod(av, b[t], q);
                    }
                }
                __syncthreads();

                for (u32 s = 0; s < logTileLen; ++s)
                {
                    const u32 m = tileLen >> (s + 1u);
                    const u32 gap = 1u << s;
                    const u32 rootBase = n - 4u * m + 1u + tileIdx * m;
                    for (u32 b = threadIdx.x; b < half; b += blockDim.x)
                    {
                        const u32 i = b >> s;
                        const u32 j = b & (gap - 1u);
                        const u32 ix = (i << (s + 1u)) + j;
                        const ShoupOperand r = roots[rootBase + i];
                        const u64 u = sh[ix];
                        const u64 v = sh[ix + gap];
                        sh[ix] = nttGuard(u + v, twoQ);
                        sh[ix + gap] = mulShoupLazy(u + twoQ - v, r, q);
                    }
                    __syncthreads();
                }

                if (tileIdx == 1u)
                {
                    // Park the second half in registers and reuse sh for the first.
                    //
                    // Thread t owns the *strided* set { t + i*threads }, not eight
                    // consecutive elements. Both work - the only requirement is that
                    // a thread hold the same indices it will combine below - but the
                    // consecutive layout made thread t read shared address t*64 B,
                    // which is a 16-way bank conflict, and wrote global memory in
                    // 64-byte-per-thread strides. Strided ownership makes both the
                    // shared reads and the global writes consecutive across a warp.
#pragma unroll
                    for (u32 i = 0; i < kInvRegs; ++i) hi[i] = sh[threadIdx.x + i * kNttThreads];
                    __syncthreads();
                    continue;
                }
                break;
            }

            // The crossing stage: m = 1, gap = n/2, with the 1/n scalar folded in,
            // then the fused post-operation and the final conditional subtraction.
            const ShoupOperand scalar = rg.mInvDegree[limb];
            const ShoupOperand scaledR = rg.mScaledInvRoot[limb];
            const u64* b = (postOp != kElemOpNone && postB) ? postB + limbOff : nullptr;
#pragma unroll
            for (u32 i = 0; i < kInvRegs; ++i)
            {
                const u32 j = threadIdx.x + i * kNttThreads;
                const u64 u = nttGuard(sh[j], twoQ);
                const u64 v = hi[i];
                u64 x0 = mulShoupLazy(nttGuard(u + v, twoQ), scalar, q);
                u64 x1 = mulShoupLazy(u + twoQ - v, scaledR, q);
                if (x0 >= q) x0 -= q;
                if (x1 >= q) x1 -= q;
                if (postOp == 2u)
                {
                    x0 = (x0 == 0) ? 0 : (q - x0);
                    x1 = (x1 == 0) ? 0 : (q - x1);
                }
                else if (postOp == 4u)
                {
                    x0 = subMod(b[j], x0, q);
                    x1 = subMod(b[j + tileLen], x1, q);
                }
                else if (postOp != kElemOpNone)
                {
                    if (postOp == 0u)
                    {
                        x0 = addMod(x0, b[j], q);
                        x1 = addMod(x1, b[j + tileLen], q);
                    }
                    else
                    {
                        x0 = subMod(x0, b[j], q);
                        x1 = subMod(x1, b[j + tileLen], q);
                    }
                }
                limbBase[j] = x0;
                limbBase[j + tileLen] = x1;
            }
        }

        // One tile-crossing inverse stage (local m >= 2), in global memory. Only
        // reached when tiles > 2; for tiles == 2 the single crossing stage is the
        // final one below.
        __global__ void nttInverseCrossKernel(DeviceRing rg, u64* data, const u32* polyIdx, u32 stage)
        {
            const u32 n = rg.mN;
            const u32 half = n >> 1;
            const u32 b = blockIdx.x * blockDim.x + threadIdx.x;
            if (b >= half) return;

            const u32 limb = blockIdx.y % rg.mRho;
            const u32 slot = blockIdx.y / rg.mRho;
            const u32 poly = polyIdx ? polyIdx[slot] : slot;

            u64* src = data + (static_cast<size_t>(poly) * rg.mRho + limb) * n;
            const ShoupOperand* roots = rg.mInvRoots + static_cast<size_t>(limb) * n;
            const u64 q = rg.mMods[limb].mValue;
            const u64 twoQ = q << 1;

            const u32 m = n >> (stage + 1u);
            const u32 gap = 1u << stage;
            const u32 rootBase = n - 2u * m + 1u;
            const u32 i = b >> stage;
            const u32 j = b & (gap - 1u);
            const u32 ix = (i << (stage + 1u)) + j;
            const ShoupOperand r = roots[rootBase + i];
            const u64 u = src[ix];
            const u64 v = src[ix + gap];
            src[ix] = nttGuard(u + v, twoQ);
            src[ix + gap] = mulShoupLazy(u + twoQ - v, r, q);
        }

        // The m = 1 inverse stage with the 1/n scalar folded in, plus the fused
        // post-operation and the final conditional subtraction. Used instead of the
        // tail of nttInverseKernel when tiles > 1.
        __global__ void nttInverseFinalKernel(
            DeviceRing rg, u64* data, const u32* polyIdx, u32 postOp, const u64* postB)
        {
            const u32 n = rg.mN;
            const u32 gap = n >> 1;
            const u32 j = blockIdx.x * blockDim.x + threadIdx.x;
            if (j >= gap) return;

            const u32 limb = blockIdx.y % rg.mRho;
            const u32 slot = blockIdx.y / rg.mRho;
            const u32 poly = polyIdx ? polyIdx[slot] : slot;

            const size_t off = (static_cast<size_t>(poly) * rg.mRho + limb) * n;
            u64* src = data + off;
            const u64 q = rg.mMods[limb].mValue;
            const u64 twoQ = q << 1;
            const ShoupOperand scalar = rg.mInvDegree[limb];
            const ShoupOperand scaledR = rg.mScaledInvRoot[limb];

            const u64 u = nttGuard(src[j], twoQ);
            const u64 v = src[j + gap];
            u64 x0 = mulShoupLazy(nttGuard(u + v, twoQ), scalar, q);
            u64 x1 = mulShoupLazy(u + twoQ - v, scaledR, q);
            if (x0 >= q) x0 -= q;
            if (x1 >= q) x1 -= q;

            if (postOp != kElemOpNone)
            {
                if (postOp == 2u)
                {
                    x0 = (x0 == 0) ? 0 : (q - x0);
                    x1 = (x1 == 0) ? 0 : (q - x1);
                }
                else if (postOp == 4u)
                {
                    const u64* b = postB + off;
                    x0 = subMod(b[j], x0, q);
                    x1 = subMod(b[j + gap], x1, q);
                }
                else
                {
                    const u64* b = postB + off;
                    if (postOp == 0u)
                    {
                        x0 = addMod(x0, b[j], q);
                        x1 = addMod(x1, b[j + gap], q);
                    }
                    else
                    {
                        x0 = subMod(x0, b[j], q);
                        x1 = subMod(x1, b[j + gap], q);
                    }
                }
            }

            src[j] = x0;
            src[j + gap] = x1;
        }

        // ---- pointwise ----------------------------------------------------

        enum class FixedIpMode : u32
        {
            Replace,
            Accumulate,
            Subtract
        };

        // The protocol's hot inner products have fixed widths and one output per
        // grid-y block. Specializing those cases removes the runtime term/mode
        // branches and the extra barrier that the fully general y-striding kernel
        // needs. Since a 256-thread block stays within one limb for the rings we
        // dispatch here, the term pointers can also be resolved to limb bases once
        // per block instead of rebuilding 64-bit addresses per coefficient.
        template<u32 Terms, FixedIpMode Mode>
        __global__ void innerProductFixedIndexedKernel(
            DeviceRing rg,
            const u64* aBase,
            const u64* bBase,
            const u32* aIdx,
            const u32* bIdx,
            u64* out)
        {
            const u32 n = rg.mN;
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            const u32 limb = elem >> rg.mLogN;
            const u32 coeff = elem & (n - 1u);
            const u32 o = blockIdx.y;
            const size_t perPoly = static_cast<size_t>(rg.mRho) * n;

            __shared__ const u64* shA[Terms];
            __shared__ const u64* shB[Terms];
            if (threadIdx.x < Terms)
            {
                const u32 k = threadIdx.x;
                const size_t idx = static_cast<size_t>(o) * Terms + k;
                const u32 ai = aIdx[idx];
                const u32 bi = bIdx[idx];
                const size_t limbBase = static_cast<size_t>(limb) * n;
                shA[k] = aBase + static_cast<size_t>(ai) * perPoly + limbBase;
                shB[k] = bBase + static_cast<size_t>(bi) * perPoly + limbBase;
            }
            __syncthreads();

            const GpuModulus mod = rg.mMods[limb];
            u64 acc;
            if constexpr (Terms == 1)
            {
                acc = mulMod(shA[0][coeff], shB[0][coeff], mod);
            }
            else
            {
                Wide sum = wideMul(shA[0][coeff], shB[0][coeff]);
#pragma unroll
                for (u32 k = 1; k < Terms; ++k)
                    sum = wideAdd(sum, wideMul(shA[k][coeff], shB[k][coeff]));
                acc = barrettReduce128(sum.mLo, sum.mHi, mod);
            }

            u64* dst = out + static_cast<size_t>(o) * perPoly + elem;
            if constexpr (Mode == FixedIpMode::Accumulate)
                acc = addMod(*dst, acc, mod.mValue);
            else if constexpr (Mode == FixedIpMode::Subtract)
                acc = subMod(*dst, acc, mod.mValue);
            *dst = acc;
        }

        // NoGoldenSeed port of the GoldenSeed pointwise specialization. The
        // full-width reducer preserves arbitrary Wide inputs and sum wraparound;
        // the checked FP64 single-product path falls back for noncanonical data.
        template<u32 Terms, FixedIpMode Mode>
        __global__ __launch_bounds__(256, 8)
        void innerProductFixedIndexedH200Kernel(DeviceRing rg, const u64* aBase,
            const u64* bBase, const u32* aIdx, const u32* bIdx, u64* out,
            const double* fp52Constants)
        {
            static_assert(Terms == 1u || Terms == 2u || Terms == 6u);
            const u32 n = rg.mN;
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            const u32 limb = elem >> rg.mLogN;
            const u32 coeff = elem & (n - 1u), o = blockIdx.y;
            const size_t perPoly = static_cast<size_t>(rg.mRho) * n;
            __shared__ const u64* shA[Terms];
            __shared__ const u64* shB[Terms];
            if (threadIdx.x < Terms)
            {
                const u32 k = threadIdx.x;
                const size_t idx = static_cast<size_t>(o) * Terms + k;
                const size_t limbBase = static_cast<size_t>(limb) * n;
                shA[k] = aBase + static_cast<size_t>(aIdx[idx]) * perPoly + limbBase;
                shB[k] = bBase + static_cast<size_t>(bIdx[idx]) * perPoly + limbBase;
            }
            __syncthreads();
            const u64 q = rg.mMods[limb].mValue;
            const u64 a0 = shA[0][coeff], b0 = shB[0][coeff];
            u64 acc;
            if constexpr (Terms == 1u)
            {
                if (a0 < q && b0 < q)
                {
                    const double qd = static_cast<double>(q);
                    const double invQ = fp52Constants ? fp52Constants[8u + limb] : __drcp_rn(qd);
                    acc = static_cast<u64>(mulModFp52(static_cast<double>(a0), static_cast<double>(b0), qd, invQ));
                }
                else acc = reducePseudo52FullWide<true>(wideMul(a0, b0), q);
            }
            else
            {
                Wide sum = wideMul(a0, b0);
#pragma unroll
                for (u32 k = 1u; k < Terms; ++k)
                {
                    const Wide product = wideMul(shA[k][coeff], shB[k][coeff]);
                    sum = wideAddCarry(sum, product);
                }
                acc = reducePseudo52FullWide<true>(sum, q);
            }
            u64* dst = out + static_cast<size_t>(o) * perPoly + elem;
            if constexpr (Mode == FixedIpMode::Accumulate) acc = addMod(*dst, acc, q);
            else if constexpr (Mode == FixedIpMode::Subtract) acc = subMod(*dst, acc, q);
            *dst = acc;
        }

        // Candidate-only copy of the accepted fixed indexed pointwise kernel.
        // Indexing, product/addition order and post-mode semantics stay exact;
        // only the final one/two/six-product reduction changes.
        template<u32 Terms, FixedIpMode Mode>
        __global__ __launch_bounds__(256, 8)
        void innerProductFixedIndexedPseudo55Kernel(
            DeviceRing rg,
            const u64* aBase,
            const u64* bBase,
            const u32* aIdx,
            const u32* bIdx,
            u64* out)
        {
            static_assert(Terms == 1u || Terms == 2u || Terms == 6u);
            constexpr u64 kRadix55 = u64{ 1 } << 55u;
            const u32 n = rg.mN;
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            const u32 limb = elem >> rg.mLogN;
            const u32 coeff = elem & (n - 1u);
            const u32 o = blockIdx.y;
            const size_t perPoly = static_cast<size_t>(rg.mRho) * n;

            __shared__ const u64* shA[Terms];
            __shared__ const u64* shB[Terms];
            if (threadIdx.x < Terms)
            {
                const u32 k = threadIdx.x;
                const size_t idx = static_cast<size_t>(o) * Terms + k;
                const u32 ai = aIdx[idx];
                const u32 bi = bIdx[idx];
                const size_t limbBase = static_cast<size_t>(limb) * n;
                shA[k] =
                    aBase + static_cast<size_t>(ai) * perPoly + limbBase;
                shB[k] =
                    bBase + static_cast<size_t>(bi) * perPoly + limbBase;
            }
            __syncthreads();

            const u64 q = rg.mMods[limb].mValue;
            const u32 c = static_cast<u32>(kRadix55 - q);
            u64 acc;
            if constexpr (Terms == 1u)
            {
                acc = pointwisePseudo55ReduceWideCanonical<1u>(
                    wideMul(shA[0][coeff], shB[0][coeff]), q, c);
            }
            else
            {
                Wide sum = wideMul(shA[0][coeff], shB[0][coeff]);
#pragma unroll
                for (u32 k = 1u; k < Terms; ++k)
                    sum = wideAdd(
                        sum, wideMul(shA[k][coeff], shB[k][coeff]));
                acc = pointwisePseudo55ReduceWideCanonical<Terms>(
                    sum, q, c);
            }

            u64* dst = out + static_cast<size_t>(o) * perPoly + elem;
            if constexpr (Mode == FixedIpMode::Accumulate)
                acc = addMod(*dst, acc, q);
            else if constexpr (Mode == FixedIpMode::Subtract)
                acc = subMod(*dst, acc, q);
            *dst = acc;
        }


        // Exact standalone outer product for the production sender tuple. One
        // CTA owns a 256-coefficient tile of one (chunk, limb), and every thread
        // retains that chunk's sk coefficient while walking the sixteen public-A
        // rows. The row loop is deliberately rolled: its single live product
        // must stay within the eight-CTA/32-register H200 envelope.
        template<u32 Mu>
        __global__ __launch_bounds__(256, 8)
        void innerProductOuterMuRowReuseKernel(
            DeviceRing rg,
            const u64* __restrict__ publicA,
            const u64* __restrict__ skNtt,
            u64* __restrict__ out)
        {
            constexpr u32 kN = 8192u;
            constexpr u32 kRho = 4u;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;

            const u32 coeff = (blockIdx.x << 8u) + threadIdx.x;
            const u32 limb = blockIdx.y;
            const u32 chunk = blockIdx.z;
            const size_t limbCoeff = static_cast<size_t>(limb) * kN + coeff;
            const GpuModulus mod = rg.mMods[limb];

            u64 skValue =
                skNtt[static_cast<size_t>(chunk) * kPerPoly + limbCoeff];
            // Prevent rematerialising this cache hit at the row-loop backedge;
            // the SASS gate requires exactly one sk load before the loop.
            asm volatile("" : "+l"(skValue));

            const u64* a = publicA + limbCoeff;
            u64* dst = out + static_cast<size_t>(chunk) * Mu * kPerPoly +
                limbCoeff;
#pragma unroll 1
            for (u32 row = 0u; row < Mu; ++row)
            {
                *dst = mulMod(*a, skValue, mod);
                a += kPerPoly;
                dst += kPerPoly;
            }
        }

        // Candidate-only copy of the accepted row-reuse sender product.  The
        // load-retention barrier, row walk and stores stay byte-for-byte in the
        // same order; only the single-product reduction is specialized for the
        // production q=2^55-c moduli.
        template<u32 Mu>
        __global__ __launch_bounds__(256, 8)
        void innerProductOuterMuRowReusePseudo55Kernel(
            DeviceRing rg,
            const u64* __restrict__ publicA,
            const u64* __restrict__ skNtt,
            u64* __restrict__ out)
        {
            constexpr u32 kN = 8192u;
            constexpr u32 kRho = 4u;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;
            constexpr u64 kRadix55 = u64{ 1 } << 55u;

            const u32 coeff = (blockIdx.x << 8u) + threadIdx.x;
            const u32 limb = blockIdx.y;
            const u32 chunk = blockIdx.z;
            const size_t limbCoeff = static_cast<size_t>(limb) * kN + coeff;
            const u64 q = rg.mMods[limb].mValue;
            const u32 c = static_cast<u32>(kRadix55 - q);

            u64 skValue =
                skNtt[static_cast<size_t>(chunk) * kPerPoly + limbCoeff];
            asm volatile("" : "+l"(skValue));

            const u64* a = publicA + limbCoeff;
            u64* dst = out + static_cast<size_t>(chunk) * Mu * kPerPoly +
                limbCoeff;
#pragma unroll 1
            for (u32 row = 0u; row < Mu; ++row)
            {
                *dst = pointwisePseudo55ReduceWideCanonical<1u>(
                    wideMul(*a, skValue), q, c);
                a += kPerPoly;
                dst += kPerPoly;
            }
        }

        // Default-on wider-mu peer of the accepted mu=8/16 sender kernel.
        // A distinct symbol keeps the accepted specializations codegen-stable;
        // each CTA still loads one sk coefficient and reuses it for every row.
        template<u32 Mu>
        __global__ __launch_bounds__(256, 8)
        void innerProductOuterWideMuRowReusePseudo55Kernel(
            DeviceRing rg,
            const u64* __restrict__ publicA,
            const u64* __restrict__ skNtt,
            u64* __restrict__ out)
        {
            static_assert(Mu == 32u || Mu == 64u || Mu == 128u);
            constexpr u32 kN = 8192u;
            constexpr u32 kRho = 4u;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;
            constexpr u64 kRadix55 = u64{ 1 } << 55u;

            const u32 coeff = (blockIdx.x << 8u) + threadIdx.x;
            const u32 limb = blockIdx.y;
            const u32 chunk = blockIdx.z;
            const size_t limbCoeff = static_cast<size_t>(limb) * kN + coeff;
            const u64 q = rg.mMods[limb].mValue;
            const u32 c = static_cast<u32>(kRadix55 - q);

            u64 skValue =
                skNtt[static_cast<size_t>(chunk) * kPerPoly + limbCoeff];
            asm volatile("" : "+l"(skValue));

            const u64* a = publicA + limbCoeff;
            u64* dst = out + static_cast<size_t>(chunk) * Mu * kPerPoly +
                limbCoeff;
#pragma unroll 1
            for (u32 row = 0u; row < Mu; ++row)
            {
                *dst = pointwisePseudo55ReduceWideCanonical<1u>(
                    wideMul(*a, skValue), q, c);
                a += kPerPoly;
                dst += kPerPoly;
            }
        }

        // The production receiver expand combines three pointwise launches with
        // fixed widths 1, 1 and 6. Keeping the intermediate accumulator in a
        // register saves four global-memory operations per coefficient while
        // retaining the high-occupancy 256-thread geometry (doing this work in the
        // shared-memory NTT kernel measured slower).
        __global__ void expandAccumulatorTau1Kernel(
            DeviceRing rg,
            const u64* ct1,
            const u64* uDigits,
            const u64* publicA,
            const u64* skNtt,
            const u64* lacct,
            const u64* nodes,
            const u32* lacctAIdx,
            const u32* lacctBIdx,
            u32 mu,
            u64* out)
        {
            constexpr u32 kTreeTerms = 6;
            constexpr u32 kTotalTerms = 2 + kTreeTerms;
            const u32 n = rg.mN;
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            const u32 limb = elem >> rg.mLogN;
            const u32 coeff = elem & (n - 1u);
            const u32 o = blockIdx.y;
            const u32 row = o % mu;
            const u32 chunk = o / mu;
            const size_t perPoly = static_cast<size_t>(rg.mRho) * n;
            const size_t limbBase = static_cast<size_t>(limb) * n;

            __shared__ const u64* shA[kTotalTerms];
            __shared__ const u64* shB[kTotalTerms];
            if (threadIdx.x < kTotalTerms)
            {
                const u32 k = threadIdx.x;
                if (k == 0)
                {
                    shA[k] = ct1 + static_cast<size_t>(row) * perPoly + limbBase;
                    shB[k] = uDigits + static_cast<size_t>(chunk) * perPoly + limbBase;
                }
                else if (k == 1)
                {
                    shA[k] = publicA + static_cast<size_t>(row) * perPoly + limbBase;
                    shB[k] = skNtt + static_cast<size_t>(chunk) * perPoly + limbBase;
                }
                else
                {
                    const u32 treeK = k - 2u;
                    const size_t idx = static_cast<size_t>(o) * kTreeTerms + treeK;
                    shA[k] = lacct + static_cast<size_t>(lacctAIdx[idx]) * perPoly + limbBase;
                    shB[k] = nodes + static_cast<size_t>(lacctBIdx[idx]) * perPoly + limbBase;
                }
            }
            __syncthreads();

            const GpuModulus mod = rg.mMods[limb];
            // ct1 and the six tree products all have a positive sign, so reduce
            // their exact 128-bit sum once. Seven products of sub-60-bit residues
            // stay below 2^123. This is the same canonical residue as reducing
            // ct1 and the tree sum separately and adding them, with one fewer
            // Barrett reduction per coefficient.
            Wide positiveSum = wideMul(shA[0][coeff], shB[0][coeff]);
#pragma unroll
            for (u32 k = 2; k < kTotalTerms; ++k)
                positiveSum = wideAdd(positiveSum, wideMul(shA[k][coeff], shB[k][coeff]));
            // Subtraction can stay in the same exact wide accumulator too: q^2
            // is zero modulo q and is strictly larger than the key product, so
            // adding q^2-keyProduct is non-negative and keeps the eight-product
            // total below 2^123. One final Barrett reduction replaces the two
            // reductions plus modular subtraction used by the separate passes.
            const Wide keyComplement = wideSub(
                wideMul(mod.mValue, mod.mValue),
                wideMul(shA[1][coeff], shB[1][coeff]));
            const Wide signedSum = wideAdd(positiveSum, keyComplement);
            const u64 acc = barrettReduce128(signedSum.mLo, signedSum.mHi, mod);
            out[static_cast<size_t>(o) * perPoly + elem] = acc;
        }

        // Exact H200 specialization for the production NoGoldenSeed tuple.
        // Its eight tree terms plus ct1 and the q^2-key complement fit in 128
        // bits when q<2^60; the same bound also leaves the Barrett input below
        // q*2^64. One CTA owns a (chunk,row,limb) plane and walks coefficient
        // tiles, amortizing the ten-entry pointer table across the full
        // N=16384 limb instead of rebuilding it in 64 independent CTAs.
        __global__ __launch_bounds__(256, 8)
        void expandAccumulatorTau1NoGoldH200Kernel(
            DeviceRing rg,
            const u64* ct1,
            const u64* uDigits,
            const u64* publicA,
            const u64* skNtt,
            const u64* lacct,
            const u64* nodes,
            const u32* lacctAIdx,
            const u32* lacctBIdx,
            u64* out)
        {
            constexpr u32 kN = 16384u;
            constexpr u32 kRho = 8u;
            // The benchmark prints the full protocol mu=32. Recursive
            // NoGoldenSeed shrink/expand truncates tau from two to one, so the
            // actual hot level has mu=alpha*tauHi*rho=16.
            constexpr u32 kMu = 16u;
            constexpr u32 kTreeTerms = 8u;
            constexpr u32 kTotalTerms = 2u + kTreeTerms;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;

            const u32 rowLimb = blockIdx.y;
            const u32 limb = rowLimb & (kRho - 1u);
            const u32 row = rowLimb >> 3u;
            const u32 chunk = blockIdx.z;
            const u32 o = chunk * kMu + row;
            const size_t limbBase = static_cast<size_t>(limb) * kN;

            // Volatile slots prevent the coefficient loop from extending all
            // ten bases through the arithmetic live range as registers.
            using SharedPointer = const u64* volatile;
            __shared__ SharedPointer shA[kTotalTerms];
            __shared__ SharedPointer shB[kTotalTerms];
            if (threadIdx.x < kTotalTerms)
            {
                const u32 k = threadIdx.x;
                if (k == 0u)
                {
                    shA[k] = ct1 +
                        static_cast<size_t>(row) * kPerPoly + limbBase;
                    shB[k] = uDigits +
                        static_cast<size_t>(chunk) * kPerPoly + limbBase;
                }
                else if (k == 1u)
                {
                    shA[k] = publicA +
                        static_cast<size_t>(row) * kPerPoly + limbBase;
                    shB[k] = skNtt +
                        static_cast<size_t>(chunk) * kPerPoly + limbBase;
                }
                else
                {
                    const u32 treeK = k - 2u;
                    const size_t idx =
                        static_cast<size_t>(o) * kTreeTerms + treeK;
                    shA[k] = lacct +
                        static_cast<size_t>(lacctAIdx[idx]) * kPerPoly +
                        limbBase;
                    shB[k] = nodes +
                        static_cast<size_t>(lacctBIdx[idx]) * kPerPoly +
                        limbBase;
                }
            }
            __syncthreads();

            const GpuModulus mod = rg.mMods[limb];
            for (u32 tile = blockIdx.x; tile < 64u; tile += gridDim.x)
            {
                const u32 coeff = (tile << 8u) + threadIdx.x;
                const u32 elem = (limb << 14u) + coeff;

                Wide positiveSum =
                    wideMul(shA[0][coeff],
                        shB[0][coeff]);
#pragma unroll 1
                for (u32 k = 2u; k < kTotalTerms; ++k)
                {
                    positiveSum = wideAdd(
                        positiveSum,
                        wideMul(shA[k][coeff],
                            shB[k][coeff]));
                }
                const Wide keyComplement = wideSub(
                    wideMul(mod.mValue, mod.mValue),
                    wideMul(shA[1][coeff],
                        shB[1][coeff]));
                const Wide signedSum =
                    wideAdd(positiveSum, keyComplement);
                const u64 acc = barrettReduce128(
                    signedSum.mLo, signedSum.mHi, mod);
                out[static_cast<size_t>(o) * kPerPoly + elem] = acc;
            }
        }

        // Exact specialization of expandAccumulatorTau1Kernel for the production
        // truncated GoldenSeed tuple N=8192, rho=4, mu=8. The three-dimensional grid makes
        // row, chunk and limb block coordinates instead of recovering row/chunk
        // with a per-thread division. Its linear CTA index is unchanged:
        //
        //   old = o*128 + limb*32 + tile
        //       = (chunk*32 + row*4 + limb)*32 + tile = new.
        //
        // Apart from this bijective coordinate rewrite, the pointer selection and
        // eight-product arithmetic below are deliberately identical to the generic
        // kernel. Eight resident 256-thread CTAs require at most 32 registers on
        // H200; resource inspection rejects this path if nvcc spills instead.
        // Golden Q64-complement specialization with adaptive coefficient tiles.
        // Every output retains the fixed product and addition order.
        __global__ __launch_bounds__(256, 8)
        void expandAccumulatorTau1GoldenExperimentalKernel(
            DeviceRing rg,
            const u64* ct1,
            const u64* uDigits,
            const u64* publicA,
            const u64* skNtt,
            const u64* lacct,
            const u64* nodes,
            const u32* lacctAIdx,
            const u32* lacctBIdx,
            u64* out)
        {
            constexpr u32 kN = 8192;
            constexpr u32 kRho = 4;
            constexpr u32 kMu = 8;
            constexpr u32 kTreeTerms = 6;
            constexpr u32 kTotalTerms = 2 + kTreeTerms;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;

            const u32 rowLimb = blockIdx.y;
            const u32 limb = rowLimb & (kRho - 1u);
            const u32 row = rowLimb >> 2u;
            const u32 chunk = blockIdx.z;
            const u32 o = chunk * kMu + row;
            const size_t limbBase = static_cast<size_t>(limb) * kN;

            // Volatile pointer slots keep the adaptive loop from hoisting all
            // sixteen bases across the back-edge. Each tile reloads the table
            // from shared memory instead of extending pointer lifetimes into
            // local stack spills under the eight-CTA launch bound.
            using SharedPointer = const u64* volatile;
            __shared__ SharedPointer shA[kTotalTerms];
            __shared__ SharedPointer shB[kTotalTerms];
            if (threadIdx.x < kTotalTerms)
            {
                const u32 k = threadIdx.x;
                if (k == 0)
                {
                    shA[k] = ct1 + static_cast<size_t>(row) * kPerPoly + limbBase;
                    shB[k] = uDigits + static_cast<size_t>(chunk) * kPerPoly + limbBase;
                }
                else if (k == 1)
                {
                    shA[k] = publicA + static_cast<size_t>(row) * kPerPoly + limbBase;
                    shB[k] = skNtt + static_cast<size_t>(chunk) * kPerPoly + limbBase;
                }
                else
                {
                    const u32 treeK = k - 2u;
                    const size_t idx = static_cast<size_t>(o) * kTreeTerms + treeK;
                    shA[k] = lacct + static_cast<size_t>(lacctAIdx[idx]) * kPerPoly + limbBase;
                    shB[k] = nodes + static_cast<size_t>(lacctBIdx[idx]) * kPerPoly + limbBase;
                }
            }
            __syncthreads();

            const GpuModulus mod = rg.mMods[limb];
            u32 tile = blockIdx.x;
            for (;;)
            {
                const u32 coeff = (tile << 8u) + threadIdx.x;
                const u32 elem = (limb << 13u) + coeff;

                // Keep the accepted specialization's order exactly: ct1 first,
                // then the six tree terms in index order, then the key complement.
                Wide positiveSum = wideMul(shA[0][coeff], shB[0][coeff]);
#pragma unroll
                for (u32 k = 2; k < kTotalTerms; ++k)
                    positiveSum = wideAdd(positiveSum, wideMul(shA[k][coeff], shB[k][coeff]));

                Wide keyComplement{};
                // The validated coefficient moduli have at most 60 bits.
                // q*2^64 is 0 modulo q and larger than the key product, while
                // q*2^64 + seven products is below 2^125, so all Wide
                // arithmetic here remains exact and non-negative.
                keyComplement = wideSub(
                    Wide{ 0, mod.mValue },
                    wideMul(shA[1][coeff], shB[1][coeff]));

                const Wide signedSum = wideAdd(positiveSum, keyComplement);
                const u64 acc = barrettReduce128(signedSum.mLo, signedSum.mHi, mod);
                out[static_cast<size_t>(o) * kPerPoly + elem] = acc;

                tile += gridDim.x;
                if (tile >= 32u) break;

            }
        }

        // Exact production-only specialization of the accepted Q64/tiled
        // accumulator for q = 2^55-c, 0<c<2^21. The product construction and
        // addition order through signedSum are identical to
        // expandAccumulatorTau1GoldenExperimentalKernel; only its
        // final canonical reduction changes.
        //
        // Writing B=2^55 and signedSum=s0+s1*B+s2*B^2 gives s0,s1<B and
        // s2<2^10 because signedSum<2^120. Since B=q+c,
        //
        //   signedSum = s0 + c*s1 + c^2*s2 (mod q).
        //
        // The right side is below 2^77. A second B split has a high part below
        // 2^22, so one more c multiply produces a value below 2q; one
        // subtraction is therefore the exact canonical residue. All c
        // products below are deliberately expressed through 32-bit operands.
        __global__ __launch_bounds__(256, 8)
        void expandAccumulatorTau1GoldenPseudo55Kernel(
            DeviceRing rg,
            const u64* ct1,
            const u64* uDigits,
            const u64* publicA,
            const u64* skNtt,
            const u64* lacct,
            const u64* nodes,
            const u32* lacctAIdx,
            const u32* lacctBIdx,
            u64* out)
        {
            constexpr u32 kN = 8192u;
            constexpr u32 kRho = 4u;
            constexpr u32 kMu = 8u;
            constexpr u32 kTreeTerms = 6u;
            constexpr u32 kTotalTerms = 2u + kTreeTerms;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;
            constexpr u64 kRadix55 = u64{ 1 } << 55u;
            constexpr u64 kMask55 = kRadix55 - 1u;

            const u32 rowLimb = blockIdx.y;
            const u32 limb = rowLimb & (kRho - 1u);
            const u32 row = rowLimb >> 2u;
            const u32 chunk = blockIdx.z;
            const u32 o = chunk * kMu + row;
            const size_t limbBase = static_cast<size_t>(limb) * kN;

            using SharedPointer = const u64* volatile;
            __shared__ SharedPointer shA[kTotalTerms];
            __shared__ SharedPointer shB[kTotalTerms];
            __shared__ u32 shC;
            if (threadIdx.x < kTotalTerms)
            {
                const u32 k = threadIdx.x;
                if (k == 0u)
                {
                    shA[k] = ct1 + static_cast<size_t>(row) * kPerPoly + limbBase;
                    shB[k] = uDigits + static_cast<size_t>(chunk) * kPerPoly + limbBase;
                }
                else if (k == 1u)
                {
                    shA[k] = publicA + static_cast<size_t>(row) * kPerPoly + limbBase;
                    shB[k] = skNtt + static_cast<size_t>(chunk) * kPerPoly + limbBase;
                }
                else
                {
                    const u32 treeK = k - 2u;
                    const size_t idx = static_cast<size_t>(o) * kTreeTerms + treeK;
                    shA[k] = lacct + static_cast<size_t>(lacctAIdx[idx]) * kPerPoly + limbBase;
                    shB[k] = nodes + static_cast<size_t>(lacctBIdx[idx]) * kPerPoly + limbBase;
                }
            }
            else if (threadIdx.x == kTotalTerms)
            {
                // Host dispatch proves this difference is in (0,2^21).
                shC = static_cast<u32>(kRadix55 - rg.mMods[limb].mValue);
            }
            __syncthreads();

            const u32 c = shC;
            const u64 q = kRadix55 - static_cast<u64>(c);
            u32 tile = blockIdx.x;
            for (;;)
            {
                const u32 coeff = (tile << 8u) + threadIdx.x;
                const u32 elem = (limb << 13u) + coeff;

                // Preserve the accepted specialization exactly through the
                // complete non-negative Q64-complement sum.
                Wide positiveSum = wideMul(shA[0][coeff], shB[0][coeff]);
#pragma unroll
                for (u32 k = 2u; k < kTotalTerms; ++k)
                    positiveSum =
                        wideAdd(positiveSum, wideMul(shA[k][coeff], shB[k][coeff]));
                const Wide keyComplement = wideSub(
                    Wide{ 0u, q }, wideMul(shA[1][coeff], shB[1][coeff]));
                const Wide signedSum = wideAdd(positiveSum, keyComplement);

                const u64 s0 = signedSum.mLo & kMask55;
                const u64 s1 =
                    ((signedSum.mLo >> 55u) | (signedSum.mHi << 9u)) & kMask55;
                const u32 s2 = static_cast<u32>(signedSum.mHi >> 46u);

                // c*s1 as two native 32x32->64 partial products. p1 is below
                // 2^44, so its high word plus both addition carries is exact.
                const u64 p0 = static_cast<u64>(static_cast<u32>(s1)) * c;
                const u64 p1 =
                    static_cast<u64>(static_cast<u32>(s1 >> 32u)) * c;
                u64 tLo = p0 + (p1 << 32u);
                u64 tCarry = static_cast<u64>(tLo < p0);

                // s2*c fits in 31 bits and its second c product fits in 52.
                const u32 s2c = s2 * c;
                const u64 topFold = static_cast<u64>(s2c) * c;
                const u64 addend = s0 + topFold;
                const u64 oldTLo = tLo;
                tLo += addend;
                tCarry += static_cast<u64>(tLo < oldTLo);
                const u64 tHi = (p1 >> 32u) + tCarry;

                const u64 t0 = tLo & kMask55;
                const u32 t1 = static_cast<u32>((tLo >> 55u) | (tHi << 9u));
                u64 acc = t0 + static_cast<u64>(t1) * c;
                if (acc >= q) acc -= q;

                out[static_cast<size_t>(o) * kPerPoly + elem] = acc;

                tile += gridDim.x;
                if (tile >= 32u) break;
            }
        }

        // Defined with the existing packed-pointer successors below. A forward
        // declaration lets the fixed Stage-111 sidecar reuse the audited vector
        // shared-load helper without moving or changing any accepted body.
        __device__ __forceinline__ Wide
        multiplySharedAccumulatorPointerPair(
            const ulonglong2* pair,
            u32 coeff);

        // Stage-111 alpha=2 sidecar for the accepted fixed mu=8/six-term
        // pseudo-55 accumulator above. Its seven non-negative ct1/tree
        // products are below 7*2^110 < 2^113 in total, so splitting them over
        // two Wide carry chains and reassociating their final addition cannot
        // overflow 128 bits. The key complement, pseudo-Mersenne fold, shared
        // pointer layout and adaptive grid are otherwise deliberately identical
        // to the accepted kernel. Keeping a distinct symbol makes the accepted
        // SASS an in-binary rollback while exposing independent carry latency.
        __global__ __launch_bounds__(256, 8)
        void expandAccumulatorTau1GoldenPseudo55DualKernel(
            DeviceRing rg,
            const u64* ct1,
            const u64* uDigits,
            const u64* publicA,
            const u64* skNtt,
            const u64* lacct,
            const u64* nodes,
            const u32* lacctAIdx,
            const u32* lacctBIdx,
            u64* out)
        {
            constexpr u32 kN = 8192u;
            constexpr u32 kRho = 4u;
            constexpr u32 kMu = 8u;
            constexpr u32 kTreeTerms = 6u;
            constexpr u32 kTotalTerms = 2u + kTreeTerms;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;
            constexpr u64 kRadix55 = u64{ 1 } << 55u;
            constexpr u64 kMask55 = kRadix55 - 1u;
            static_assert(sizeof(const u64*) == sizeof(unsigned long long));
            static_assert(alignof(ulonglong2) == 16u);

            const u32 rowLimb = blockIdx.y;
            const u32 limb = rowLimb & (kRho - 1u);
            const u32 row = rowLimb >> 2u;
            const u32 chunk = blockIdx.z;
            const u32 o = chunk * kMu + row;
            const size_t limbBase = static_cast<size_t>(limb) * kN;

            __shared__ ulonglong2 shPairs[kTotalTerms];
            __shared__ u32 shC;
            if (threadIdx.x < kTotalTerms)
            {
                const u32 k = threadIdx.x;
                const u64* a;
                const u64* b;
                if (k == 0u)
                {
                    a = ct1 +
                        static_cast<size_t>(row) * kPerPoly + limbBase;
                    b = uDigits +
                        static_cast<size_t>(chunk) * kPerPoly + limbBase;
                }
                else if (k == 1u)
                {
                    a = publicA +
                        static_cast<size_t>(row) * kPerPoly + limbBase;
                    b = skNtt +
                        static_cast<size_t>(chunk) * kPerPoly + limbBase;
                }
                else
                {
                    const u32 treeK = k - 2u;
                    const size_t idx =
                        static_cast<size_t>(o) * kTreeTerms + treeK;
                    a = lacct +
                        static_cast<size_t>(lacctAIdx[idx]) * kPerPoly +
                        limbBase;
                    b = nodes +
                        static_cast<size_t>(lacctBIdx[idx]) * kPerPoly +
                        limbBase;
                }
                shPairs[k] = make_ulonglong2(
                    reinterpret_cast<unsigned long long>(a),
                    reinterpret_cast<unsigned long long>(b));
            }
            else if (threadIdx.x == kTotalTerms)
            {
                shC = static_cast<u32>(
                    kRadix55 - rg.mMods[limb].mValue);
            }
            __syncthreads();

            const u32 c = shC;
            const u64 q = kRadix55 - static_cast<u64>(c);
            u32 tile = blockIdx.x;
            for (;;)
            {
                const u32 coeff = (tile << 8u) + threadIdx.x;
                const u32 elem = (limb << 13u) + coeff;

                // Four adjacent shared pointer pairs feed two balanced exact
                // chains. The second chain starts with the non-negative key
                // complement, so only one dependent join remains at the tail.
                // It is below q*2^64+3*2^110 < 2^120; the first chain is below
                // 4*2^110. Their complete sum is therefore the same exact
                // (non-wrapping) integer as the accepted serial expression.
                Wide sumEven =
                    multiplySharedAccumulatorPointerPair(shPairs, coeff);
                Wide sumOdd = wideSub(
                    Wide{ 0u, q },
                    multiplySharedAccumulatorPointerPair(
                        shPairs + 1u, coeff));
                sumEven = wideAdd(
                    sumEven,
                    multiplySharedAccumulatorPointerPair(
                        shPairs + 2u, coeff));
                sumOdd = wideAdd(
                    sumOdd,
                    multiplySharedAccumulatorPointerPair(
                        shPairs + 3u, coeff));
                sumEven = wideAdd(
                    sumEven,
                    multiplySharedAccumulatorPointerPair(
                        shPairs + 4u, coeff));
                sumOdd = wideAdd(
                    sumOdd,
                    multiplySharedAccumulatorPointerPair(
                        shPairs + 5u, coeff));
                sumEven = wideAdd(
                    sumEven,
                    multiplySharedAccumulatorPointerPair(
                        shPairs + 6u, coeff));
                sumOdd = wideAdd(
                    sumOdd,
                    multiplySharedAccumulatorPointerPair(
                        shPairs + 7u, coeff));
                const Wide signedSum = wideAdd(sumEven, sumOdd);

                const u64 s0 = signedSum.mLo & kMask55;
                const u64 s1 =
                    ((signedSum.mLo >> 55u) |
                     (signedSum.mHi << 9u)) & kMask55;
                const u32 s2 =
                    static_cast<u32>(signedSum.mHi >> 46u);

                const u64 p0 =
                    static_cast<u64>(static_cast<u32>(s1)) * c;
                const u64 p1 =
                    static_cast<u64>(static_cast<u32>(s1 >> 32u)) * c;
                u64 tLo = p0 + (p1 << 32u);
                u64 tCarry = static_cast<u64>(tLo < p0);

                const u32 s2c = s2 * c;
                const u64 topFold = static_cast<u64>(s2c) * c;
                const u64 addend = s0 + topFold;
                const u64 oldTLo = tLo;
                tLo += addend;
                tCarry += static_cast<u64>(tLo < oldTLo);
                const u64 tHi = (p1 >> 32u) + tCarry;

                const u64 t0 = tLo & kMask55;
                const u32 t1 = static_cast<u32>(
                    (tLo >> 55u) | (tHi << 9u));
                u64 acc = t0 + static_cast<u64>(t1) * c;
                if (acc >= q) acc -= q;

                out[static_cast<size_t>(o) * kPerPoly + elem] = acc;

                tile += gridDim.x;
                if (tile >= 32u) break;
            }
        }

        // Benchmark alpha overrides use the exact power-of-two receiver tuples
        // (mu, treeTerms) = (16,8), (32,10), (64,12), (128,14). Keep their
        // combined accumulator in distinct template instantiations so the
        // accepted mu=8/treeTerms=6 symbol and its SASS remain untouched.
        //
        // With B=2^55 and q=B-c, 0<c<2^21, the largest positive sum contains
        // ct1 plus fourteen tree products and is below 15*2^110. Adding the
        // non-negative q*2^64-keyProduct complement keeps the complete exact
        // value below 2^119+15*2^110<2^120. Its third radix-B digit is therefore
        // below 2^10, so the accepted three-digit pseudo-Mersenne fold below is
        // also exact for every wider tuple.
        // Hopper sidecar for the same strict wide tuples as the accepted
        // Stage-99 kernel above. All operands are non-negative and the complete
        // positive sum is below 2^114, so partitioning it into two Wide values
        // and joining them once is exact (and residue-bit-identical) without an
        // intermediate overflow. Pairing tree terms also halves the rolled-loop
        // control work while exposing two independent carry recurrences.
        __device__ __forceinline__ ulonglong2
        loadSharedAccumulatorPointerPair(const ulonglong2* pair)
        {
            unsigned long long a;
            unsigned long long b;
            const u32 address =
                static_cast<u32>(__cvta_generic_to_shared(pair));
            // The adaptive tile loop must reload the pair instead of extending
            // all sixteen pointer lifetimes across its back-edge. Vector PTX
            // makes scalarization an explicit SASS-gate failure.
            asm volatile(
                "ld.shared.v2.u64 {%0, %1}, [%2];"
                : "=l"(a), "=l"(b)
                : "r"(address)
                : "memory");
            return make_ulonglong2(a, b);
        }

        __device__ __forceinline__ Wide multiplySharedAccumulatorPointerPair(
            const ulonglong2* pair,
            u32 coeff)
        {
            const ulonglong2 bases = loadSharedAccumulatorPointerPair(pair);
            const u64* const a = reinterpret_cast<const u64*>(bases.x);
            const u64* const b = reinterpret_cast<const u64*>(bases.y);
            return wideMul(a[coeff], b[coeff]);
        }

        // NoGoldenSeed port of the GoldenSeed vector shared-pointer table.
        // The positive sum is below 9*2^104; adding q^2-key stays below
        // 10*2^104 < 2^128. Keep q^2 rather than a q*2^64 complement:
        // the latter would invalidate the existing 32-bit s2*c bound.
        __global__ __launch_bounds__(256, 8)
        void expandAccumulatorTau1NoGoldH200PackedKernel(
            DeviceRing rg,
            const u64* ct1, const u64* uDigits,
            const u64* publicA, const u64* skNtt,
            const u64* lacct, const u64* nodes,
            const u32* lacctAIdx, const u32* lacctBIdx, u64* out)
        {
            constexpr u32 kN = 16384u;
            constexpr u32 kRho = 8u;
            constexpr u32 kMu = 16u;
            constexpr u32 kTreeTerms = 8u;
            constexpr u32 kTotalTerms = 10u;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;
            constexpr u64 kRadix52 = u64{ 1 } << 52u;
            constexpr u64 kMask52 = kRadix52 - 1u;
            const u32 limb = blockIdx.y & 7u;
            const u32 row = blockIdx.y >> 3u;
            const u32 chunk = blockIdx.z;
            const u32 o = chunk * kMu + row;
            const size_t limbBase = static_cast<size_t>(limb) * kN;

            __shared__ ulonglong2 shPairs[kTotalTerms];
            if (threadIdx.x < kTotalTerms)
            {
                const u32 k = threadIdx.x;
                const u64* a;
                const u64* b;
                if (k == 0u)
                {
                    a = ct1 + static_cast<size_t>(row) * kPerPoly + limbBase;
                    b = uDigits + static_cast<size_t>(chunk) * kPerPoly + limbBase;
                }
                else if (k == 1u)
                {
                    a = publicA + static_cast<size_t>(row) * kPerPoly + limbBase;
                    b = skNtt + static_cast<size_t>(chunk) * kPerPoly + limbBase;
                }
                else
                {
                    const size_t idx = static_cast<size_t>(o) * kTreeTerms + k - 2u;
                    a = lacct + static_cast<size_t>(lacctAIdx[idx]) * kPerPoly + limbBase;
                    b = nodes + static_cast<size_t>(lacctBIdx[idx]) * kPerPoly + limbBase;
                }
                shPairs[k] = make_ulonglong2(
                    reinterpret_cast<unsigned long long>(a),
                    reinterpret_cast<unsigned long long>(b));
            }
            __syncthreads();

            const u64 registerQ = rg.mMods[limb].mValue;
            for (u32 tile = blockIdx.x; tile < 64u; tile += gridDim.x)
            {
                const u32 coeff = (tile << 8u) + threadIdx.x;
                const auto product = [&](u32 k) {
                    const ulonglong2 bases = loadSharedAccumulatorPointerPair(shPairs + k);
                    return wideMul(
                        __ldca(reinterpret_cast<const u64*>(bases.x) + coeff),
                        __ldca(reinterpret_cast<const u64*>(bases.y) + coeff));
                };
                Wide positiveSum = product(0u);
#pragma unroll 1
                for (u32 k = 2u; k < kTotalTerms; ++k)
                    positiveSum = wideAddCarry(positiveSum, product(k));
                const u32 c = static_cast<u32>(kRadix52 - registerQ);
                const u64 q = registerQ;
                const Wide keyComplement = wideSubCarry(wideMul(q, q), product(1u));
                const Wide signedSum = wideAddCarry(positiveSum, keyComplement);
                const u64 s0 = signedSum.mLo & kMask52;
                const u64 s1 = ((signedSum.mLo >> 52u) |
                    (signedSum.mHi << 12u)) & kMask52;
                const u32 s2 = static_cast<u32>(signedSum.mHi >> 40u);
                const u64 p0 = static_cast<u64>(static_cast<u32>(s1)) * c;
                const u64 p1 = static_cast<u64>(static_cast<u32>(s1 >> 32u)) * c;
                u64 tLo = p0 + (p1 << 32u);
                u64 tCarry = static_cast<u64>(tLo < p0);
                const u32 s2c = s2 * c;
                const u64 topFold = static_cast<u64>(s2c) * c;
                const u64 addend = s0 + topFold;
                const u64 oldTLo = tLo;
                tLo += addend;
                tCarry += static_cast<u64>(tLo < oldTLo);
                const u64 tHi = (p1 >> 32u) + tCarry;
                const u64 t0 = tLo & kMask52;
                const u32 t1 = static_cast<u32>((tLo >> 52u) | (tHi << 12u));
                u64 acc = t0 + static_cast<u64>(t1) * c;
                if (acc >= q) acc -= q;
                out[static_cast<size_t>(o) * kPerPoly + (limb << 14u) + coeff] = acc;
            }
        }

        // Packed-pointer successor to the Stage-101 dual-Wide accumulator. The
        // positive products retain exactly the same two carry chains and join
        // order of the dual-Wide accumulator; only the shared
        // pointer-table representation changes. Keeping a separate symbol
        // preserves both accepted wide implementations as codegen-stable
        // same-binary rollbacks.
        template<u32 Mu, u32 TreeTerms>
        __global__ __launch_bounds__(256, 8)
        void expandAccumulatorTau1WidePseudo55DualPackedPairsKernel(
            DeviceRing rg,
            const u64* ct1,
            const u64* uDigits,
            const u64* publicA,
            const u64* skNtt,
            const u64* lacct,
            const u64* nodes,
            const u32* lacctAIdx,
            const u32* lacctBIdx,
            u64* out)
        {
            static_assert(
                (Mu == 16u && TreeTerms == 8u) ||
                (Mu == 32u && TreeTerms == 10u) ||
                (Mu == 64u && TreeTerms == 12u) ||
                (Mu == 128u && TreeTerms == 14u));
            static_assert((TreeTerms & 1u) == 0u);
            constexpr u32 kN = 8192u;
            constexpr u32 kRho = 4u;
            constexpr u32 kTotalTerms = 2u + TreeTerms;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;
            constexpr u64 kRadix55 = u64{ 1 } << 55u;
            constexpr u64 kMask55 = kRadix55 - 1u;
            static_assert(sizeof(const u64*) == sizeof(unsigned long long));
            static_assert(alignof(ulonglong2) == 16u);

            const u32 rowLimb = blockIdx.y;
            const u32 limb = rowLimb & (kRho - 1u);
            const u32 row = rowLimb >> 2u;
            const u32 chunk = blockIdx.z;
            const u32 o = chunk * Mu + row;

            __shared__ ulonglong2 shPairs[kTotalTerms];
            __shared__ u32 shC;
            if (threadIdx.x < kTotalTerms)
            {
                const u32 k = threadIdx.x;
                const size_t limbBase = static_cast<size_t>(limb) * kN;
                const u64* a;
                const u64* b;
                if (k == 0u)
                {
                    a = ct1 +
                        static_cast<size_t>(row) * kPerPoly + limbBase;
                    b = uDigits +
                        static_cast<size_t>(chunk) * kPerPoly + limbBase;
                }
                else if (k == 1u)
                {
                    a = publicA +
                        static_cast<size_t>(row) * kPerPoly + limbBase;
                    b = skNtt +
                        static_cast<size_t>(chunk) * kPerPoly + limbBase;
                }
                else
                {
                    const u32 treeK = k - 2u;
                    const size_t idx =
                        static_cast<size_t>(o) * TreeTerms + treeK;
                    a = lacct +
                        static_cast<size_t>(lacctAIdx[idx]) * kPerPoly +
                        limbBase;
                    b = nodes +
                        static_cast<size_t>(lacctBIdx[idx]) * kPerPoly +
                        limbBase;
                }
                shPairs[k] = make_ulonglong2(
                    reinterpret_cast<unsigned long long>(a),
                    reinterpret_cast<unsigned long long>(b));
            }
            else if (threadIdx.x == kTotalTerms)
            {
                shC = static_cast<u32>(
                    kRadix55 - rg.mMods[limb].mValue);
            }
            __syncthreads();

            u32 tile = blockIdx.x;
            for (;;)
            {
                const u32 coeff = (tile << 8u) + threadIdx.x;
                const u32 elem = (limb << 13u) + coeff;

                // Preserve the Stage-101 grouping exactly: ct1 seeds the even
                // chain, tree term zero seeds the odd chain, paired tree terms
                // extend them, and the final tree term completes the even side.
                Wide positiveEven =
                    multiplySharedAccumulatorPointerPair(
                        shPairs, coeff);
                Wide positiveOdd =
                    multiplySharedAccumulatorPointerPair(
                        shPairs + 2u, coeff);
#pragma unroll 1
                for (u32 k = 3u; k + 1u < kTotalTerms; k += 2u)
                {
                    positiveEven = wideAdd(
                        positiveEven,
                        multiplySharedAccumulatorPointerPair(
                            shPairs + k, coeff));
                    positiveOdd = wideAdd(
                        positiveOdd,
                        multiplySharedAccumulatorPointerPair(
                            shPairs + k + 1u, coeff));
                }
                positiveEven = wideAdd(
                    positiveEven,
                    multiplySharedAccumulatorPointerPair(
                        shPairs + kTotalTerms - 1u, coeff));
                const Wide positiveSum =
                    wideAdd(positiveEven, positiveOdd);

                const u32 c = shC;
                const u64 q = kRadix55 - static_cast<u64>(c);
                const Wide keyComplement = wideSub(
                    Wide{ 0u, q },
                    multiplySharedAccumulatorPointerPair(
                        shPairs + 1u, coeff));
                const Wide signedSum =
                    wideAdd(positiveSum, keyComplement);

                const u64 s0 = signedSum.mLo & kMask55;
                const u64 s1 =
                    ((signedSum.mLo >> 55u) |
                     (signedSum.mHi << 9u)) & kMask55;
                const u32 s2 =
                    static_cast<u32>(signedSum.mHi >> 46u);

                const u64 p0 =
                    static_cast<u64>(static_cast<u32>(s1)) * c;
                const u64 p1 =
                    static_cast<u64>(static_cast<u32>(s1 >> 32u)) * c;
                u64 tLo = p0 + (p1 << 32u);
                u64 tCarry = static_cast<u64>(tLo < p0);

                const u32 s2c = s2 * c;
                const u64 topFold = static_cast<u64>(s2c) * c;
                const u64 addend = s0 + topFold;
                const u64 oldTLo = tLo;
                tLo += addend;
                tCarry += static_cast<u64>(tLo < oldTLo);
                const u64 tHi = (p1 >> 32u) + tCarry;

                const u64 t0 = tLo & kMask55;
                const u32 t1 = static_cast<u32>(
                    (tLo >> 55u) | (tHi << 9u));
                u64 acc = t0 + static_cast<u64>(t1) * c;
                if (acc >= q) acc -= q;

                out[static_cast<size_t>(o) * kPerPoly + elem] = acc;

                tile += gridDim.x;
                if (tile >= 32u) break;
            }
        }


        __global__ void innerProductKernel(
            DeviceRing rg,
            const u64* aBase,
            const u64* bBase,
            const u32* aIdx,
            const u32* bIdx,
            u32 terms,
            u64* out,
            const u32* outIdx,
            u32 outCount,
            bool accumulate,
            bool negate,
            bool subtract)
        {
            const u32 n = rg.mN;
            const size_t perPoly = static_cast<size_t>(rg.mRho) * n;
            const u32 outCountArg = outCount;
            const u32 perPolyU = static_cast<u32>(perPoly);
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            // Not an early return: the loop below has a block-wide barrier, so every
            // thread has to stay for it. Only the last block in x has idle threads.
            const bool active = elem < perPolyU;
            // N is a power of two, so the limb/coefficient split is a shift and
            // a mask; an actual 64-bit division here costs ~70 instructions.
            const u32 limb = active ? (elem >> rg.mLogN) : 0u;
            const u32 coeff = elem & (n - 1u);

            // The operand base pointers for one output, resolved once per block
            // instead of once per element: aIdx/bIdx depend only on `o`, which is
            // block-uniform, so the reload was `terms` pairs of L1 hits and address
            // computations per element.
            __shared__ const u64* shA[kMaxFusedIpTerms];
            __shared__ const u64* shB[kMaxFusedIpTerms];
            const bool hoist = terms <= kMaxFusedIpTerms;

            for (u32 o = blockIdx.y; o < outCountArg; o += gridDim.y)
            {
                if (hoist)
                {
                    // On the first (and overwhelmingly common only) y iteration
                    // there are no prior shared pointers to protect. Later
                    // iterations still need this barrier before overwriting them.
                    if (o != blockIdx.y) __syncthreads();
                    for (u32 k = threadIdx.x; k < terms; k += blockDim.x)
                    {
                        const u32 ai = aIdx ? aIdx[static_cast<size_t>(o) * terms + k] : k;
                        const u32 bi = bIdx ? bIdx[static_cast<size_t>(o) * terms + k] : k;
                        shA[k] = aBase + static_cast<size_t>(ai) * perPoly;
                        shB[k] = bBase + static_cast<size_t>(bi) * perPoly;
                    }
                    __syncthreads();
                }
                if (!active) continue;

                const GpuModulus mod = rg.mMods[limb];
                const size_t limbOff = static_cast<size_t>(limb) * n + coeff;

                // Lazy accumulation, as in the fused inner product: the exact
                // 128-bit product sum stays below 2^126 for 60-bit moduli and
                // kMaxFusedIpTerms terms, so one Barrett reduction at the end
                // replaces one per term and yields the same residue.
                u64 acc = 0;
                u32 k = 0;
                if (hoist)
                {
                    Wide sum{ 0, 0 };
                    for (; k < terms; ++k)
                    {
                        sum = wideAdd(sum, wideMul(shA[k][limbOff], shB[k][limbOff]));
                    }
                    acc = barrettReduce128(sum.mLo, sum.mHi, mod);
                }
                else
                {
                    for (; k < terms; ++k)
                    {
                        const u32 ai = aIdx ? aIdx[static_cast<size_t>(o) * terms + k] : k;
                        const u32 bi = bIdx ? bIdx[static_cast<size_t>(o) * terms + k] : k;
                        const u64 av = aBase[static_cast<size_t>(ai) * perPoly + limbOff];
                        const u64 bv = bBase[static_cast<size_t>(bi) * perPoly + limbOff];
                        acc = mulAddMod(av, bv, acc, mod);
                    }
                }

                const u32 oi = outIdx ? outIdx[o] : o;
                u64* dst = out + static_cast<size_t>(oi) * perPoly + limbOff;
                if (subtract)
                {
                    // out = out - sum, in one pass. Note this is deliberately not
                    // expressible as accumulate + negate, which yields
                    // -(out + sum) because negate is applied last.
                    acc = subMod(*dst, acc, mod.mValue);
                }
                else
                {
                    if (accumulate)
                    {
                        acc = addMod(*dst, acc, mod.mValue);
                    }
                    if (negate && acc != 0)
                    {
                        acc = mod.mValue - acc;
                    }
                }
                *dst = acc;
            }
        }

        __global__ void elementwiseKernel(
            DeviceRing rg,
            const u64* aBase,
            const u32* aIdx,
            const u64* bBase,
            const u32* bIdx,
            u64* out,
            const u32* outIdx,
            u32 outCount,
            u32 op)
        {
            const u32 n = rg.mN;
            const size_t perPoly = static_cast<size_t>(rg.mRho) * n;
            const u32 outCountArg = outCount;
            const u32 perPolyU = static_cast<u32>(perPoly);
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            if (elem >= perPolyU) return;
            // N is a power of two, so the limb/coefficient split is a shift and
            // a mask; an actual 64-bit division here costs ~70 instructions.
            const u32 limb = elem >> rg.mLogN;
            const u32 coeff = elem & (n - 1u);
            for (u32 o = blockIdx.y; o < outCountArg; o += gridDim.y)
            {
                const u64 q = rg.mMods[limb].mValue;
                const size_t limbOff = static_cast<size_t>(limb) * n + coeff;

                const u32 ai = aIdx ? aIdx[o] : o;
                const u64 av = aBase[static_cast<size_t>(ai) * perPoly + limbOff];
                u64 res;
                if (op == 2u)
                {
                    res = (av == 0) ? 0 : (q - av);
                }
                else if (op == 3u)
                {
                    res = av;
                }
                else
                {
                    const u32 bi = bIdx ? bIdx[o] : o;
                    const u64 bv = bBase[static_cast<size_t>(bi) * perPoly + limbOff];
                    res = (op == 0u) ? addMod(av, bv, q) : subMod(av, bv, q);
                }

                const u32 oi = outIdx ? outIdx[o] : o;
                out[static_cast<size_t>(oi) * perPoly + limbOff] = res;
            }
        }

        __global__ void scalePow2Kernel(
            DeviceRing rg,
            const u64* aBase,
            const u32* aIdx,
            u64* out,
            const u32* outIdx,
            u32 outCount,
            const u64* factors)
        {
            const u32 n = rg.mN;
            const size_t perPoly = static_cast<size_t>(rg.mRho) * n;
            const u32 outCountArg = outCount;
            const u32 perPolyU = static_cast<u32>(perPoly);
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            if (elem >= perPolyU) return;
            // N is a power of two, so the limb/coefficient split is a shift and
            // a mask; an actual 64-bit division here costs ~70 instructions.
            const u32 limb = elem >> rg.mLogN;
            const u32 coeff = elem & (n - 1u);
            for (u32 o = blockIdx.y; o < outCountArg; o += gridDim.y)
            {
                const GpuModulus mod = rg.mMods[limb];
                const size_t limbOff = static_cast<size_t>(limb) * n + coeff;

                const u32 ai = aIdx ? aIdx[o] : o;
                const u64 av = aBase[static_cast<size_t>(ai) * perPoly + limbOff];
                const u32 oi = outIdx ? outIdx[o] : o;
                out[static_cast<size_t>(oi) * perPoly + limbOff] = mulMod(av, factors[limb], mod);
            }
        }

        __global__ void canonicalizeKernel(DeviceRing rg, u64* data, const u32* polyIdx, u32 polyCount)
        {
            const u32 n = rg.mN;
            const size_t perPoly = static_cast<size_t>(rg.mRho) * n;
            const u32 outCountArg = polyCount;
            const u32 perPolyU = static_cast<u32>(perPoly);
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            if (elem >= perPolyU) return;
            // N is a power of two, so the limb/coefficient split is a shift and
            // a mask; an actual 64-bit division here costs ~70 instructions.
            const u32 limb = elem >> rg.mLogN;
            const u32 coeff = elem & (n - 1u);
            for (u32 o = blockIdx.y; o < outCountArg; o += gridDim.y)
            {
                const GpuModulus mod = rg.mMods[limb];
                const u32 pi = polyIdx ? polyIdx[o] : o;
                u64* p = data + static_cast<size_t>(pi) * perPoly + static_cast<size_t>(limb) * n + coeff;
                const u64 v = *p;
                *p = (v < mod.mValue) ? v : barrettReduce64(v, mod);
            }
        }

        // ---- gadget decomposition ----------------------------------------

        constexpr u64 kGadgetHi110HalfHi = u64(1) << 45;
        constexpr u64 kGadgetHi110BaseHi = u64(1) << 46;
        constexpr u64 kGadgetHi110MaskHi = kGadgetHi110BaseHi - 1u;
        constexpr u64 kGadgetRadix55 = u64(1) << 55;

        // Reduce a magnitude bounded by 2^109 modulo q, where
        // 2^54 < q < 2^55. Writing magnitude = lo55 + hi55*2^55 gives
        // hi55 <= 2^54 < q, while lo55 < 2^55 < 2q and therefore needs at
        // most one subtraction. The Shoup operand for 2^55 mod q is
        // 2^55-q. Its quotient can be recovered without another table from
        // R=floor(2^128/q), already stored in GpuModulus:
        //
        //   floor((2^55-q)*2^64/q) = floor(R/2^9) - 2^64.
        //
        // Taking the low word of R>>9 performs the final subtraction exactly.
        __device__ __forceinline__ u64 gadgetReduceMagnitude110Radix55(
            u64 magLo, u64 magHi, const GpuModulus& mod)
        {
            constexpr u64 mask55 = kGadgetRadix55 - 1u;
            const u64 q = mod.mValue;
            u64 lo55 = magLo & mask55;
            const u64 hi55 = (magLo >> 55u) | (magHi << 9u);
            lo55 = (lo55 >= q) ? (lo55 - q) : lo55;

            const ShoupOperand radix55{
                kGadgetRadix55 - q,
                (mod.mRatio1 << 55u) | (mod.mRatio0 >> 9u)
            };
            return addMod(lo55, mulShoup(hi55, radix55, q), q);
        }

        // Candidate-only small-complement replacement for the accepted Shoup
        // fold above. Let R=2^55, q=R-c, 0<c<2^21, and x<=2^109. With
        // x=lo55+hi55*R,
        //
        //   t = lo55 + hi55*c,
        //   y = (t mod R) + floor(t/R)*c == x (mod q).
        //
        // hi55<=2^54 and the endpoint hi55=2^54 implies lo55=0. Thus
        // floor(t/R)<=2^20. Consequently y<R+2^41<2q under the strict
        // q>R-2^21 bound, so exactly one final conditional subtraction makes
        // the result canonical. The split product prevents ptxas from
        // materializing a generic 64x64-wide multiply or Barrett/Shoup chain.
        __device__ __forceinline__ u64
        gadgetReduceMagnitude110Pseudo55SecondFold(
            u64 magLo, u64 magHi, u64 q, u32 c)
        {
            constexpr u64 mask55 = kGadgetRadix55 - 1u;
            const u64 lo55 = magLo & mask55;
            const u64 hi55 = (magLo >> 55u) | (magHi << 9u);

            const u64 p0 =
                static_cast<u64>(static_cast<u32>(hi55)) * c;
            const u64 p1 =
                static_cast<u64>(static_cast<u32>(hi55 >> 32u)) * c;
            u64 tLo = p0 + (p1 << 32u);
            u64 tHi =
                (p1 >> 32u) + static_cast<u64>(tLo < p0);
            const u64 oldTLo = tLo;
            tLo += lo55;
            tHi += static_cast<u64>(tLo < oldTLo);

            const u64 t0 = tLo & mask55;
            const u32 t1 = static_cast<u32>(
                (tLo >> 55u) | (tHi << 9u));
            u64 y = t0 + static_cast<u64>(t1) * c;
            if (y >= q) y -= q;
            return y;
        }


        // Fixed production high digit. For B=2^110 and the centred CRT value x,
        // the generic level-zero state is
        //
        //   floor(x/B) + I[(x mod B) >= B/2]
        //     = floor((x + B/2) / B).
        //
        // Its only requested output is the balanced residue of that state modulo
        // B, so the second generic arithmetic shift is dead. Extracting bits
        // 110..219 after adding bit 109 gives those low 110 quotient bits for
        // positive and negative x alike; arithmetic sign fill begins above them.
        __global__ void gadgetDecomposeHi110Rho4Kernel(
            DeviceRing rg,
            const u64* in,
            const u32* inIdx,
            u32 inCount,
            u64* out,
            const u32* outIdx)
        {
            const u32 n = rg.mN;
            constexpr u32 w = 4;
            const size_t perPoly = static_cast<size_t>(w) * n;
            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;

            for (u32 o = blockIdx.y; o < inCount; o += gridDim.y)
            {
                const u32 ii = inIdx ? inIdx[o] : o;
                u64 value[w];
                crtCompose(
                    in + static_cast<size_t>(ii) * perPoly + coeff,
                    n,
                    rg.mMods,
                    rg.mInvPuncturedProd,
                    rg.mPuncturedProd,
                    rg.mBaseProd,
                    value);

                // Map the canonical CRT representative into [-floor(Q/2),
                // floor(Q/2)], exactly as centeredDecomposeSlow does.
                if (mpGreaterG(value, rg.mBaseProdHalf))
                {
                    mpSubG(value, rg.mBaseProd, value);
                }

                // z = x + 2^109. Word zero cannot participate because the addend
                // starts in word one. Discarding a carry beyond word three is the
                // required fixed-width two's-complement addition; it can occur for
                // negative x and leaves the exact low quotient bits extracted below.
                u64 z1;
                u64 z2;
                u64 z3;
                unsigned char carry = addU64(value[1], u64(1) << 45, &z1);
                carry = addU64(value[2], static_cast<u64>(carry), &z2);
                addU64(value[3], static_cast<u64>(carry), &z3);

                // Low 110 bits of arithmetic_shift_right(z, 110).
                const u64 rawLo = (z1 >> 46) | (z2 << 18);
                const u64 rawHi = ((z2 >> 46) | (z3 << 18)) & kGadgetHi110MaskHi;
                const bool negative = (rawHi & kGadgetHi110HalfHi) != 0;

                // Absolute value in the 110-bit two's-complement domain. The
                // magnitude is at most 2^109, hence magHi <= 2^45. The launcher
                // guards min(q_j)>2^45, satisfying barrettReduce128's hi<q_j
                // precondition without another reduction in this hot loop.
                const u64 magLo = negative ? (u64(0) - rawLo) : rawLo;
                const u64 magHi = negative
                    ? (kGadgetHi110BaseHi - rawHi - static_cast<u64>(rawLo != 0))
                    : rawHi;

                // levels is fixed at one, so generic slot o*levels+0 is just o.
                const u32 oi = outIdx ? outIdx[o] : o;
                u64* dst = out + static_cast<size_t>(oi) * perPoly + coeff;
#pragma unroll
                for (u32 m = 0; m < w; ++m)
                {
                    const GpuModulus mod = rg.mMods[m];
                    const u64 reduced = barrettReduce128(magLo, magHi, mod);
                    dst[static_cast<size_t>(m) * n] =
                        (negative && reduced != 0) ? (mod.mValue - reduced) : reduced;
                }
            }
        }

        // Same fixed Hi110 digit extraction and output reduction as the accepted
        // kernel above; only CRT composition uses the q_j<2^55 bounds proven in
        // crtComposeRho4Compact55. Keeping a distinct entry point makes toggle-off
        // a true same-binary rollback for both semantics and code generation.
        __global__ void gadgetDecomposeHi110Rho4CompactCrtKernel(
            DeviceRing rg,
            const u64* in,
            const u32* inIdx,
            u32 inCount,
            u64* out,
            const u32* outIdx)
        {
            const u32 n = rg.mN;
            constexpr u32 w = 4;
            const size_t perPoly = static_cast<size_t>(w) * n;
            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;

            for (u32 o = blockIdx.y; o < inCount; o += gridDim.y)
            {
                const u32 ii = inIdx ? inIdx[o] : o;
                u64 value[w];
                crtComposeRho4Compact55(
                    in + static_cast<size_t>(ii) * perPoly + coeff,
                    n,
                    rg.mMods,
                    rg.mInvPuncturedProd,
                    rg.mPuncturedProd,
                    rg.mBaseProd,
                    value);

                if (mpGreaterG(value, rg.mBaseProdHalf))
                {
                    mpSubG(value, rg.mBaseProd, value);
                }

                u64 z1;
                u64 z2;
                u64 z3;
                unsigned char carry = addU64(value[1], u64(1) << 45, &z1);
                carry = addU64(value[2], static_cast<u64>(carry), &z2);
                addU64(value[3], static_cast<u64>(carry), &z3);

                const u64 rawLo = (z1 >> 46) | (z2 << 18);
                const u64 rawHi =
                    ((z2 >> 46) | (z3 << 18)) & kGadgetHi110MaskHi;
                const bool negative = (rawHi & kGadgetHi110HalfHi) != 0;

                const u64 magLo = negative ? (u64(0) - rawLo) : rawLo;
                const u64 magHi = negative
                    ? (kGadgetHi110BaseHi - rawHi -
                       static_cast<u64>(rawLo != 0))
                    : rawHi;

                const u32 oi = outIdx ? outIdx[o] : o;
                u64* dst = out + static_cast<size_t>(oi) * perPoly + coeff;
#pragma unroll
                for (u32 m = 0; m < w; ++m)
                {
                    const GpuModulus mod = rg.mMods[m];
                    const u64 reduced = barrettReduce128(magLo, magHi, mod);
                    dst[static_cast<size_t>(m) * n] =
                        (negative && reduced != 0)
                            ? (mod.mValue - reduced)
                            : reduced;
                }
            }
        }

        // Same CRT composition, centering, and fixed Hi110 extraction as the
        // accepted compact kernel. Only the final per-limb reduction uses the
        // exact radix-2^55 fold above. A separate entry point makes toggle-off a
        // codegen-stable rollback to gadgetDecomposeHi110Rho4CompactCrtKernel.
        __global__ void gadgetDecomposeHi110Rho4CompactCrtRadix55Kernel(
            DeviceRing rg,
            const u64* in,
            const u32* inIdx,
            u32 inCount,
            u64* out,
            const u32* outIdx)
        {
            const u32 n = rg.mN;
            constexpr u32 w = 4;
            const size_t perPoly = static_cast<size_t>(w) * n;
            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;

            for (u32 o = blockIdx.y; o < inCount; o += gridDim.y)
            {
                const u32 ii = inIdx ? inIdx[o] : o;
                u64 value[w];
                crtComposeRho4Compact55(
                    in + static_cast<size_t>(ii) * perPoly + coeff,
                    n,
                    rg.mMods,
                    rg.mInvPuncturedProd,
                    rg.mPuncturedProd,
                    rg.mBaseProd,
                    value);

                if (mpGreaterG(value, rg.mBaseProdHalf))
                {
                    mpSubG(value, rg.mBaseProd, value);
                }

                u64 z1;
                u64 z2;
                u64 z3;
                unsigned char carry = addU64(value[1], u64(1) << 45, &z1);
                carry = addU64(value[2], static_cast<u64>(carry), &z2);
                addU64(value[3], static_cast<u64>(carry), &z3);

                const u64 rawLo = (z1 >> 46) | (z2 << 18);
                const u64 rawHi =
                    ((z2 >> 46) | (z3 << 18)) & kGadgetHi110MaskHi;
                const bool negative = (rawHi & kGadgetHi110HalfHi) != 0;

                const u64 magLo = negative ? (u64(0) - rawLo) : rawLo;
                const u64 magHi = negative
                    ? (kGadgetHi110BaseHi - rawHi -
                       static_cast<u64>(rawLo != 0))
                    : rawHi;

                const u32 oi = outIdx ? outIdx[o] : o;
                u64* dst = out + static_cast<size_t>(oi) * perPoly + coeff;
#pragma unroll
                for (u32 m = 0; m < w; ++m)
                {
                    const GpuModulus mod = rg.mMods[m];
                    const u64 reduced =
                        gadgetReduceMagnitude110Radix55(magLo, magHi, mod);
                    dst[static_cast<size_t>(m) * n] =
                        (negative && reduced != 0)
                            ? (mod.mValue - reduced)
                            : reduced;
                }
            }
        }

        // Stage-89 dense sidecar. CRT composition, centering, digit extraction,
        // signs, scatter indexing, and stores duplicate the accepted Radix55
        // symbol; only the final magnitude reduction uses the bounded second
        // pseudo-55 fold.
        __global__ __launch_bounds__(128)
        void gadgetDecomposeHi110Rho4CompactCrtPseudo55SecondFoldKernel(
            DeviceRing rg,
            const u64* in,
            const u32* inIdx,
            u32 inCount,
            u64* out,
            const u32* outIdx)
        {
            constexpr u32 n = 8192u;
            constexpr u32 w = 4u;
            constexpr size_t perPoly = size_t(w) * n;
            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;

            for (u32 o = blockIdx.y; o < inCount; o += gridDim.y)
            {
                const u32 ii = inIdx ? inIdx[o] : o;
                u64 value[w];
                crtComposeRho4Compact55(
                    in + static_cast<size_t>(ii) * perPoly + coeff,
                    n,
                    rg.mMods,
                    rg.mInvPuncturedProd,
                    rg.mPuncturedProd,
                    rg.mBaseProd,
                    value);

                if (mpGreaterG(value, rg.mBaseProdHalf))
                {
                    mpSubG(value, rg.mBaseProd, value);
                }

                u64 z1;
                u64 z2;
                u64 z3;
                unsigned char carry =
                    addU64(value[1], u64(1) << 45, &z1);
                carry = addU64(
                    value[2], static_cast<u64>(carry), &z2);
                addU64(value[3], static_cast<u64>(carry), &z3);

                const u64 rawLo = (z1 >> 46) | (z2 << 18);
                const u64 rawHi =
                    ((z2 >> 46) | (z3 << 18)) & kGadgetHi110MaskHi;
                const bool negative =
                    (rawHi & kGadgetHi110HalfHi) != 0;

                const u64 magLo =
                    negative ? (u64(0) - rawLo) : rawLo;
                const u64 magHi = negative
                    ? (kGadgetHi110BaseHi - rawHi -
                       static_cast<u64>(rawLo != 0))
                    : rawHi;

                const u32 oi = outIdx ? outIdx[o] : o;
                u64* dst =
                    out + static_cast<size_t>(oi) * perPoly + coeff;
#pragma unroll
                for (u32 m = 0; m < w; ++m)
                {
                    const u64 q = rg.mMods[m].mValue;
                    const u32 c = static_cast<u32>(
                        kGadgetRadix55 - q);
                    const u64 reduced =
                        gadgetReduceMagnitude110Pseudo55SecondFold(
                            magLo, magHi, q, c);
                    dst[static_cast<size_t>(m) * n] =
                        (negative && reduced != 0)
                            ? (q - reduced)
                            : reduced;
                }
            }
        }

        // Candidate-only sparse recursive-leaf consumer. Separate fixed-pair
        // instantiations keep the first active CRT limb known at compile time and
        // avoid making both address paths live in one kernel. Input parent o is
        // even for active limbs 0/1 and odd for active limbs 2/3. The output is
        // nevertheless a complete dense rho4 polynomial.
        template<u32 First>
        __global__ void gadgetDecomposeHi110Rho4SparsePairCompactCrtRadix55Kernel(
            DeviceRing rg,
            const u64* in,
            u32 pairCount,
            u64* out,
            const u32* outIdx)
        {
            static_assert(First == 0u || First == 2u);
            constexpr u32 n = 8192u;
            constexpr u32 w = 4u;
            constexpr size_t perPoly = size_t(w) * n;
            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;

            for (u32 pair = blockIdx.y; pair < pairCount; pair += gridDim.y)
            {
                const u32 o = (pair << 1u) + (First >> 1u);
                u64 value[w];
                crtComposeRho4Compact55Pair<First>(
                    in + static_cast<size_t>(o) * perPoly + coeff,
                    n,
                    rg.mMods,
                    rg.mInvPuncturedProd,
                    rg.mPuncturedProd,
                    rg.mBaseProd,
                    value);

                if (mpGreaterG(value, rg.mBaseProdHalf))
                {
                    mpSubG(value, rg.mBaseProd, value);
                }

                u64 z1;
                u64 z2;
                u64 z3;
                unsigned char carry = addU64(value[1], u64(1) << 45, &z1);
                carry = addU64(value[2], static_cast<u64>(carry), &z2);
                addU64(value[3], static_cast<u64>(carry), &z3);

                const u64 rawLo = (z1 >> 46) | (z2 << 18);
                const u64 rawHi =
                    ((z2 >> 46) | (z3 << 18)) & kGadgetHi110MaskHi;
                const bool negative = (rawHi & kGadgetHi110HalfHi) != 0;

                const u64 magLo = negative ? (u64(0) - rawLo) : rawLo;
                const u64 magHi = negative
                    ? (kGadgetHi110BaseHi - rawHi -
                       static_cast<u64>(rawLo != 0))
                    : rawHi;

                const u32 oi = outIdx ? outIdx[o] : o;
                u64* dst = out + static_cast<size_t>(oi) * perPoly + coeff;
#pragma unroll
                for (u32 m = 0; m < w; ++m)
                {
                    const GpuModulus mod = rg.mMods[m];
                    const u64 reduced =
                        gadgetReduceMagnitude110Radix55(magLo, magHi, mod);
                    dst[static_cast<size_t>(m) * n] =
                        (negative && reduced != 0)
                            ? (mod.mValue - reduced)
                            : reduced;
                }
            }
        }

        // Stage-89 sparse-pair sidecars. First remains a compile-time pair so
        // the accepted input ownership/address shape is unchanged; the output
        // is still a complete dense rho4 polynomial.
        template<u32 First>
        __global__ __launch_bounds__(128)
        void gadgetDecomposeHi110Rho4SparsePairCompactCrtPseudo55SecondFoldKernel(
            DeviceRing rg,
            const u64* in,
            u32 pairCount,
            u64* out,
            const u32* outIdx)
        {
            static_assert(First == 0u || First == 2u);
            constexpr u32 n = 8192u;
            constexpr u32 w = 4u;
            constexpr size_t perPoly = size_t(w) * n;
            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;

            for (u32 pair = blockIdx.y; pair < pairCount; pair += gridDim.y)
            {
                const u32 o = (pair << 1u) + (First >> 1u);
                u64 value[w];
                crtComposeRho4Compact55Pair<First>(
                    in + static_cast<size_t>(o) * perPoly + coeff,
                    n,
                    rg.mMods,
                    rg.mInvPuncturedProd,
                    rg.mPuncturedProd,
                    rg.mBaseProd,
                    value);

                if (mpGreaterG(value, rg.mBaseProdHalf))
                {
                    mpSubG(value, rg.mBaseProd, value);
                }

                u64 z1;
                u64 z2;
                u64 z3;
                unsigned char carry =
                    addU64(value[1], u64(1) << 45, &z1);
                carry = addU64(
                    value[2], static_cast<u64>(carry), &z2);
                addU64(value[3], static_cast<u64>(carry), &z3);

                const u64 rawLo = (z1 >> 46) | (z2 << 18);
                const u64 rawHi =
                    ((z2 >> 46) | (z3 << 18)) & kGadgetHi110MaskHi;
                const bool negative =
                    (rawHi & kGadgetHi110HalfHi) != 0;

                const u64 magLo =
                    negative ? (u64(0) - rawLo) : rawLo;
                const u64 magHi = negative
                    ? (kGadgetHi110BaseHi - rawHi -
                       static_cast<u64>(rawLo != 0))
                    : rawHi;

                const u32 oi = outIdx ? outIdx[o] : o;
                u64* dst =
                    out + static_cast<size_t>(oi) * perPoly + coeff;
#pragma unroll
                for (u32 m = 0; m < w; ++m)
                {
                    const u64 q = rg.mMods[m].mValue;
                    const u32 c = static_cast<u32>(
                        kGadgetRadix55 - q);
                    const u64 reduced =
                        gadgetReduceMagnitude110Pseudo55SecondFold(
                            magLo, magHi, q, c);
                    dst[static_cast<size_t>(m) * n] =
                        (negative && reduced != 0)
                            ? (q - reduced)
                            : reduced;
                }
            }
        }

        // Templated on the RNS word count so that every multi-precision
        // temporary below (value, digit, digitAbs, base, one) can live in
        // registers. With a runtime `w` the loops cannot unroll, the arrays go to
        // local memory, and the kernel carried a 448-byte stack frame and 94
        // registers at 132 GiB/s. The launcher dispatches on rho.
        template<u32 W>
        __global__ void gadgetDecomposeKernelT(
            DeviceRing rg,
            const u64* in,
            const u32* inIdx,
            u32 inCount,
            u32 digitBits,
            u32 startLevel,
            u32 levels,
            bool centered,
            u64* out,
            const u32* outIdx,
            bool garner)
        {
            const u32 n = rg.mN;
            constexpr u32 w = W;
            const size_t perPoly = static_cast<size_t>(w) * n;
            const u32 outCountArg = inCount;

            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;

            // A digit is digitBits wide, so its Barrett chain needs only this many
            // words even though the composed value needs all W. In the centred path
            // a negative digit becomes 2^digitBits - digit, and a digit is only
            // negative when it is at least 2^(digitBits-1), so the complement is at
            // most 2^(digitBits-1) and fits in the same words.
            const u32 digitWords = (digitBits + 63u) >> 6;

            for (u32 o = blockIdx.y; o < outCountArg; o += gridDim.y)
            {
                const u32 ii = inIdx ? inIdx[o] : o;

                u64 value[w];
                if (garner)
                {
                    garnerCompose(
                        in + static_cast<size_t>(ii) * perPoly + coeff,
                        n,
                        rg.mMods,
                        rg.mGarnerInv,
                        value);
                }
                else
                {
                    crtCompose(
                        in + static_cast<size_t>(ii) * perPoly + coeff,
                        n,
                        rg.mMods,
                        rg.mInvPuncturedProd,
                        rg.mPuncturedProd,
                        rg.mBaseProd,
                        value);
                }

                if (!centered)
                {
                    // Mirrors gadgetDecomposeBitsRange.
                    mpShiftRight(value, startLevel * digitBits);
                    u64 digit[w];
                    for (u32 level = 0; level < levels; ++level)
                    {
                        mpCopy(value, digit);
                        mpMaskLowBits(digit, digitBits);
                        const u32 slot = o * levels + level;
                        const u32 oi = outIdx ? outIdx[slot] : slot;
                        u64* dst = out + static_cast<size_t>(oi) * perPoly + coeff;
#pragma unroll
                        for (u32 m = 0; m < w; ++m)
                        {
                            dst[static_cast<size_t>(m) * n] =
                                mpModuloBounded(digit, rg.mMods[m], digitWords);
                        }
                        mpShiftRight(value, digitBits);
                    }
                }
                else
                {
                    // Mirrors centeredDecomposeSlow.
                    if (mpGreaterG(value, rg.mBaseProdHalf))
                    {
                        mpSubG(value, rg.mBaseProd, value);
                    }

                    u64 digit[w];
                    u64 digitAbs[w];
                    const u32 lastLevel = startLevel + levels;
                    for (u32 level = 0; level < lastLevel; ++level)
                    {
                        mpCopy(value, digit);
                        mpMaskLowBits(digit, digitBits);
                        mpShiftRightArith(value, digitBits);

                        // digit >= 2^(digitBits-1) ?
                        bool digitIsNegative;
                        {
                            const u32 hb = digitBits - 1u;
                            const u32 hw = hb >> 6;
                            const u32 hbit = hb & 63u;
                            // halfBase is a power of two, so the comparison is a
                            // bit test plus a check for higher set words. Both the
                            // scan bound and the tested word index come from
                            // digitBits, so the scan is unrolled over every word and
                            // predicated rather than indexed - the early break is
                            // dropped because the result is just an OR.
                            bool higher = false;
#pragma unroll
                            for (u32 m = 0; m < w; ++m)
                            {
                                if (m > hw && digit[m] != 0) higher = true;
                            }
                            digitIsNegative = higher || (hw < w && (mpPick(digit, hw) >> hbit) != 0);
                        }

                        if (digitIsNegative)
                        {
                            // digitAbs = 2^digitBits - digit. The set word index is
                            // a runtime value, so it goes in as a select.
                            u64 base[w];
                            const u32 bw = digitBits >> 6;
                            const u64 bit = u64(1) << (digitBits & 63u);
#pragma unroll
                            for (u32 k = 0; k < w; ++k) base[k] = (k == bw) ? bit : u64(0);
                            mpSub(base, digit, digitAbs);
                            // value += 1
                            u64 one[w];
                            mpSetZero(one);
                            one[0] = 1;
                            mpAdd(value, one, value);
                        }
                        else
                        {
                            mpCopy(digit, digitAbs);
                        }

                        if (level < startLevel) continue;

                        const u32 slot = o * levels + (level - startLevel);
                        const u32 oi = outIdx ? outIdx[slot] : slot;
                        u64* dst = out + static_cast<size_t>(oi) * perPoly + coeff;
#pragma unroll
                        for (u32 m = 0; m < w; ++m)
                        {
                            const u64 reduced = mpModuloBounded(digitAbs, rg.mMods[m], digitWords);
                            dst[static_cast<size_t>(m) * n] =
                                (digitIsNegative && reduced != 0) ? (rg.mMods[m].mValue - reduced) : reduced;
                        }
                    }
                }
            }
        }

        // Fixed centred high digit for NoGoldenSeed: rho=8, base=2^208,
        // startLevel=1, levels=1. After centering, the discarded low digit only
        // contributes its balanced carry. The requested digit is therefore bits
        // 208..415 plus that carry, reduced modulo 2^208. This avoids two general
        // multi-precision shifts and all runtime digit/level predicates. Garner
        // composition is exact and measured slightly faster for this rho=8 base.
        __device__ __forceinline__ u64 pseudo52FoldDigitCarry(u64 acc, u64 digit, u32 c, u64 q)
        {
            // Dispatch bounds acc,digit<2^52 and c<2^24, so acc*c+digit
            // is below 2^76. Since 2^52 == c (mod q), the first fold is
            // below 2q and one subtraction returns the canonical residue.
            const Wide value = wideAddCarry(wideMul(acc, static_cast<u64>(c)), Wide{digit, 0u});
            const u64 low = value.mLo & ((u64{1} << 52u) - 1u);
            const u32 high = static_cast<u32>((value.mLo >> 52u) | (value.mHi << 12u));
            u64 folded = low + static_cast<u64>(high) * c;
            if (folded >= q) folded -= q;
            return folded;
        }

        template<bool CachedConstants>
        __device__ __forceinline__ void garnerComposeRho8Fp52(
            const u64* residues, const GpuModulus* mods, const ShoupOperand* garnerInv,
            u64 (&out)[8], const double* cachedQ = nullptr,
            const double* cachedInvQ = nullptr, const double* cachedRoots = nullptr)
        {
            // All moduli lie strictly between 2^51 and 2^52. A digit from
            // any earlier modulus is therefore below twice the current one.
            u64 v[8];
            if constexpr (CachedConstants)
            {
                // Preserve earlier mixed-radix digits as exact doubles. The
                // row order limits liveness while avoiding repeated integer
                // conversions in each subsequent modular subtraction.
                double vd[8];
#pragma unroll
                for (u32 i = 0u; i < 8u; ++i)
                {
                    const GpuModulus mod = mods[i];
                    const u64 raw = residues[static_cast<size_t>(i) * 16384u];
                    double td = static_cast<double>(raw < mod.mValue ? raw : barrettReduce64(raw, mod));
                    const double q = cachedQ[i];
#pragma unroll
                    for (u32 j = 0u; j < i; ++j)
                    {
                        double vj = vd[j];
                        if (vj >= q) vj = __dsub_rn(vj, q);
                        td = mulModFp52(__dsub_rn(td, vj), cachedRoots[i * 8u + j], q, cachedInvQ[i]);
                    }
                    vd[i] = td;
                }
#pragma unroll
                for (u32 i = 0u; i < 8u; ++i) v[i] = static_cast<u64>(vd[i]);
            }
            else
            {
#pragma unroll
                for (u32 i = 0u; i < 8u; ++i)
                {
                    const GpuModulus mod = mods[i];
                    u64 t = barrettReduce64(residues[static_cast<size_t>(i) * 16384u], mod);
                    const double q = static_cast<double>(mod.mValue);
                    const double invQ = __drcp_rn(q);
                    double td = static_cast<double>(t);
#pragma unroll
                    for (u32 j = 0u; j < i; ++j)
                    {
                        u64 vj = v[j];
                        if (vj >= mod.mValue) vj -= mod.mValue;
                        td = mulModFp52(__dsub_rn(td, static_cast<double>(vj)),
                            static_cast<double>(garnerInv[i * 8u + j].mOperand), q, invQ);
                    }
                    t = static_cast<u64>(td);
                    v[i] = t;
                }
            }
            mpSetZero(out);
            out[0] = v[7];
#pragma unroll
            for (u32 i = 7u; i-- > 0u;)
            {
                // At this step the result is below 2^(52*(8-i)). Fold
                // the next digit into the multiply's low-word carry,
                // eliminating a separate eight-word addition chain.
                u64 carry = v[i];
#pragma unroll
                for (u32 k = 0u; k < 8u; ++k)
                {
                    if (k < (52u * (8u - i) + 63u) / 64u)
                    {
                        const Wide word = wideAddCarry(wideMul(out[k], mods[i].mValue), Wide{carry, 0u});
                        out[k] = word.mLo;
                        carry = word.mHi;
                    }
                    else out[k] = 0u;
                }
            }
        }

        template<bool Pseudo52, bool CachedConstants = false>
        __device__ __forceinline__ void gadgetDecomposeHi208Rho8H200Body(
            DeviceRing rg,
            const u64* in,
            const u32* inIdx,
            u32 inCount,
            u64* out,
            const u32* outIdx,
            const double* persistentConstants = nullptr)
        {
            constexpr u32 n = 16384u;
            constexpr u32 w = 8u;
            constexpr size_t perPoly = static_cast<size_t>(w) * n;
            const double* cachedQ = nullptr;
            const double* cachedInvQ = nullptr;
            const double* cachedRoots = nullptr;
            if constexpr (CachedConstants)
            {
                cachedQ = persistentConstants;
                cachedInvQ = persistentConstants + 8u;
                cachedRoots = persistentConstants + 16u;
            }
            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;

            for (u32 o = blockIdx.y; o < inCount; o += gridDim.y)
            {
                const u32 ii = inIdx ? inIdx[o] : o;
                u64 value[w];
                if constexpr (Pseudo52)
                    garnerComposeRho8Fp52<CachedConstants>(
                        in + static_cast<size_t>(ii) * perPoly + coeff, rg.mMods, rg.mGarnerInv,
                        value, cachedQ, cachedInvQ, cachedRoots);
                else
                    garnerCompose(
                        in + static_cast<size_t>(ii) * perPoly + coeff,
                        n, rg.mMods, rg.mGarnerInv, value);
                if (mpGreaterG(value, rg.mBaseProdHalf))
                    mpSubG(value, rg.mBaseProd, value);

                // Arithmetic shift by 208, retaining its low 208 bits. These
                // bits come only from value[3..6]; sign extension begins above
                // the retained range.
                u64 digit[4];
                digit[0] = (value[3] >> 16u) | (value[4] << 48u);
                digit[1] = (value[4] >> 16u) | (value[5] << 48u);
                digit[2] = (value[5] >> 16u) | (value[6] << 48u);
                digit[3] = (value[6] >> 16u) & 0xFFFFu;

                // centeredDecomposeSlow adds one to the shifted value iff the
                // discarded level-zero digit has bit 207 set.
                unsigned char carry =
                    static_cast<unsigned char>((value[3] >> 15u) & 1u);
#pragma unroll
                for (u32 i = 0u; i < 4u; ++i)
                {
                    if (carry != 0u)
                    {
                        u64 next;
                        carry = addU64(digit[i], 1u, &next);
                        digit[i] = next;
                    }
                }
                digit[3] &= 0xFFFFu;

                const bool negative = (digit[3] & 0x8000u) != 0u;
                u64 magnitude[4];
                if (negative)
                {
                    // Two's complement inside exactly 208 bits is
                    // 2^208-digit, the accepted balanced magnitude.
                    unsigned char add = 1u;
#pragma unroll
                    for (u32 i = 0u; i < 4u; ++i)
                    {
                        const u64 inv = ~digit[i];
                        u64 next;
                        add = addU64(inv, static_cast<u64>(add), &next);
                        magnitude[i] = next;
                    }
                    magnitude[3] &= 0xFFFFu;
                }
                else
                {
#pragma unroll
                    for (u32 i = 0u; i < 4u; ++i)
                        magnitude[i] = digit[i];
                }

                const u32 oi = outIdx ? outIdx[o] : o;
                u64* dst =
                    out + static_cast<size_t>(oi) * perPoly + coeff;
#pragma unroll
                for (u32 m = 0u; m < w; ++m)
                {
                    const GpuModulus mod = rg.mMods[m];
                    u64 reduced;
                    if constexpr (Pseudo52)
                    {
                        constexpr u64 kMask52 =
                            (u64{ 1 } << 52u) - 1u;
                        const u32 c = static_cast<u32>(
                            (u64{ 1 } << 52u) - mod.mValue);
                        const u64 d0 = magnitude[0] & kMask52;
                        const u64 d1 =
                            ((magnitude[0] >> 52u) |
                             (magnitude[1] << 12u)) & kMask52;
                        const u64 d2 =
                            ((magnitude[1] >> 40u) |
                             (magnitude[2] << 24u)) & kMask52;
                        const u64 d3 =
                            ((magnitude[2] >> 28u) |
                             (magnitude[3] << 36u)) & kMask52;
                        reduced = pseudo52FoldDigitCarry(d3, d2, c, mod.mValue);
                        reduced = pseudo52FoldDigitCarry(reduced, d1, c, mod.mValue);
                        reduced = pseudo52FoldDigitCarry(reduced, d0, c, mod.mValue);
                    }
                    else
                    {
                        reduced = mpModulo(magnitude, mod);
                    }
                    dst[static_cast<size_t>(m) * n] =
                        negative && reduced != 0u
                            ? mod.mValue - reduced
                            : reduced;
                }
            }
        }

        template<bool Pseudo52, bool CachedConstants = false>
        __global__ __launch_bounds__(128)
        void gadgetDecomposeHi208Rho8H200Kernel(DeviceRing rg, const u64* in,
            const u32* inIdx, u32 inCount, u64* out, const u32* outIdx)
        {
            gadgetDecomposeHi208Rho8H200Body<Pseudo52, CachedConstants>(rg, in, inIdx, inCount, out, outIdx);
        }

        __global__ void prepareH200Fp52GadgetConstantsKernel(DeviceRing rg, double* out)
        {
            const u32 t = threadIdx.x;
            if (t < 8u)
            {
                const double q = static_cast<double>(rg.mMods[t].mValue);
                out[t] = q;
                out[8u + t] = __drcp_rn(q);
            }
            if (t < 64u)
            {
                const double root = static_cast<double>(rg.mGarnerInv[t].mOperand);
                out[16u + t] = root;
            }
        }

        __global__ __launch_bounds__(128)
        void gadgetDecomposeHi208Rho8ConstantsKernel(DeviceRing rg, const u64* in,
            const u32* inIdx, u32 inCount, u64* out, const u32* outIdx, const double* constants)
        {
            gadgetDecomposeHi208Rho8H200Body<true, true>(
                rg, in, inIdx, inCount, out, outIdx, constants);
        }

        // ---- CRT limb helpers --------------------------------------------

        __global__ void seedLabelRepKernel(
            RingDeviceConstView rc, const u64* input, u64* output, u32 tau,
            u32 count, bool gammaOne)
        {
            const u64 words = static_cast<u64>(rc.mRho) * rc.mN;
            const u64 total = words * count;
            for (u64 index = static_cast<u64>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < total; index += static_cast<u64>(gridDim.x) * blockDim.x)
            {
                const u64 poly = index / words;
                const u64 word = index % words;
                const u32 limb = static_cast<u32>(word / rc.mN);
                const u32 digit = gammaOne ? 0u : static_cast<u32>((poly / rc.mRho) % tau);
                output[index] = gammaOne || limb == poly % rc.mRho
                    ? input[static_cast<u64>(digit) * words + word] : 0u;
            }
        }

        __global__ void selectScaleLimbKernel(
            DeviceRing rg,
            const u64* aBase,
            const u32* aIdx,
            const u32* limbSel,
            const u64* scalePerLimb,
            u64* out,
            const u32* outIdx,
            u32 outCount)
        {
            const u32 n = rg.mN;
            const size_t perPoly = static_cast<size_t>(rg.mRho) * n;
            const u32 outCountArg = outCount;
            const u32 perPolyU = static_cast<u32>(perPoly);
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            if (elem >= perPolyU) return;
            // N is a power of two, so the limb/coefficient split is a shift and
            // a mask; an actual 64-bit division here costs ~70 instructions.
            const u32 limb = elem >> rg.mLogN;
            const u32 coeff = elem & (n - 1u);
            for (u32 o = blockIdx.y; o < outCountArg; o += gridDim.y)
            {
                const size_t limbOff = static_cast<size_t>(limb) * n + coeff;
                const u32 oi = outIdx ? outIdx[o] : o;
                u64* dst = out + static_cast<size_t>(oi) * perPoly + limbOff;

                const u32 sel = limbSel[o];
                if (limb != sel)
                {
                    *dst = 0;
                    continue;
                }
                const u32 ai = aIdx ? aIdx[o] : o;
                const u64 av = aBase[static_cast<size_t>(ai) * perPoly + limbOff];
                *dst = mulMod(av, scalePerLimb[sel], rg.mMods[limb]);
            }
        }

        __global__ void liftCenteredLimbKernel(
            DeviceRing rg,
            const u64* aBase,
            const u32* aIdx,
            const u32* limbSel,
            const u64* invScalePerLimb,
            u64* out,
            const u32* outIdx,
            u32 outCount)
        {
            const u32 n = rg.mN;
            const size_t perPoly = static_cast<size_t>(rg.mRho) * n;
            const u32 outCountArg = outCount;
            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;
            for (u32 o = blockIdx.y; o < outCountArg; o += gridDim.y)
            {
                const u32 sel = limbSel[o];
                const u32 ai = aIdx ? aIdx[o] : o;
                const GpuModulus modSel = rg.mMods[sel];

                const u64 av =
                    aBase[static_cast<size_t>(ai) * perPoly + static_cast<size_t>(sel) * n + coeff];
                const u64 reduced = mulMod(av, invScalePerLimb[sel], modSel);
                const bool negative = reduced > (modSel.mValue >> 1);
                const u64 magnitude = negative ? (modSel.mValue - reduced) : reduced;

                const u32 oi = outIdx ? outIdx[o] : o;
                u64* dst = out + static_cast<size_t>(oi) * perPoly + coeff;
                for (u32 m = 0; m < rg.mRho; ++m)
                {
                    const u64 qm = rg.mMods[m].mValue;
                    dst[static_cast<size_t>(m) * n] = negative ? (qm - magnitude) : magnitude;
                }
            }
        }

        __global__ void expandCenteredCompactKernel(
            DeviceRing rg, const u64* compactQ0, u64* out, u32 outCount)
        {
            const u32 coefficient = blockIdx.x * blockDim.x + threadIdx.x;
            if (coefficient >= rg.mN) return;
            const auto q0 = rg.mMods[0];
            const size_t polynomialWords = static_cast<size_t>(rg.mRho) * rg.mN;
            for (u32 row = blockIdx.y; row < outCount; row += gridDim.y)
            {
                const u64 reduced = mulMod(
                    compactQ0[static_cast<size_t>(row) * rg.mN + coefficient], 1, q0);
                const bool negative = reduced > (q0.mValue >> 1);
                const u64 magnitude = negative ? q0.mValue - reduced : reduced;
                u64* destination = out + static_cast<size_t>(row) * polynomialWords + coefficient;
                for (u32 limb = 0; limb < rg.mRho; ++limb)
                    destination[static_cast<size_t>(limb) * rg.mN] =
                        negative ? rg.mMods[limb].mValue - magnitude : magnitude;
            }
        }

        __global__ void prepareDeltaSlotsKernel(u64 delta0, u64 delta1, u64 delta2,
            u32 slotCount, bool garbled, u64* out)
        {
            const u32 slot = blockIdx.x * blockDim.x + threadIdx.x;
            if (slot >= slotCount) return;
            if (!garbled) { out[slot] = delta0; return; }
            if (slot >= (slotCount / 3u) * 3u) { out[slot] = 0; return; }
            const u32 component = slot % 3u;
            out[slot] = component == 0 ? delta0 : component == 1 ? delta1 : delta2;
        }

        __global__ void prepareConstantDeltaKernel(DeviceRing rg, u64 delta,
            const u64* liftModQ, u64* out)
        {
            const u32 coefficient = blockIdx.x * blockDim.x + threadIdx.x;
            if (coefficient >= rg.mN) return;
            for (u32 limb = 0; limb < rg.mRho; ++limb)
                out[static_cast<size_t>(limb) * rg.mN + coefficient] = coefficient == 0
                    ? mulMod(delta, liftModQ[limb], rg.mMods[limb]) : 0;
        }

        // Mirrors recursiveLeafPairInnerProductNttToStd: the two operands each
        // contribute to a single RNS limb. leftB/rightB are already scaled by
        // prod_{w != limb} q_w mod q_limb in the offline cache. Every other limb
        // of the accumulator stays zero.
        __global__ void leafPairScaledKernel(
            DeviceRing rg,
            const u64* leftB,       // one polynomial
            const u64* rightB,      // one polynomial
            const u64* digits,      // node digit buffer
            const u32* leftIdx,     // [outCount] index into digits
            const u32* rightIdx,    // [outCount]
            const u32* leftLimb,    // [outCount]
            const u32* rightLimb,   // [outCount]
            u64* out,
            const u32* outIdx,
            u32 outCount)
        {
            const u32 n = rg.mN;
            const size_t perPoly = static_cast<size_t>(rg.mRho) * n;
            const u32 perPolyU = static_cast<u32>(perPoly);
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            if (elem >= perPolyU) return;
            const u32 limb = elem >> rg.mLogN;
            const size_t rem = static_cast<size_t>(elem);
            const GpuModulus mod = rg.mMods[limb];
            for (u32 o = blockIdx.y; o < outCount; o += gridDim.y)
            {
                u64 acc = 0;
                if (limb == leftLimb[o])
                {
                    const u64 d = digits[static_cast<size_t>(leftIdx[o]) * perPoly + rem];
                    acc = addMod(acc, mulMod(leftB[rem], d, mod), mod.mValue);
                }
                if (limb == rightLimb[o])
                {
                    const u64 d = digits[static_cast<size_t>(rightIdx[o]) * perPoly + rem];
                    acc = addMod(acc, mulMod(rightB[rem], d, mod), mod.mValue);
                }

                const u32 oi = outIdx ? outIdx[o] : o;
                out[static_cast<size_t>(oi) * perPoly + rem] = acc;
            }
        }

        // In the compact recursive representation, logical leaf s selects limb
        // s%rho of physical high digit s/rho. After the centred out-of-place NTT,
        // that diagonal limb is both (a) exactly the producer's high digit in NTT
        // form and (b) the only limb this leaf contributes to its parent pair.
        // Read it once, cache (a), and form (b). The parent buffer is zeroed before
        // launch, and rho>1 makes the two siblings' selected limbs distinct.
        __global__ void recursiveLeafDiagonalKernel(
            DeviceRing rg,
            const u64* nodes,
            const u32* nodeIdx,
            const u32* parentAndSide,
            const u64* leftB,
            const u64* rightB,
            u64* packed,
            u64* parent,
            u32 logicalCount)
        {
            const u32 n = rg.mN;
            const size_t perPoly = static_cast<size_t>(rg.mRho) * n;
            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;

            for (u32 logical = blockIdx.y; logical < logicalCount; logical += gridDim.y)
            {
                const u32 limb = logical % rg.mRho;
                const u32 physical = logical / rg.mRho;
                const size_t rem = static_cast<size_t>(limb) * n + coeff;
                const u64 digit =
                    nodes[static_cast<size_t>(nodeIdx[logical]) * perPoly + rem];
                packed[static_cast<size_t>(physical) * perPoly + rem] = digit;

                const u32 encoded = parentAndSide[logical];
                const u32 parentPoly = encoded & 0x7fffffffu;
                const u64* b = (encoded >> 31u) ? rightB : leftB;
                const GpuModulus mod = rg.mMods[limb];
                parent[static_cast<size_t>(parentPoly) * perPoly + rem] =
                    mulMod(b[rem], digit, mod);
            }
        }

        // Fixed full-chunk rho4 twin. Siblings in each parent select either
        // limbs (0,1) or (2,3). A sibling at limb l therefore owns exactly one
        // missing destination at l XOR 2; together the pair writes all four
        // limbs without races and without pre-zeroing the parent allocation.
        __global__ __launch_bounds__(256, 8)
        void recursiveLeafDiagonalRho4SelfZeroKernel(
            DeviceRing rg,
            const u64* nodes,
            const u32* nodeIdx,
            const u32* parentAndSide,
            const u64* leftB,
            const u64* rightB,
            u64* packed,
            u64* parent,
            u32 logicalCount)
        {
            constexpr u32 n = 8192u;
            constexpr size_t perPoly = 4u * n;
            constexpr size_t oppositePairBit = 2u * n;
            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;

            for (u32 logical = blockIdx.y; logical < logicalCount;
                 logical += gridDim.y)
            {
                const u32 limb = logical & 3u;
                const u32 physical = logical >> 2u;
                const size_t rem = static_cast<size_t>(limb) * n + coeff;
                const u64 digit =
                    nodes[static_cast<size_t>(nodeIdx[logical]) * perPoly + rem];
                packed[static_cast<size_t>(physical) * perPoly + rem] = digit;

                const u32 encoded = parentAndSide[logical];
                const u32 parentPoly = encoded & 0x7fffffffu;
                const u64* b = (encoded >> 31u) ? rightB : leftB;
                const GpuModulus mod = rg.mMods[limb];
                u64* const dst =
                    parent + static_cast<size_t>(parentPoly) * perPoly;
                dst[rem] = mulMod(b[rem], digit, mod);
                dst[rem ^ oppositePairBit] = 0u;
            }
        }

        // ---- denoise comb -------------------------------------------------

        struct DeviceDenoise
        {
            const u64* mQ;
            const GpuModulus* mMods;
            const u32* mSrcLimb;
            const u64* mCrtInvPunctured;
            const u64* mPuncturedProdModTarget;
            const ShoupOperand* mCrtInvPuncturedShoup;
            const ShoupOperand* mScaledPuncturedShoup;
            const u64* mFracInvLo;
            const u64* mFracInvHi;
            const u64* mCrtLiftModTarget;
            const u64* mInvCrtLiftModTarget;
            const ShoupOperand* mInvCrtLiftShoup;
        };

        template<bool ValidateGolden>
        __global__ void denoiseCombKernel(
            DeviceRing rg,
            DeviceDenoise dn,
            const u64* in,
            u64* out,
            u32 outCount,
            const u64* marginLo,
            const u64* marginHi,
            u32* failFlag)
        {
            const u32 n = rg.mN;
            const u32 rho = rg.mRho;
            const u32 reducedCount = rho - 1u;
            const size_t perPoly = static_cast<size_t>(rho) * n;
            const u32 outCountArg = outCount;

            const u32 perPolyU = static_cast<u32>(perPoly);
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            if (elem >= perPolyU) return;
            const u32 j = elem >> rg.mLogN;             // target limb
            const u32 k = elem & (n - 1u);
            for (u32 o = blockIdx.y; o < outCountArg; o += gridDim.y)
            {

                const u64* polyIn = in + (static_cast<size_t>(o) * rho + j) * perPoly;
                const u64 qj = dn.mQ[j];
                const GpuModulus modJ = dn.mMods[j];

                // sumFrac starts at 2^127 (the rounding term).
                u64 fracLo = 0;
                u64 fracHi = u64(1) << 63;
                u64 alpha = 0;
                u64 eModQj = 0;

                for (u32 idx = 0; idx < reducedCount; ++idx)
                {
                    const size_t ci = static_cast<size_t>(j) * reducedCount + idx;
                    const u32 wl = dn.mSrcLimb[ci];
                    const u64 vw = polyIn[static_cast<size_t>(wl) * n + k];
                    const u64 xw = mulMod(vw, dn.mCrtInvPunctured[ci], dn.mMods[wl]);

                    // wideU64MulLow(xw, fracInv): low 128 bits of xw * fracInv.
                    const u64 fLo = dn.mFracInvLo[ci];
                    const u64 fHi = dn.mFracInvHi[ci];
                    const u64 pLo = xw * fLo;
                    const u64 pHi = mulHi64(xw, fLo) + xw * fHi;

                    u64 nLo;
                    const unsigned char c0 = addU64(fracLo, pLo, &nLo);
                    u64 nHi;
                    const unsigned char c1 = addU64(fracHi, pHi, &nHi);
                    u64 nHi2;
                    const unsigned char c2 = addU64(nHi, static_cast<u64>(c0), &nHi2);
                    fracLo = nLo;
                    fracHi = nHi2;
                    if (c1 | c2) ++alpha;

                    const u64 xwModQj = barrettReduce64(xw, modJ);
                    const u64 proj = mulMod(xwModQj, dn.mPuncturedProdModTarget[ci], modJ);
                    eModQj += proj;
                    if (eModQj >= qj) eModQj -= qj;
                }

                if constexpr (ValidateGolden)
                {
                    // For p=o*rho+j and mu%rho==0, validation's target
                    // ((p%mu)%rho) is exactly j. fracLo/fracHi is the same
                    // wrapped sum that validateGoldenSeedKernel reconstructs;
                    // alpha only retains its discarded carry for denoising.
                    const Wide sumFrac{ fracLo, fracHi };
                    const Wide distanceToTop = wideSub(Wide{ 0, 0 }, sumFrac);
                    const Wide margin{ marginLo[j], marginHi[j] };
                    const bool lowFail =
                        (sumFrac.mHi < margin.mHi) ||
                        (sumFrac.mHi == margin.mHi && sumFrac.mLo < margin.mLo);
                    const bool highFail =
                        (distanceToTop.mHi < margin.mHi) ||
                        (distanceToTop.mHi == margin.mHi && distanceToTop.mLo < margin.mLo);
                    if (lowFail || highFail)
                    {
                        // Do not return: even a rejected attempt must finish the
                        // denoise chain so all later kernels have defined inputs.
                        atomicExch(failFlag, 1u);
                    }
                }

                const u64 alphaTerm = mulMod(alpha, dn.mCrtLiftModTarget[j], modJ);
                if (eModQj >= alphaTerm) eModQj -= alphaTerm;
                else eModQj += qj - alphaTerm;

                const u64 vj = polyIn[static_cast<size_t>(j) * n + k];
                const u64 diff = (vj >= eModQj) ? (vj - eModQj) : (vj + qj - eModQj);
                out[static_cast<size_t>(o) * perPoly + static_cast<size_t>(j) * n + k] =
                    mulMod(diff, dn.mInvCrtLiftModTarget[j], modJ);
            }
        }

        template<u32 Rho, u32 TargetLimb, u32 Idx>
        __device__ __forceinline__ void denoiseCombSpecializedTerms(
            DeviceDenoise dn,
            const u64* polyIn,
            u32 n,
            u32 k,
            const GpuModulus& modJ,
            u64 qj,
            u64& fracLo,
            u64& fracHi,
            u64& alpha,
            u64& eModQj)
        {
            static_assert(Rho == 4u || Rho == 8u);
            static_assert(TargetLimb < Rho);
            static_assert(Idx < Rho - 1u);
            constexpr u32 reducedCount = Rho - 1u;
            constexpr u32 wl = Idx + (Idx >= TargetLimb ? 1u : 0u);
            constexpr size_t ci = static_cast<size_t>(TargetLimb) * reducedCount + Idx;

            const u64 vw = polyIn[static_cast<size_t>(wl) * n + k];
            const u64 xw = mulMod(vw, dn.mCrtInvPunctured[ci], dn.mMods[wl]);

            const u64 fLo = dn.mFracInvLo[ci];
            const u64 fHi = dn.mFracInvHi[ci];
            const u64 pLo = xw * fLo;
            const u64 pHi = mulHi64(xw, fLo) + xw * fHi;

            u64 nLo;
            const unsigned char c0 = addU64(fracLo, pLo, &nLo);
            u64 nHi;
            const unsigned char c1 = addU64(fracHi, pHi, &nHi);
            u64 nHi2;
            const unsigned char c2 = addU64(nHi, static_cast<u64>(c0), &nHi2);
            fracLo = nLo;
            fracHi = nHi2;
            if (c1 | c2) ++alpha;

            const u64 xwModQj = barrettReduce64(xw, modJ);
            const u64 proj = mulMod(xwModQj, dn.mPuncturedProdModTarget[ci], modJ);
            eModQj += proj;
            if (eModQj >= qj) eModQj -= qj;

            if constexpr (Idx + 1u < reducedCount)
            {
                denoiseCombSpecializedTerms<Rho, TargetLimb, Idx + 1u>(
                    dn, polyIn, n, k, modJ, qj, fracLo, fracHi, alpha, eModQj);
            }
        }

        template<u32 Rho, u32 TargetLimb, bool ValidateGolden>
        __device__ __forceinline__ void denoiseCombSpecializedTarget(
            DeviceDenoise dn,
            const u64* in,
            u64* out,
            u32 n,
            u32 k,
            u32 outCount,
            const u64* marginLo,
            const u64* marginHi,
            u32* failFlag)
        {
            const size_t perPoly = static_cast<size_t>(Rho) * n;
            const u64 qj = dn.mQ[TargetLimb];
            const GpuModulus modJ = dn.mMods[TargetLimb];

            for (u32 o = blockIdx.y; o < outCount; o += gridDim.y)
            {
                const u64* polyIn =
                    in + (static_cast<size_t>(o) * Rho + TargetLimb) * perPoly;
                u64 fracLo = 0;
                u64 fracHi = u64(1) << 63;
                u64 alpha = 0;
                u64 eModQj = 0;

                denoiseCombSpecializedTerms<Rho, TargetLimb, 0u>(
                    dn, polyIn, n, k, modJ, qj, fracLo, fracHi, alpha, eModQj);

                if constexpr (ValidateGolden)
                {
                    const Wide sumFrac{ fracLo, fracHi };
                    const Wide distanceToTop = wideSub(Wide{ 0, 0 }, sumFrac);
                    const Wide margin{ marginLo[TargetLimb], marginHi[TargetLimb] };
                    const bool lowFail =
                        (sumFrac.mHi < margin.mHi) ||
                        (sumFrac.mHi == margin.mHi && sumFrac.mLo < margin.mLo);
                    const bool highFail =
                        (distanceToTop.mHi < margin.mHi) ||
                        (distanceToTop.mHi == margin.mHi && distanceToTop.mLo < margin.mLo);
                    if (lowFail || highFail) atomicExch(failFlag, 1u);
                }

                const u64 alphaTerm =
                    mulMod(alpha, dn.mCrtLiftModTarget[TargetLimb], modJ);
                if (eModQj >= alphaTerm) eModQj -= alphaTerm;
                else eModQj += qj - alphaTerm;

                const u64 vj = polyIn[static_cast<size_t>(TargetLimb) * n + k];
                const u64 diff =
                    (vj >= eModQj) ? (vj - eModQj) : (vj + qj - eModQj);
                out[static_cast<size_t>(o) * perPoly +
                    static_cast<size_t>(TargetLimb) * n + k] =
                    mulMod(diff, dn.mInvCrtLiftModTarget[TargetLimb], modJ);
            }
        }

        template<bool ValidateGolden>
        __global__ void denoiseCombSpecializedKernel(
            DeviceRing rg,
            DeviceDenoise dn,
            const u64* in,
            u64* out,
            u32 outCount,
            const u64* marginLo,
            const u64* marginHi,
            u32* failFlag)
        {
            constexpr u32 Rho = 4u;
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            if (elem >= Rho * rg.mN) return;
            const u32 targetLimb = elem >> rg.mLogN;
            const u32 k = elem & (rg.mN - 1u);

            switch (targetLimb)
            {
            case 0u: denoiseCombSpecializedTarget<Rho, 0u, ValidateGolden>(dn, in, out, rg.mN, k, outCount, marginLo, marginHi, failFlag); break;
            case 1u: denoiseCombSpecializedTarget<Rho, 1u, ValidateGolden>(dn, in, out, rg.mN, k, outCount, marginLo, marginHi, failFlag); break;
            case 2u: denoiseCombSpecializedTarget<Rho, 2u, ValidateGolden>(dn, in, out, rg.mN, k, outCount, marginLo, marginHi, failFlag); break;
            case 3u: denoiseCombSpecializedTarget<Rho, 3u, ValidateGolden>(dn, in, out, rg.mN, k, outCount, marginLo, marginHi, failFlag); break;

            }
        }

        // Generalize the accepted GoldenSeed Shoup algebra, not its four-limb
        // constants. The GPU ring already owns exact per-target Shoup tables
        // for all eight limbs. Fractional carries retain the original order.
        __device__ __forceinline__ void denoiseNoGoldShoupTerm(
            DeviceDenoise dn, const u64* polyIn, u32 k, u32 target, u32 idx,
            u64 qj, u64& fracLo, u64& fracHi, u64& alpha, u64& projected)
        {
            const u32 source = idx + static_cast<u32>(idx >= target);
            const u32 ci = target * 7u + idx;
            const u64 value = polyIn[static_cast<size_t>(source) * 16384u + k];
            const u64 xw = mulShoup(value, dn.mCrtInvPuncturedShoup[ci], dn.mQ[source]);
            const u64 fLo = dn.mFracInvLo[ci];
            const u64 pLo = xw * fLo;
            const u64 pHi = mulHi64(xw, fLo) + xw * dn.mFracInvHi[ci];
            u64 lo, hi, hiWithCarry;
            const unsigned char c0 = addU64(fracLo, pLo, &lo);
            const unsigned char c1 = addU64(fracHi, pHi, &hi);
            const unsigned char c2 = addU64(hi, static_cast<u64>(c0), &hiWithCarry);
            fracLo = lo;
            fracHi = hiWithCarry;
            alpha += static_cast<u64>(c1 | c2);
            // Preflight proves q_source < 2*q_target; xw is canonical.
            const u64 reduced = xw >= qj ? xw - qj : xw;
            projected = addMod(projected, mulShoup(reduced, dn.mScaledPuncturedShoup[ci], qj), qj);
        }

        __global__ __launch_bounds__(128) void denoiseNoGoldShoupKernel(
            DeviceDenoise dn, const u64* in, u64* out)
        {
            const u32 k = blockIdx.x * 128u + threadIdx.x;
            const u32 logical = blockIdx.y;
            const u32 target = logical & 7u;
            const u64 qj = dn.mQ[target];
            const u64* polyIn = in + (static_cast<size_t>(logical) << 17u);
            u64 fracLo = 0u, fracHi = u64(1) << 63u, alpha = 0u, projected = 0u;
#pragma unroll
            for (u32 idx = 0u; idx < 7u; ++idx)
                denoiseNoGoldShoupTerm(dn, polyIn, k, target, idx, qj,
                    fracLo, fracHi, alpha, projected);

            const u64 vj = polyIn[static_cast<size_t>(target) * 16384u + k];
            const u64 scaled = mulShoup(vj, dn.mInvCrtLiftShoup[target], qj);
            out[(static_cast<size_t>(logical) << 14u) + k] =
                addMod(subMod(scaled, projected, qj), alpha, qj);
        }

        void launchNoGoldDenoiseShoup(DeviceDenoise dn,
            const u64* in, u64* out, u32 outCount, cudaStream_t stream)
        {
            const dim3 grid(16384u / 128u, outCount * 8u, 1u);
            denoiseNoGoldShoupKernel<<<grid, 128u, 0u, stream>>>(dn, in, out);
        }

        constexpr u32 kDenoiseRho4N = 8192u;
        constexpr u32 kDenoiseRho4LogN = 13u;
        constexpr u32 kDenoiseRho4PerPoly = 4u * kDenoiseRho4N;

        // One fully fixed rho=4 source term. UseShoup=false deliberately mirrors
        // denoiseCombSpecializedTerms, providing an arithmetic-identical geometry
        // A/B without changing the existing specialized kernel.
        template<bool UseShoup, u32 TargetLimb, u32 Idx>
        __device__ __forceinline__ void denoiseCombRho4FixedTerm(
            DeviceDenoise dn,
            const u64* polyIn,
            u32 k,
            u64 qj,
            const GpuModulus& modJ,
            u64& fracLo,
            u64& fracHi,
            u64& alpha,
            u64& projected)
        {
            static_assert(TargetLimb < 4u);
            static_assert(Idx < 3u);
            constexpr u32 wl = Idx + (Idx >= TargetLimb ? 1u : 0u);
            constexpr size_t ci = static_cast<size_t>(TargetLimb) * 3u + Idx;

            const u64 vw = polyIn[static_cast<size_t>(wl) * kDenoiseRho4N + k];
            u64 xw;
            if constexpr (UseShoup)
            {
                xw = mulShoup(vw, dn.mCrtInvPuncturedShoup[ci], dn.mQ[wl]);
            }
            else
            {
                xw = mulMod(vw, dn.mCrtInvPunctured[ci], dn.mMods[wl]);
            }

            // Keep the exact host/legacy 128-bit product and addition order: the
            // wrapped fraction feeds GoldenSeed validation and its discarded
            // carry is alpha.
            const u64 fLo = dn.mFracInvLo[ci];
            const u64 fHi = dn.mFracInvHi[ci];
            const u64 pLo = xw * fLo;
            const u64 pHi = mulHi64(xw, fLo) + xw * fHi;

            u64 nLo;
            const unsigned char c0 = addU64(fracLo, pLo, &nLo);
            u64 nHi;
            const unsigned char c1 = addU64(fracHi, pHi, &nHi);
            u64 nHi2;
            const unsigned char c2 = addU64(nHi, static_cast<u64>(c0), &nHi2);
            fracLo = nLo;
            fracHi = nHi2;
            if (c1 | c2) ++alpha;

            u64 proj;
            if constexpr (UseShoup)
            {
                // The launcher proves max(q_w) < 2*min(q_j). Since xw<q_w,
                // one subtraction is the exact xw mod q_j. The stored constant
                // is P_{j,w} * inv(crtLift_j) mod q_j.
                const u64 xwModQj = (xw >= qj) ? (xw - qj) : xw;
                proj = mulShoup(xwModQj, dn.mScaledPuncturedShoup[ci], qj);
            }
            else
            {
                const u64 xwModQj = barrettReduce64(xw, modJ);
                proj = mulMod(xwModQj, dn.mPuncturedProdModTarget[ci], modJ);
            }
            projected = addMod(projected, proj, qj);
        }

        template<bool UseShoup, u32 TargetLimb, bool ValidateGolden>
        __device__ __forceinline__ void denoiseCombRho4FixedTarget(
            DeviceDenoise dn,
            const u64* in,
            u64* out,
            size_t logical,
            u32 k,
            const u64* marginLo,
            const u64* marginHi,
            u32* failFlag)
        {
            static_assert(TargetLimb < 4u);
            const u64 qj = dn.mQ[TargetLimb];
            const GpuModulus modJ = dn.mMods[TargetLimb];
            const u64* polyIn = in + (logical << 15u);

            u64 fracLo = 0;
            u64 fracHi = u64(1) << 63;
            u64 alpha = 0;
            u64 projected = 0;

            denoiseCombRho4FixedTerm<UseShoup, TargetLimb, 0u>(
                dn, polyIn, k, qj, modJ, fracLo, fracHi, alpha, projected);
            denoiseCombRho4FixedTerm<UseShoup, TargetLimb, 1u>(
                dn, polyIn, k, qj, modJ, fracLo, fracHi, alpha, projected);
            denoiseCombRho4FixedTerm<UseShoup, TargetLimb, 2u>(
                dn, polyIn, k, qj, modJ, fracLo, fracHi, alpha, projected);

            if constexpr (ValidateGolden)
            {
                const Wide sumFrac{ fracLo, fracHi };
                const Wide distanceToTop = wideSub(Wide{ 0, 0 }, sumFrac);
                const Wide margin{ marginLo[TargetLimb], marginHi[TargetLimb] };
                const bool lowFail =
                    (sumFrac.mHi < margin.mHi) ||
                    (sumFrac.mHi == margin.mHi && sumFrac.mLo < margin.mLo);
                const bool highFail =
                    (distanceToTop.mHi < margin.mHi) ||
                    (distanceToTop.mHi == margin.mHi && distanceToTop.mLo < margin.mLo);
                if (lowFail || highFail) atomicExch(failFlag, 1u);
            }

            const u64 vj = polyIn[static_cast<size_t>(TargetLimb) * kDenoiseRho4N + k];
            u64 result;
            if constexpr (UseShoup)
            {
                // Legacy computes
                //   (vj - sum(xw*P) + alpha*crtLift) * inv(crtLift).
                // Distribute the inverse into the pre-scaled P constants; the
                // alpha term becomes alpha exactly in Z_q.
                const u64 scaledVj =
                    mulShoup(vj, dn.mInvCrtLiftShoup[TargetLimb], qj);
                result = addMod(subMod(scaledVj, projected, qj), alpha, qj);
            }
            else
            {
                const u64 alphaTerm =
                    mulMod(alpha, dn.mCrtLiftModTarget[TargetLimb], modJ);
                if (projected >= alphaTerm) projected -= alphaTerm;
                else projected += qj - alphaTerm;
                const u64 diff =
                    (vj >= projected) ? (vj - projected) : (vj + qj - projected);
                result = mulMod(diff, dn.mInvCrtLiftModTarget[TargetLimb], modJ);
            }
            out[(logical << kDenoiseRho4LogN) + k] = result;
        }

        template<bool UseShoup, bool HotGeometry, bool ValidateGolden>
        __device__ __forceinline__ void denoiseCombRho4FixedDispatch(
            DeviceDenoise dn,
            const u64* in,
            u64* out,
            u32 targetLimb,
            size_t logical,
            u32 k,
            const u64* marginLo,
            const u64* marginHi,
            u32* failFlag)
        {
            switch (targetLimb)
            {
            case 0u:
                denoiseCombRho4FixedTarget<UseShoup, 0u, ValidateGolden>(
                    dn, in, out, logical, k, marginLo, marginHi, failFlag);
                break;
            case 1u:
                denoiseCombRho4FixedTarget<UseShoup, 1u, ValidateGolden>(
                    dn, in, out, logical, k, marginLo, marginHi, failFlag);
                break;
            case 2u:
                denoiseCombRho4FixedTarget<UseShoup, 2u, ValidateGolden>(
                    dn, in, out, logical, k, marginLo, marginHi, failFlag);
                break;
            case 3u:
                denoiseCombRho4FixedTarget<UseShoup, 3u, ValidateGolden>(
                    dn, in, out, logical, k, marginLo, marginHi, failFlag);
                break;
            }
        }

        // HotGeometry maps grid=(32,4*outCount) so logical=o*4+target is already
        // blockIdx.y. The non-hot form retains grid=(128,outCount), including its
        // large-count grid.y loop, while still allowing isolated Shoup A/B.
        template<bool UseShoup, bool HotGeometry, bool ValidateGolden>
        __global__ void denoiseCombRho4FixedKernel(
            DeviceDenoise dn,
            const u64* in,
            u64* out,
            u32 outCount,
            const u64* marginLo,
            const u64* marginHi,
            u32* failFlag)
        {
            if constexpr (HotGeometry)
            {
                const u32 k = (blockIdx.x << 8u) + threadIdx.x;
                const size_t logical = blockIdx.y;
                const u32 targetLimb = static_cast<u32>(logical) & 3u;
                denoiseCombRho4FixedDispatch<UseShoup, HotGeometry, ValidateGolden>(
                    dn, in, out, targetLimb, logical, k, marginLo, marginHi, failFlag);
            }
            else
            {
                const u32 elem = (blockIdx.x << 8u) + threadIdx.x;
                const u32 targetLimb = elem >> kDenoiseRho4LogN;
                const u32 k = elem & (kDenoiseRho4N - 1u);
                for (u32 o = blockIdx.y; o < outCount; o += gridDim.y)
                {
                    const size_t logical = (static_cast<size_t>(o) << 2u) + targetLimb;
                    denoiseCombRho4FixedDispatch<UseShoup, HotGeometry, ValidateGolden>(
                        dn, in, out, targetLimb, logical, k, marginLo, marginHi, failFlag);
                }
            }
        }

        template<u32 FixedRho>
        __global__ void validateLeafGoldenSeedKernel(
            u32 n, u32 dynamicRho, const LeafGoldenSeedLimb* constants,
            const u64* tbk, u32 polyCount, Wide margin, u32* failFlag)
        {
            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;
            const u32 rho = FixedRho ? FixedRho : dynamicRho;
            for (u32 polyIdx = blockIdx.y; polyIdx < polyCount; polyIdx += gridDim.y)
            {
                if (*failFlag) return;
                const u64* poly = tbk + static_cast<size_t>(polyIdx) * rho * n;
                Wide sum{0, u64(1) << 63};
                #pragma unroll
                for (u32 i = 0; i < rho; ++i)
                {
                    const auto c = constants[i];
                    const ShoupOperand inverse{c.mInverse.mOperand, c.mInverse.mQuotient};
                    const u64 y = mulShoup(poly[static_cast<size_t>(i) * n + coeff], inverse, c.mQ);
                    sum = wideAdd(sum, wideMulLow(y, Wide{c.mReciprocalLo, c.mReciprocalHi}));
                }
                const Wide negative = wideSub(Wide{0, 0}, sum);
                if (sum.mHi < margin.mHi || (sum.mHi == margin.mHi && sum.mLo < margin.mLo) ||
                    negative.mHi < margin.mHi || (negative.mHi == margin.mHi && negative.mLo < margin.mLo))
                {
                    atomicExch(failFlag, 1u);
                    return;
                }
            }
        }

        // Mirrors validateGoldenSeedCandidate: for every coefficient of every
        // sampled polynomial, reconstruct the fractional part of the CRT lift
        // and reject the seed if it sits within `margin` of a rounding boundary.
        // The 128-bit accumulation wraps, exactly as wideU64Add does with a null
        // carry-out on the host.
        __global__ void validateGoldenSeedKernel(
            DeviceRing rg,
            DeviceDenoise dn,
            const u64* tbk,
            u32 polyCount,
            u32 mu,
            const u64* marginLo,
            const u64* marginHi,
            u32* failFlag)
        {
            const u32 n = rg.mN;
            const u32 rho = rg.mRho;
            const u32 reducedCount = rho - 1u;
            const size_t perPoly = static_cast<size_t>(rho) * n;

            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;

            for (u32 o = blockIdx.y; o < polyCount; o += gridDim.y)
            {
                if (*failFlag) return;

                const u32 targetLimb = (o % mu) % rho;
                const u64* poly = tbk + static_cast<size_t>(o) * perPoly;

                Wide sumFrac{ 0, u64(1) << 63 };
                for (u32 idx = 0; idx < reducedCount; ++idx)
                {
                    const size_t ci = static_cast<size_t>(targetLimb) * reducedCount + idx;
                    const u32 wl = dn.mSrcLimb[ci];
                    const u64 vw = poly[static_cast<size_t>(wl) * n + coeff];
                    const u64 xw = mulMod(vw, dn.mCrtInvPunctured[ci], dn.mMods[wl]);
                    sumFrac = wideAdd(sumFrac, wideMulLow(xw, Wide{ dn.mFracInvLo[ci], dn.mFracInvHi[ci] }));
                }

                // distanceToTop = -sumFrac (two's complement over 128 bits)
                const Wide negated = wideSub(Wide{ 0, 0 }, sumFrac);
                const Wide margin{ marginLo[targetLimb], marginHi[targetLimb] };

                const bool lowFail =
                    (sumFrac.mHi < margin.mHi) || (sumFrac.mHi == margin.mHi && sumFrac.mLo < margin.mLo);
                const bool highFail =
                    (negated.mHi < margin.mHi) || (negated.mHi == margin.mHi && negated.mLo < margin.mLo);
                if (lowFail || highFail)
                {
                    *failFlag = 1u;
                    return;
                }
            }
        }

        template<u32 Rho, u32 TargetLimb, u32 Idx>
        __device__ __forceinline__ void validateGoldenSeedSpecializedTerms(
            DeviceDenoise dn,
            const u64* poly,
            u32 n,
            u32 coeff,
            Wide& sumFrac)
        {
            static_assert(Rho == 4u || Rho == 8u);
            static_assert(TargetLimb < Rho);
            static_assert(Idx < Rho - 1u);
            constexpr u32 reducedCount = Rho - 1u;
            constexpr u32 wl = Idx + (Idx >= TargetLimb ? 1u : 0u);
            constexpr size_t ci = static_cast<size_t>(TargetLimb) * reducedCount + Idx;

            const u64 vw = poly[static_cast<size_t>(wl) * n + coeff];
            const u64 xw = mulMod(vw, dn.mCrtInvPunctured[ci], dn.mMods[wl]);
            sumFrac = wideAdd(
                sumFrac, wideMulLow(xw, Wide{ dn.mFracInvLo[ci], dn.mFracInvHi[ci] }));

            if constexpr (Idx + 1u < reducedCount)
            {
                validateGoldenSeedSpecializedTerms<Rho, TargetLimb, Idx + 1u>(
                    dn, poly, n, coeff, sumFrac);
            }
        }

        template<u32 Rho, u32 TargetLimb>
        __device__ __forceinline__ bool validateGoldenSeedSpecializedTarget(
            DeviceDenoise dn,
            const u64* poly,
            u32 n,
            u32 coeff,
            const u64* marginLo,
            const u64* marginHi)
        {
            Wide sumFrac{ 0, u64(1) << 63 };
            validateGoldenSeedSpecializedTerms<Rho, TargetLimb, 0u>(
                dn, poly, n, coeff, sumFrac);

            const Wide negated = wideSub(Wide{ 0, 0 }, sumFrac);
            const Wide margin{ marginLo[TargetLimb], marginHi[TargetLimb] };
            const bool lowFail =
                (sumFrac.mHi < margin.mHi) ||
                (sumFrac.mHi == margin.mHi && sumFrac.mLo < margin.mLo);
            const bool highFail =
                (negated.mHi < margin.mHi) ||
                (negated.mHi == margin.mHi && negated.mLo < margin.mLo);
            return lowFail || highFail;
        }

        __global__ void validateGoldenSeedSpecializedKernel(
            DeviceRing rg,
            DeviceDenoise dn,
            const u64* tbk,
            u32 polyCount,
            const u64* marginLo,
            const u64* marginHi,
            u32* failFlag)
        {
            constexpr u32 Rho = 4u;
            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= rg.mN) return;
            const size_t perPoly = static_cast<size_t>(Rho) * rg.mN;

            for (u32 o = blockIdx.y; o < polyCount; o += gridDim.y)
            {
                if (*failFlag) return;
                // launchValidateGoldenSeed has already checked mu % rho == 0,
                // so (o % mu) % rho is exactly o % rho for rho=4.
                const u32 targetLimb = o & (Rho - 1u);
                const u64* poly = tbk + static_cast<size_t>(o) * perPoly;
                bool failed = false;
                switch (targetLimb)
                {
                case 0u:
                    failed = validateGoldenSeedSpecializedTarget<Rho, 0u>(
                        dn, poly, rg.mN, coeff, marginLo, marginHi);
                    break;
                case 1u:
                    failed = validateGoldenSeedSpecializedTarget<Rho, 1u>(
                        dn, poly, rg.mN, coeff, marginLo, marginHi);
                    break;
                case 2u:
                    failed = validateGoldenSeedSpecializedTarget<Rho, 2u>(
                        dn, poly, rg.mN, coeff, marginLo, marginHi);
                    break;
                case 3u:
                    failed = validateGoldenSeedSpecializedTarget<Rho, 3u>(
                        dn, poly, rg.mN, coeff, marginLo, marginHi);
                    break;

                }
                if (failed)
                {
                    *failFlag = 1u;
                    return;
                }
            }
        }

        // Compact view for the fixed production GoldenSeed predicate. Keeping
        // the unrelated denoise tables out of the kernel parameter set reduces
        // pointer liveness across the four uniform target-limb bodies.
        struct DeviceGoldenValidateRho4
        {
            const u64* mQ;
            const ShoupOperand* mCrtInvPunctured;
            const u64* mFracInvLo;
            const u64* mFracInvHi;
        };

        template<u32 TargetLimb, u32 Idx>
        __device__ __forceinline__ void validateGoldenSeedRho4ShoupTerm(
            DeviceGoldenValidateRho4 gv,
            const u64* poly,
            u32 coeff,
            Wide& sumFrac)
        {
            static_assert(TargetLimb < 4u);
            static_assert(Idx < 3u);
            constexpr u32 wl = Idx + (Idx >= TargetLimb ? 1u : 0u);
            constexpr size_t ci = static_cast<size_t>(TargetLimb) * 3u + Idx;

            const u64 vw = poly[static_cast<size_t>(wl) * kDenoiseRho4N + coeff];
            const u64 xw =
                mulShoup(vw, gv.mCrtInvPunctured[ci], gv.mQ[wl]);
            sumFrac = wideAdd(
                sumFrac, wideMulLow(xw, Wide{ gv.mFracInvLo[ci], gv.mFracInvHi[ci] }));
        }

        template<u32 TargetLimb>
        __device__ __forceinline__ bool validateGoldenSeedRho4ShoupTarget(
            DeviceGoldenValidateRho4 gv,
            const u64* poly,
            u32 coeff,
            const u64* marginLo,
            const u64* marginHi)
        {
            static_assert(TargetLimb < 4u);
            Wide sumFrac{ 0, u64(1) << 63 };
            // Preserve validateGoldenSeedCandidate's source-limb and wrapped
            // 128-bit addition order exactly.
            validateGoldenSeedRho4ShoupTerm<TargetLimb, 0u>(gv, poly, coeff, sumFrac);
            validateGoldenSeedRho4ShoupTerm<TargetLimb, 1u>(gv, poly, coeff, sumFrac);
            validateGoldenSeedRho4ShoupTerm<TargetLimb, 2u>(gv, poly, coeff, sumFrac);

            const Wide negated = wideSub(Wide{ 0, 0 }, sumFrac);
            const Wide margin{ marginLo[TargetLimb], marginHi[TargetLimb] };
            const bool lowFail =
                (sumFrac.mHi < margin.mHi) ||
                (sumFrac.mHi == margin.mHi && sumFrac.mLo < margin.mLo);
            const bool highFail =
                (negated.mHi < margin.mHi) ||
                (negated.mHi == margin.mHi && negated.mLo < margin.mLo);
            return lowFail || highFail;
        }

        // Exactly one block-row per polynomial and 32 x-blocks cover N=8192.
        // mu divisibility and the grid.y limit are proved by the launcher, so no
        // bounds checks or per-thread polynomial loop remain on this hot path.
        __global__ void validateGoldenSeedRho4ShoupKernel(
            DeviceGoldenValidateRho4 gv,
            const u64* tbk,
            const u64* marginLo,
            const u64* marginHi,
            u32* failFlag)
        {
            // Preserve the cheap global short-circuit before doing any index or
            // constant-table work for a seed that another block has rejected.
            if (*failFlag) return;

            const u32 coeff = (blockIdx.x << 8u) + threadIdx.x;
            const u32 o = blockIdx.y;
            const u32 targetLimb = o & 3u;
            const u64* poly = tbk + (static_cast<size_t>(o) << 15u);
            bool failed = false;
            switch (targetLimb)
            {
            case 0u:
                failed = validateGoldenSeedRho4ShoupTarget<0u>(
                    gv, poly, coeff, marginLo, marginHi);
                break;
            case 1u:
                failed = validateGoldenSeedRho4ShoupTarget<1u>(
                    gv, poly, coeff, marginLo, marginHi);
                break;
            case 2u:
                failed = validateGoldenSeedRho4ShoupTarget<2u>(
                    gv, poly, coeff, marginLo, marginHi);
                break;
            case 3u:
                failed = validateGoldenSeedRho4ShoupTarget<3u>(
                    gv, poly, coeff, marginLo, marginHi);
                break;
            }
            if (failed) *failFlag = 1u;
        }

        // Mirrors seedLabelAgg: out[i] = sum_{j<tau} in[i*tau+j] mod q.
        __global__ void aggregateKernel(
            DeviceRing rg, const u64* in, u32 tau, u64* out, u32 outCount)
        {
            const u32 n = rg.mN;
            const size_t perPoly = static_cast<size_t>(rg.mRho) * n;
            const u32 perPolyU = static_cast<u32>(perPoly);
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            if (elem >= perPolyU) return;
            const u32 limb = elem >> rg.mLogN;
            const u64 q = rg.mMods[limb].mValue;
            const size_t rem = static_cast<size_t>(elem);

            for (u32 o = blockIdx.y; o < outCount; o += gridDim.y)
            {
                const u64* src = in + static_cast<size_t>(o) * tau * perPoly + rem;
                u64 acc = src[0];
                for (u32 j = 1; j < tau; ++j)
                {
                    acc = addMod(acc, src[static_cast<size_t>(j) * perPoly], q);
                }
                out[static_cast<size_t>(o) * perPoly + rem] = acc;
            }
        }

        // Mirrors the unscaled public CRT/BatchEncoder decode branch. Unlike
        // the gadget paths, host-supplied ring labels may contain noncanonical
        // residues, so normalize every limb before composing its [0,Q) value.
        template<u32 W>
        __global__ void composeReducePlainKernel(
            DeviceRing ring,
            const GpuModulus* plainMods,
            const u64* in,
            u32 inCount,
            u64* out)
        {
            const u32 n = ring.mN;
            const size_t perPoly = static_cast<size_t>(W) * n;
            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;
            const GpuModulus plain = plainMods[0];
            for (u32 o = blockIdx.y; o < inCount; o += gridDim.y)
            {
                const u64* poly = in + static_cast<size_t>(o) * perPoly;
                u64 residues[W];
#pragma unroll
                for (u32 j = 0; j < W; ++j)
                {
                    const GpuModulus q = ring.mMods[j];
                    const u64 value = poly[static_cast<size_t>(j) * n + coeff];
                    residues[j] = value < q.mValue ? value : barrettReduce64(value, q);
                }
                u64 composed[W];
                crtCompose(residues, 1u, ring.mMods,
                    ring.mInvPuncturedProd, ring.mPuncturedProd,
                    ring.mBaseProd, composed);
                out[static_cast<size_t>(o) * n + coeff] =
                    mpModuloPlain(composed, plain);
            }
        }

        // Mirrors the scaleAndRound branch of unwrapRingLabelsCrt: divide each
        // RNS residue by q_i, scale by the plaintext modulus, and round, giving
        // one plaintext coefficient per ring coefficient.
        template<bool UseShoupQuotient>
        __global__ void scaleAndRoundKernel(
            DeviceRing rg,
            const u64* in,
            u32 inCount,
            u64 plainModulus,
            const u64* crtInvPunctured,
            const u64* qValues,
            const u64* pShoup,
            const u64* fracInvLo,
            const u64* fracInvHi,
            u64* out)
        {
            const u32 n = rg.mN;
            const u32 rho = rg.mRho;
            const size_t perPoly = static_cast<size_t>(rho) * n;
            const u32 outCountArg = inCount;

            const u32 coeff = blockIdx.x * blockDim.x + threadIdx.x;
            if (coeff >= n) return;
            for (u32 o = blockIdx.y; o < outCountArg; o += gridDim.y)
            {
                const u64* poly = in + static_cast<size_t>(o) * perPoly;

                u64 scaled = 0;
                Wide fracSum{ 0, u64(1) << 63 };   // the 2^127 rounding term

                for (u32 j = 0; j < rho; ++j)
                {
                    const GpuModulus mod = rg.mMods[j];
                    u64 v = poly[static_cast<size_t>(j) * n + coeff];
                    if (v >= mod.mValue) v = barrettReduce64(v, mod);
                    u64 x = 0;
                    if constexpr (UseShoupQuotient)
                    {
                        // GpuRing already mirrors this full-base inverse-punctured
                        // operand in Shoup form. Reuse it instead of paying a
                        // generic 128-bit Barrett multiply in every limb.
                        x = mulShoup(v, rg.mInvPuncturedProd[j], mod.mValue);
                    }
                    else
                    {
                        x = mulMod(v, crtInvPunctured[j], mod);
                    }

                    u64 quotientLo = 0;
                    u64 rem = 0;
                    if constexpr (UseShoupQuotient)
                    {
                        const u64 q = mod.mValue;
                        quotientLo = mulHi64(x, pShoup[j]);

                        // With R=2^64 and s=floor(pR/q), floor(xs/R) is
                        // floor(xp/q) or one less. Thus this difference is in
                        // [0,2q), and q<2^63 makes its wrapped low word exact.
                        rem = x * plainModulus - quotientLo * q;
                        if (rem >= q)
                        {
                            rem -= q;
                            ++quotientLo;
                        }
                    }
                    else
                    {
                        Wide quotient{};
                        divModWide(
                            wideMul(x, plainModulus), qValues[j],
                            Wide{ fracInvLo[j], fracInvHi[j] }, &quotient, &rem);
                        quotientLo = quotient.mLo;
                    }

                    if constexpr (!UseShoupQuotient)
                    {
                        scaled += quotientLo;
                        if (scaled >= plainModulus) scaled -= plainModulus;
                    }

                    unsigned char carry = 0;
                    fracSum = wideAdd(fracSum, wideMulLow(rem, Wide{ fracInvLo[j], fracInvHi[j] }), &carry);
                    if constexpr (UseShoupQuotient)
                    {
                        // scaled and quotientLo are each below p and carry is a
                        // bit, so their sum is below 2p <= 2^64. Defer the only
                        // modular correction until all three are available.
                        scaled += quotientLo + static_cast<u64>(carry);
                        if (scaled >= plainModulus) scaled -= plainModulus;
                    }
                    else if (carry)
                    {
                        ++scaled;
                        if (scaled == plainModulus) scaled = 0;
                    }
                }

                out[static_cast<size_t>(o) * n + coeff] = scaled;
            }
        }

        // Fixed production scale-and-round geometry. The direct two-dimensional
        // grid gives every thread exactly one (output,coefficient), while the
        // compact persistent table contains only the seven words consumed per
        // limb. Keeping the rho=4 loop rolled limits live constants and allows
        // eight resident 256-thread CTAs without spills.
        __global__ __launch_bounds__(256, 8)
        void scaleAndRoundHotRho4Kernel(
            const u64* __restrict__ in,
            u64 plainModulus,
            const ScaleRoundFastLimb* __restrict__ fastLimbs,
            u64* __restrict__ out)
        {
            constexpr u32 kN = 8192;
            constexpr u32 kRho = 4;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;

            const u32 coeff = (blockIdx.x << 8u) + threadIdx.x;
            const u32 o = blockIdx.y;
            const u64* poly = in + static_cast<size_t>(o) * kPerPoly;

            u64 scaled = 0;
            Wide fracSum{ 0, u64(1) << 63 };

#pragma unroll 1
            for (u32 j = 0; j < kRho; ++j)
            {
                const ScaleRoundFastLimb& limb = fastLimbs[j];
                const u64 q = limb.mQ;
                u64 v = poly[(static_cast<size_t>(j) << 13u) + coeff];
                if (v >= q)
                {
                    const u64 tmp = mulHi64(v, limb.mBarrettRatio1);
                    v -= tmp * q;
                    if (v >= q) v -= q;
                }

                u64 x = limb.mInvOperand * v -
                    mulHi64(v, limb.mInvQuotient) * q;
                if (x >= q) x -= q;

                u64 quotientLo = mulHi64(x, limb.mPShoup);
                u64 rem = x * plainModulus - quotientLo * q;
                if (rem >= q)
                {
                    rem -= q;
                    ++quotientLo;
                }

                unsigned char carry = 0;
                fracSum = wideAdd(
                    fracSum,
                    wideMulLow(rem, Wide{ limb.mFracLo, limb.mFracHi }),
                    &carry);
                scaled += quotientLo + static_cast<u64>(carry);
                if (scaled >= plainModulus) scaled -= plainModulus;

            }

            out[static_cast<size_t>(o) * kN + coeff] = scaled;
        }

        // Exact high-word-first specialization of the accepted fast rho=4
        // kernel. For T_j = rem_j * frac_j (mod 2^128), write T_j as
        // hi_j*2^64 + lo_j. The old sum's total 128-bit carry is
        //
        // floor((2^63 + sum(hi_j) + floor(sum(lo_j)/2^64)) / 2^64).
        //
        // The low-word carry is at most three for four terms. Therefore the
        // common path needs only hi_j; all four low products are replayed only
        // in the three wrapped high residues where they can change the answer.
        __global__ __launch_bounds__(256, 8)
        void scaleAndRoundHotRho4HiCarryKernel(
            const u64* __restrict__ in,
            u64 plainModulus,
            const ScaleRoundFastLimb* __restrict__ fastLimbs,
            u64* __restrict__ out)
        {
            constexpr u32 kN = 8192;
            constexpr u32 kRho = 4;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;
            constexpr u64 kReplayMin = ~u64(2); // 2^64 - 3
            static_assert(kRho - 1u == 3u, "rho=4 low-word carry bound");

            const u32 coeff = (blockIdx.x << 8u) + threadIdx.x;
            const u32 o = blockIdx.y;
            const u64* poly = in + static_cast<size_t>(o) * kPerPoly;

            u64 scaled = 0;
            u64 fracHigh = u64(1) << 63;

#pragma unroll 1
            for (u32 j = 0; j < kRho; ++j)
            {
                const ScaleRoundFastLimb& limb = fastLimbs[j];
                const u64 q = limb.mQ;
                u64 v = poly[(static_cast<size_t>(j) << 13u) + coeff];
                if (v >= q)
                {
                    const u64 tmp = mulHi64(v, limb.mBarrettRatio1);
                    v -= tmp * q;
                    if (v >= q) v -= q;
                }

                u64 x = limb.mInvOperand * v -
                    mulHi64(v, limb.mInvQuotient) * q;
                if (x >= q) x -= q;

                u64 quotientLo = mulHi64(x, limb.mPShoup);
                u64 rem = x * plainModulus - quotientLo * q;
                if (rem >= q)
                {
                    rem -= q;
                    ++quotientLo;
                }

                // High word of the low 128 bits of rem*(fracLo,fracHi).
                // Unsigned wrap intentionally discards product bits >=128.
                const u64 termHigh =
                    mulHi64(rem, limb.mFracLo) + rem * limb.mFracHi;
                const u64 oldHigh = fracHigh;
                fracHigh += termHigh;
                const u64 highCarry = static_cast<u64>(fracHigh < oldHigh);

                scaled += quotientLo + highCarry;
                if (scaled >= plainModulus) scaled -= plainModulus;
            }

            if (fracHigh >= kReplayMin)
            {
                u64 fracLow = 0;
                u32 lowCarry = 0;

#pragma unroll 1
                for (u32 j = 0; j < kRho; ++j)
                {
                    const ScaleRoundFastLimb& limb = fastLimbs[j];
                    const u64 q = limb.mQ;
                    u64 v = poly[(static_cast<size_t>(j) << 13u) + coeff];
                    if (v >= q)
                    {
                        const u64 tmp = mulHi64(v, limb.mBarrettRatio1);
                        v -= tmp * q;
                        if (v >= q) v -= q;
                    }

                    u64 x = limb.mInvOperand * v -
                        mulHi64(v, limb.mInvQuotient) * q;
                    if (x >= q) x -= q;

                    const u64 quotientLo = mulHi64(x, limb.mPShoup);
                    u64 rem = x * plainModulus - quotientLo * q;
                    if (rem >= q) rem -= q;

                    const u64 next = fracLow + rem * limb.mFracLo;
                    lowCarry += static_cast<u32>(next < fracLow);
                    fracLow = next;
                }

                // fracHigh + lowCarry wraps iff fracHigh > 2^64-1-lowCarry.
                if (fracHigh > ~static_cast<u64>(lowCarry))
                {
                    ++scaled;
                    if (scaled == plainModulus) scaled = 0;
                }
            }

            out[static_cast<size_t>(o) * kN + coeff] = scaled;
        }

        // The hot unwrap has three adjacent ownership boundaries:
        //
        //   RNS labels -> scale-and-round -> plaintext NTT -> decoded slots.
        //
        // Keeping the first boundary in this block's 64 KiB shared tile removes
        // the chunk*N coefficient allocation and its full global write/read. The
        // final NTT owner already has the inverse slot permutation, so the second
        // boundary is removed in the same way as nttForwardGather. The rolled
        // rho loop is intentionally identical to scaleAndRoundHotRho4Kernel, and
        // the fixed stages are the same helpers used by nttForwardKernel.
        struct ScaleNttForwardGather8192Args
        {
            const u64* mIn;
            const ScaleRoundFastLimb* mFastLimbs;
            const ShoupOperand* mRoots;
            const u32* mInverseSlotMap;
            u64* mOut;
            u64 mOutCount;
            u64 mPlainModulus;
        };

        __global__ void scaleNttForwardGather8192Rho4Kernel(
            ScaleNttForwardGather8192Args args)
        {
            constexpr u32 kN = 8192u;
            constexpr u32 kRho = 4u;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;
            extern __shared__ u64 sh[];

            // End all RNS-only pointer and accumulator lifetimes before the
            // block enters the transform. This is important at 1024 threads,
            // where 32 registers is the threshold for two resident CTAs.
            {
                const u64* poly =
                    args.mIn + static_cast<size_t>(blockIdx.x) * kPerPoly;
                for (u32 coeff = threadIdx.x; coeff < kN; coeff += blockDim.x)
                {
                    u64 scaled = 0;
                    Wide fracSum{ 0, u64(1) << 63 };

#pragma unroll 1
                    for (u32 j = 0; j < kRho; ++j)
                    {
                        const ScaleRoundFastLimb& limb = args.mFastLimbs[j];
                        const u64 q = limb.mQ;
                        u64 v = poly[(static_cast<size_t>(j) << 13u) + coeff];
                        if (v >= q)
                        {
                            const u64 tmp = mulHi64(v, limb.mBarrettRatio1);
                            v -= tmp * q;
                            if (v >= q) v -= q;
                        }

                        u64 x = limb.mInvOperand * v -
                            mulHi64(v, limb.mInvQuotient) * q;
                        if (x >= q) x -= q;

                        u64 quotientLo = mulHi64(x, limb.mPShoup);
                        u64 rem = x * args.mPlainModulus - quotientLo * q;
                        if (rem >= q)
                        {
                            rem -= q;
                            ++quotientLo;
                        }

                        unsigned char carry = 0;
                        fracSum = wideAdd(
                            fracSum,
                            wideMulLow(rem, Wide{ limb.mFracLo, limb.mFracHi }),
                            &carry);
                        scaled += quotientLo + static_cast<u64>(carry);
                        if (scaled >= args.mPlainModulus)
                            scaled -= args.mPlainModulus;

                    }
                    sh[coeff] = scaled;
                }
            }
            __syncthreads();

            {
                const u64 q = args.mPlainModulus;
                const u64 twoQ = q << 1u;
                const ShoupOperand* roots = args.mRoots;
                nttForwardStage8192<0, true>(sh, roots, q, twoQ);
                nttForwardStage8192<1, true>(sh, roots, q, twoQ);
                nttForwardStage8192<2, true>(sh, roots, q, twoQ);
                nttForwardStage8192<3, true>(sh, roots, q, twoQ);
                nttForwardStage8192<4, true>(sh, roots, q, twoQ);
                nttForwardStage8192<5, true>(sh, roots, q, twoQ);
                nttForwardStage8192<6, true>(sh, roots, q, twoQ);
                nttForwardStage8192<7, true>(sh, roots, q, twoQ);
                nttForwardStage8192<8, true>(sh, roots, q, twoQ);
                nttForwardStage8192<9, true>(sh, roots, q, twoQ);
                nttForwardStage8192<10, true>(sh, roots, q, twoQ);
                nttForwardStage8192<11, true>(sh, roots, q, twoQ);
                nttForwardStage8192<12, true>(sh, roots, q, twoQ);
            }

            for (u32 coeff = threadIdx.x; coeff < kN; coeff += blockDim.x)
            {
                u64 x = sh[coeff];
                const u64 twoQ = args.mPlainModulus << 1u;
                if (x >= twoQ) x -= twoQ;
                if (x >= args.mPlainModulus) x -= args.mPlainModulus;
                const u64 outIdx =
                    static_cast<u64>(blockIdx.x) * kN +
                    args.mInverseSlotMap[coeff];
                if (outIdx < args.mOutCount) args.mOut[outIdx] = x;
            }
        }

        // Selected production scale/NTT/gather fusion. The scale phase
        // is bit-for-bit the accepted rho=4 high-word carry specialization; its
        // rare replay reconstructs the omitted low-word carry exactly. Scoped
        // phase lifetimes keep the complete 1024-thread kernel at the Hopper
        // two-CTA limit of 32 registers with no local memory or calls.
        __global__ __launch_bounds__(1024, 2)
        void scaleNttForwardGather8192Rho4HiCarryKernel(
            ScaleNttForwardGather8192Args args)
        {
            constexpr u32 kN = 8192u;
            constexpr u32 kRho = 4u;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;
            constexpr u64 kReplayMin = ~u64(2); // 2^64 - 3
            static_assert(kRho - 1u == 3u, "rho=4 low-word carry bound");
            extern __shared__ u64 sh[];

            {
                const u64 plainModulus = args.mPlainModulus;
                const u64* poly =
                    args.mIn + static_cast<size_t>(blockIdx.x) * kPerPoly;
                for (u32 coeff = threadIdx.x; coeff < kN;
                     coeff += blockDim.x)
                {
                    u64 scaled = 0;
                    u64 fracHigh = u64(1) << 63;

#pragma unroll 1
                    for (u32 j = 0; j < kRho; ++j)
                    {
                        const ScaleRoundFastLimb& limb = args.mFastLimbs[j];
                        const u64 q = limb.mQ;
                        u64 v =
                            poly[(static_cast<size_t>(j) << 13u) + coeff];
                        if (v >= q)
                        {
                            const u64 tmp = mulHi64(v, limb.mBarrettRatio1);
                            v -= tmp * q;
                            if (v >= q) v -= q;
                        }

                        u64 x = limb.mInvOperand * v -
                            mulHi64(v, limb.mInvQuotient) * q;
                        if (x >= q) x -= q;

                        u64 quotientLo = mulHi64(x, limb.mPShoup);
                        u64 rem = x * plainModulus - quotientLo * q;
                        if (rem >= q)
                        {
                            rem -= q;
                            ++quotientLo;
                        }

                        const u64 termHigh =
                            mulHi64(rem, limb.mFracLo) +
                            rem * limb.mFracHi;
                        const u64 oldHigh = fracHigh;
                        fracHigh += termHigh;
                        const u64 highCarry =
                            static_cast<u64>(fracHigh < oldHigh);

                        scaled += quotientLo + highCarry;
                        if (scaled >= plainModulus) scaled -= plainModulus;
                    }

                    if (fracHigh >= kReplayMin)
                    {
                        u64 fracLow = 0;
                        u32 lowCarry = 0;

#pragma unroll 1
                        for (u32 j = 0; j < kRho; ++j)
                        {
                            const ScaleRoundFastLimb& limb =
                                args.mFastLimbs[j];
                            const u64 q = limb.mQ;
                            u64 v = poly[
                                (static_cast<size_t>(j) << 13u) + coeff];
                            if (v >= q)
                            {
                                const u64 tmp =
                                    mulHi64(v, limb.mBarrettRatio1);
                                v -= tmp * q;
                                if (v >= q) v -= q;
                            }

                            u64 x = limb.mInvOperand * v -
                                mulHi64(v, limb.mInvQuotient) * q;
                            if (x >= q) x -= q;

                            const u64 quotientLo =
                                mulHi64(x, limb.mPShoup);
                            u64 rem =
                                x * plainModulus - quotientLo * q;
                            if (rem >= q) rem -= q;

                            const u64 next =
                                fracLow + rem * limb.mFracLo;
                            lowCarry +=
                                static_cast<u32>(next < fracLow);
                            fracLow = next;
                        }

                        if (fracHigh > ~static_cast<u64>(lowCarry))
                        {
                            ++scaled;
                            if (scaled == plainModulus) scaled = 0;
                        }
                    }

                    sh[coeff] = scaled;
                }
            }
            __syncthreads();

            {
                const u64 q = args.mPlainModulus;
                const u64 twoQ = q << 1u;
                const ShoupOperand* roots = args.mRoots;
                nttForwardStage8192<0, true>(sh, roots, q, twoQ);
                nttForwardStage8192<1, true>(sh, roots, q, twoQ);
                nttForwardStage8192<2, true>(sh, roots, q, twoQ);
                nttForwardStage8192<3, true>(sh, roots, q, twoQ);
                nttForwardStage8192<4, true>(sh, roots, q, twoQ);
                nttForwardStage8192<5, true>(sh, roots, q, twoQ);
                nttForwardStage8192<6, true>(sh, roots, q, twoQ);
                nttForwardStage8192<7, true>(sh, roots, q, twoQ);
                nttForwardStage8192<8, true>(sh, roots, q, twoQ);
                nttForwardStage8192<9, true>(sh, roots, q, twoQ);
                nttForwardStage8192<10, true>(sh, roots, q, twoQ);
                nttForwardStage8192<11, true>(sh, roots, q, twoQ);
                nttForwardStage8192<12, true>(sh, roots, q, twoQ);
            }

            for (u32 coeff = threadIdx.x; coeff < kN;
                 coeff += blockDim.x)
            {
                u64 x = sh[coeff];
                const u64 twoQ = args.mPlainModulus << 1u;
                if (x >= twoQ) x -= twoQ;
                if (x >= args.mPlainModulus) x -= args.mPlainModulus;
                const u64 outIdx =
                    static_cast<u64>(blockIdx.x) * kN +
                    args.mInverseSlotMap[coeff];
                if (outIdx < args.mOutCount) args.mOut[outIdx] = x;
            }
        }

        // Exact counterpart of scaleNttForwardGather8192Rho4HiCarryKernel
        // through the completed S12 shared tile. Only final ownership changes:
        // A separate BatchEncoder forward slotMap makes adjacent threads write
        // adjacent decoded slots and gather their NTT coefficients from shared
        // memory. GpuPlainNtt validates slotMap as a permutation before upload,
        // proving one writer per output slot. Keeping it outside the accepted
        // Args type leaves that type and the rollback symbol byte-for-byte intact.
        __global__ __launch_bounds__(1024, 2)
        void scaleNttForwardGather8192Rho4HiCarrySlotOwnedKernel(
            ScaleNttForwardGather8192Args args,
            const u32* slotMap)
        {
            constexpr u32 kN = 8192u;
            constexpr u32 kRho = 4u;
            constexpr size_t kPerPoly = static_cast<size_t>(kRho) * kN;
            constexpr u64 kReplayMin = ~u64(2); // 2^64 - 3
            static_assert(kRho - 1u == 3u, "rho=4 low-word carry bound");
            extern __shared__ u64 sh[];

            {
                const u64 plainModulus = args.mPlainModulus;
                const u64* poly =
                    args.mIn + static_cast<size_t>(blockIdx.x) * kPerPoly;
                for (u32 coeff = threadIdx.x; coeff < kN;
                     coeff += blockDim.x)
                {
                    u64 scaled = 0;
                    u64 fracHigh = u64(1) << 63;

#pragma unroll 1
                    for (u32 j = 0; j < kRho; ++j)
                    {
                        const ScaleRoundFastLimb& limb = args.mFastLimbs[j];
                        const u64 q = limb.mQ;
                        u64 v =
                            poly[(static_cast<size_t>(j) << 13u) + coeff];
                        if (v >= q)
                        {
                            const u64 tmp =
                                mulHi64(v, limb.mBarrettRatio1);
                            v -= tmp * q;
                            if (v >= q) v -= q;
                        }

                        u64 x = limb.mInvOperand * v -
                            mulHi64(v, limb.mInvQuotient) * q;
                        if (x >= q) x -= q;

                        u64 quotientLo = mulHi64(x, limb.mPShoup);
                        u64 rem = x * plainModulus - quotientLo * q;
                        if (rem >= q)
                        {
                            rem -= q;
                            ++quotientLo;
                        }

                        const u64 termHigh =
                            mulHi64(rem, limb.mFracLo) +
                            rem * limb.mFracHi;
                        const u64 oldHigh = fracHigh;
                        fracHigh += termHigh;
                        const u64 highCarry =
                            static_cast<u64>(fracHigh < oldHigh);

                        scaled += quotientLo + highCarry;
                        if (scaled >= plainModulus) scaled -= plainModulus;
                    }

                    if (fracHigh >= kReplayMin)
                    {
                        u64 fracLow = 0;
                        u32 lowCarry = 0;

#pragma unroll 1
                        for (u32 j = 0; j < kRho; ++j)
                        {
                            const ScaleRoundFastLimb& limb =
                                args.mFastLimbs[j];
                            const u64 q = limb.mQ;
                            u64 v = poly[
                                (static_cast<size_t>(j) << 13u) + coeff];
                            if (v >= q)
                            {
                                const u64 tmp =
                                    mulHi64(v, limb.mBarrettRatio1);
                                v -= tmp * q;
                                if (v >= q) v -= q;
                            }

                            u64 x = limb.mInvOperand * v -
                                mulHi64(v, limb.mInvQuotient) * q;
                            if (x >= q) x -= q;

                            const u64 quotientLo =
                                mulHi64(x, limb.mPShoup);
                            u64 rem =
                                x * plainModulus - quotientLo * q;
                            if (rem >= q) rem -= q;

                            const u64 next =
                                fracLow + rem * limb.mFracLo;
                            lowCarry +=
                                static_cast<u32>(next < fracLow);
                            fracLow = next;
                        }

                        if (fracHigh > ~static_cast<u64>(lowCarry))
                        {
                            ++scaled;
                            if (scaled == plainModulus) scaled = 0;
                        }
                    }

                    sh[coeff] = scaled;
                }
            }
            __syncthreads();

            {
                const u64 q = args.mPlainModulus;
                const u64 twoQ = q << 1u;
                const ShoupOperand* roots = args.mRoots;
                nttForwardStage8192<0, true>(sh, roots, q, twoQ);
                nttForwardStage8192<1, true>(sh, roots, q, twoQ);
                nttForwardStage8192<2, true>(sh, roots, q, twoQ);
                nttForwardStage8192<3, true>(sh, roots, q, twoQ);
                nttForwardStage8192<4, true>(sh, roots, q, twoQ);
                nttForwardStage8192<5, true>(sh, roots, q, twoQ);
                nttForwardStage8192<6, true>(sh, roots, q, twoQ);
                nttForwardStage8192<7, true>(sh, roots, q, twoQ);
                nttForwardStage8192<8, true>(sh, roots, q, twoQ);
                nttForwardStage8192<9, true>(sh, roots, q, twoQ);
                nttForwardStage8192<10, true>(sh, roots, q, twoQ);
                nttForwardStage8192<11, true>(sh, roots, q, twoQ);
                // This CTA barrier is the handoff from coefficient owners to
                // arbitrary slot owners and must remain even though S12's
                // butterflies are otherwise independent.
                nttForwardStage8192<12, true>(sh, roots, q, twoQ);
            }

            for (u32 slot = threadIdx.x; slot < kN;
                 slot += blockDim.x)
            {
                const u64 outIdx =
                    static_cast<u64>(blockIdx.x) * kN + slot;
                // Clip before touching the permutation or shared tile. This
                // covers every partial final chunk without speculative reads.
                if (outIdx < args.mOutCount)
                {
                    const u32 coeff = slotMap[slot];
                    u64 x = sh[coeff];
                    const u64 twoQ = args.mPlainModulus << 1u;
                    if (x >= twoQ) x -= twoQ;
                    if (x >= args.mPlainModulus) x -= args.mPlainModulus;
                    args.mOut[outIdx] = x;
                }
            }
        }


        // Mirrors the first loop of seal::BatchEncoder::encode:
        //   plain[matrix_reps_index_map_[i]] = values[i]
        // with `padValue` standing in for labels past the end of the input, as
        // wrapZpBatchCrt does.
        __global__ void scatterSlotsKernel(
            const u64* __restrict__ labels,
            u64 labelCount,
            u64 padValue,
            const u32* __restrict__ slotMap,
            u32 slotCount,
            u32 chunkCount,
            u64* __restrict__ plain,
            u32 n,
            bool garbledInput)
        {
            const u32 slot = blockIdx.x * blockDim.x + threadIdx.x;
            if (slot >= slotCount) return;
            const u32 dst = slotMap[slot];
            for (u32 c = blockIdx.y; c < chunkCount; c += gridDim.y)
            {
                const u64 src = static_cast<u64>(c) * slotCount + slot;
                plain[static_cast<size_t>(c) * n + dst] = garbledInput
                    ? garbledInputSlot(labels, labelCount, c, slotCount, slot)
                    : (src < labelCount ? labels[src] : padValue);
            }
        }

        __global__ void repeatGarbledInputsKernel(
            const u64* labels, u64 count, u32 n, u32 chunks, u64* out)
        {
            const u32 slot = blockIdx.x * blockDim.x + threadIdx.x;
            if (slot >= n) return;
            for (u32 c = blockIdx.y; c < chunks; c += gridDim.y)
                out[static_cast<u64>(c) * n + slot] = garbledInputSlot(labels, count, c, n, slot);
        }

        // Mirrors encodeSlotsToRingCrt's lift: broadcast the plaintext
        // coefficients to every RNS limb, optionally scaled by Delta = the
        // plaintext lift factor mod q_j.
        __global__ void liftPlainToRingKernel(
            DeviceRing rg,
            const u64* __restrict__ plain,
            u32 chunkCount,
            const u64* __restrict__ liftModQ,   // null for a plain broadcast
            u64* __restrict__ out)
        {
            const u32 n = rg.mN;
            const u32 rho = rg.mRho;
            const u32 elem = blockIdx.x * blockDim.x + threadIdx.x;
            if (elem >= rho * n) return;
            const u32 limb = elem >> rg.mLogN;
            const u32 coeff = elem & (n - 1u);
            const size_t perPoly = static_cast<size_t>(rho) * n;

            const GpuModulus mod = rg.mMods[limb];
            const u64 lift = liftModQ ? liftModQ[limb] : 0;
            for (u32 c = blockIdx.y; c < chunkCount; c += gridDim.y)
            {
                const u64 v = plain[static_cast<size_t>(c) * n + coeff];
                out[static_cast<size_t>(c) * perPoly + elem] = liftModQ ? mulMod(v, lift, mod) : v;
            }
        }

        // Mirrors the final loop of seal::BatchEncoder::decode:
        //   destination[i] = temp_dest[matrix_reps_index_map_[i]]
        // applied to every chunk, writing straight into the flat label array so
        // that no per-chunk host buffer is ever materialised. The last chunk is
        // truncated by `outCount`.
        __global__ void gatherSlotsKernel(
            const u64* __restrict__ plain,
            u32 n,
            const u32* __restrict__ slotMap,
            u32 slotCount,
            u32 chunkCount,
            u64* __restrict__ out,
            u64 outCount)
        {
            const u32 slot = blockIdx.x * blockDim.x + threadIdx.x;
            if (slot >= slotCount) return;
            const u32 src = slotMap[slot];
            for (u32 c = blockIdx.y; c < chunkCount; c += gridDim.y)
            {
                const u64 dst = static_cast<u64>(c) * slotCount + slot;
                if (dst >= outCount) continue;
                out[dst] = plain[static_cast<size_t>(c) * n + src];
            }
        }

        // ---- Blake2b hashing --------------------------------------------
        // RandomOracle hashing for seed derivation and Root digests. PRNG
        // expansion uses AES below.

        __constant__ u64 kBlake2bIV[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };

        __device__ inline u64 rotr64(u64 x, u32 c)
        {
            return (x >> c) | (x << (64u - c));
        }

        // The message words must be indexed with compile-time constants,
        // otherwise nvcc is forced to keep m[16] in local memory (a 128-byte
        // stack frame) and the kernel becomes memory bound. Hence the fully
        // expanded rounds below rather than a loop over a sigma table.
#define LV_B2B_G(a, b, c, d, x, y)                    \
    do {                                              \
        v##a = v##a + v##b + (x);                      \
        v##d = rotr64(v##d ^ v##a, 32);                \
        v##c = v##c + v##d;                            \
        v##b = rotr64(v##b ^ v##c, 24);                \
        v##a = v##a + v##b + (y);                      \
        v##d = rotr64(v##d ^ v##a, 16);                \
        v##c = v##c + v##d;                            \
        v##b = rotr64(v##b ^ v##c, 63);                \
    } while (0)

#define LV_B2B_ROUND(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15) \
    LV_B2B_G(0, 4, 8, 12, m[s0], m[s1]);                                                    \
    LV_B2B_G(1, 5, 9, 13, m[s2], m[s3]);                                                    \
    LV_B2B_G(2, 6, 10, 14, m[s4], m[s5]);                                                   \
    LV_B2B_G(3, 7, 11, 15, m[s6], m[s7]);                                                   \
    LV_B2B_G(0, 5, 10, 15, m[s8], m[s9]);                                                   \
    LV_B2B_G(1, 6, 11, 12, m[s10], m[s11]);                                                 \
    LV_B2B_G(2, 7, 8, 13, m[s12], m[s13]);                                                  \
    LV_B2B_G(3, 4, 9, 14, m[s14], m[s15])

        __device__ __forceinline__ void blake2bCompress(u64* h, const u64* m, u64 t0, u64 t1, u64 f0)
        {
            u64 v0 = h[0], v1 = h[1], v2 = h[2], v3 = h[3];
            u64 v4 = h[4], v5 = h[5], v6 = h[6], v7 = h[7];
            u64 v8 = 0x6a09e667f3bcc908ULL, v9 = 0xbb67ae8584caa73bULL;
            u64 v10 = 0x3c6ef372fe94f82bULL, v11 = 0xa54ff53a5f1d36f1ULL;
            u64 v12 = 0x510e527fade682d1ULL ^ t0;
            u64 v13 = 0x9b05688c2b3e6c1fULL ^ t1;
            u64 v14 = 0x1f83d9abfb41bd6bULL ^ f0;
            u64 v15 = 0x5be0cd19137e2179ULL;

            LV_B2B_ROUND(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            LV_B2B_ROUND(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
            LV_B2B_ROUND(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
            LV_B2B_ROUND(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
            LV_B2B_ROUND(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
            LV_B2B_ROUND(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
            LV_B2B_ROUND(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
            LV_B2B_ROUND(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
            LV_B2B_ROUND(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
            LV_B2B_ROUND(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);
            LV_B2B_ROUND(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            LV_B2B_ROUND(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);

            h[0] ^= v0 ^ v8;
            h[1] ^= v1 ^ v9;
            h[2] ^= v2 ^ v10;
            h[3] ^= v3 ^ v11;
            h[4] ^= v4 ^ v12;
            h[5] ^= v5 ^ v13;
            h[6] ^= v6 ^ v14;
            h[7] ^= v7 ^ v15;
        }

        // ---- osuCrypto::RandomOracle (Blake2b-16) --------------------------
        //
        // Blake2b parameter word 0 for an unkeyed hash with `outlen` output
        // bytes: digest_length=outlen, key_length=0, fanout=1, depth=1. Matches
        // blake2b_init(state, outlen), which is what osuCrypto::Blake2 uses.
        __device__ __forceinline__ u64 roParamWord0(u32 outlen)
        {
            return static_cast<u64>(outlen) | (1ull << 16) | (1ull << 24);
        }

        // label|sid|fallbackNonce|instanceIdx|seedSize (5 x 8) + digestHash (16)
        // + goldenSeed (16). Must match deriveSeedInstanceBlockFromDigestHash.
        constexpr u64 kCt2SeedMessageBytes = 5 * 8 + 16 + 16;

        // ---- AES-128, matching osuCrypto::PRNG -----------------------------
        //
        // PRNG(seed) keys AES-128 with the 16-byte seed and produces its stream
        // as ECB counter mode from counter 0, i.e. block j = AES_seed(j) with j
        // in the low 64 bits, little endian. That is what sealSeedFromBlock
        // consumes to build the 64-byte SEAL prng seed.

        __constant__ __align__(16) unsigned char kAesSbox[256] = {
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
        };

        __device__ __forceinline__ unsigned char xtime(unsigned char x)
        {
            return static_cast<unsigned char>((x << 1) ^ ((x >> 7) * 0x1b));
        }

        // Standard AES-128 key schedule, identical to the sequence produced by
        // libOTe's keyGenHelper<Rcon> chain (Rcon = 01,02,04,...,36).
        __device__ inline void aes128Expand(const unsigned char* key, unsigned char* rk)
        {
#pragma unroll
            for (u32 i = 0; i < 16; ++i) rk[i] = key[i];
            unsigned char rcon = 1;
            for (u32 i = 4; i < 44; ++i)
            {
                unsigned char t[4];
#pragma unroll
                for (u32 j = 0; j < 4; ++j) t[j] = rk[(i - 1) * 4 + j];
                if ((i & 3u) == 0)
                {
                    const unsigned char tmp = t[0];
                    t[0] = static_cast<unsigned char>(kAesSbox[t[1]] ^ rcon);
                    t[1] = kAesSbox[t[2]];
                    t[2] = kAesSbox[t[3]];
                    t[3] = kAesSbox[tmp];
                    rcon = xtime(rcon);
                }
#pragma unroll
                for (u32 j = 0; j < 4; ++j) rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ t[j];
            }
        }

        // AES-128 expansion with only the current 16-byte round key live. The
        // split ct2 seed path writes the 11 round keys to a tiny global scratch
        // array, then lets four independent threads encrypt counters 0..3 instead
        // of one 188-register thread doing all four serially.
        __device__ inline void aes128ExpandToGlobal(u64 lo, u64 hi, unsigned char* out)
        {
            unsigned char key[16];
#pragma unroll
            for (u32 i = 0; i < 8; ++i)
            {
                key[i] = static_cast<unsigned char>(lo >> (8 * i));
                key[8 + i] = static_cast<unsigned char>(hi >> (8 * i));
            }
#pragma unroll
            for (u32 i = 0; i < 16; ++i) out[i] = key[i];

            unsigned char rcon = 1;
#pragma unroll
            for (u32 round = 1; round <= 10; ++round)
            {
                const unsigned char t0 = static_cast<unsigned char>(kAesSbox[key[13]] ^ rcon);
                const unsigned char t1 = kAesSbox[key[14]];
                const unsigned char t2 = kAesSbox[key[15]];
                const unsigned char t3 = kAesSbox[key[12]];
                key[0] ^= t0;
                key[1] ^= t1;
                key[2] ^= t2;
                key[3] ^= t3;
#pragma unroll
                for (u32 i = 4; i < 16; ++i) key[i] ^= key[i - 4];
#pragma unroll
                for (u32 i = 0; i < 16; ++i) out[16 * round + i] = key[i];
                rcon = xtime(rcon);
            }
        }



        __device__ inline void aes128Encrypt(const unsigned char* rk, unsigned char* s)
        {
#pragma unroll
            for (u32 i = 0; i < 16; ++i) s[i] ^= rk[i];
            for (u32 round = 1; round <= 10; ++round)
            {
#pragma unroll
                for (u32 i = 0; i < 16; ++i) s[i] = kAesSbox[s[i]];
                // ShiftRows: state is column major, s[r + 4c].
                unsigned char t;
                t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
                t = s[2]; s[2] = s[10]; s[10] = t;
                t = s[6]; s[6] = s[14]; s[14] = t;
                t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
                if (round != 10)
                {
#pragma unroll
                    for (u32 c = 0; c < 4; ++c)
                    {
                        unsigned char* p = s + 4 * c;
                        const unsigned char a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
                        const unsigned char x = a0 ^ a1 ^ a2 ^ a3;
                        p[0] = static_cast<unsigned char>(a0 ^ x ^ xtime(a0 ^ a1));
                        p[1] = static_cast<unsigned char>(a1 ^ x ^ xtime(a1 ^ a2));
                        p[2] = static_cast<unsigned char>(a2 ^ x ^ xtime(a2 ^ a3));
                        p[3] = static_cast<unsigned char>(a3 ^ x ^ xtime(a3 ^ a0));
                    }
                }
#pragma unroll
                for (u32 i = 0; i < 16; ++i) s[i] ^= rk[16 * round + i];
            }
        }

        // Identical AES round order with the substitution table supplied by the
        // caller. The dedicated full-CTA encrypt kernel passes its shared table;
        // the accepted constant-memory implementation above remains untouched.
        __device__ __forceinline__ void aes128EncryptSharedSbox(
            const unsigned char* rk,
            unsigned char* s,
            const unsigned char* __restrict__ sharedSbox)
        {
#pragma unroll
            for (u32 i = 0; i < 16; ++i) s[i] ^= rk[i];
            for (u32 round = 1; round <= 10; ++round)
            {
#pragma unroll
                for (u32 i = 0; i < 16; ++i)
                    s[i] = sharedSbox[s[i]];
                unsigned char t;
                t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
                t = s[2]; s[2] = s[10]; s[10] = t;
                t = s[6]; s[6] = s[14]; s[14] = t;
                t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
                if (round != 10)
                {
#pragma unroll
                    for (u32 c = 0; c < 4; ++c)
                    {
                        unsigned char* p = s + 4 * c;
                        const unsigned char a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
                        const unsigned char x = a0 ^ a1 ^ a2 ^ a3;
                        p[0] = static_cast<unsigned char>(a0 ^ x ^ xtime(a0 ^ a1));
                        p[1] = static_cast<unsigned char>(a1 ^ x ^ xtime(a1 ^ a2));
                        p[2] = static_cast<unsigned char>(a2 ^ x ^ xtime(a2 ^ a3));
                        p[3] = static_cast<unsigned char>(a3 ^ x ^ xtime(a3 ^ a0));
                    }
                }
#pragma unroll
                for (u32 i = 0; i < 16; ++i) s[i] ^= rk[16 * round + i];
            }
        }

        __device__ __forceinline__ void aes128EncryptCounter(
            const unsigned char* roundKeys, u64 counter, u64& lo, u64& hi)
        {
            unsigned char state[16];
#pragma unroll
            for (u32 i = 0; i < 16; ++i) state[i] = 0;
#pragma unroll
            for (u32 i = 0; i < 8; ++i)
                state[i] = static_cast<unsigned char>(counter >> (8u * i));
            aes128Encrypt(roundKeys, state);

            lo = 0;
            hi = 0;
#pragma unroll
            for (u32 i = 0; i < 8; ++i)
            {
                lo |= static_cast<u64>(state[i]) << (8u * i);
                hi |= static_cast<u64>(state[8u + i]) << (8u * i);
            }
        }

        // Root's production randomizer uses g=110, hence a 111-bit draw. The
        // low word is unmasked and the high word keeps 47 bits. Exactly one raw
        // value (all 111 bits set) is rejected, leaving a bijection onto
        // [-eta,eta], eta=2^110-1.
        constexpr u64 kRootZetaSampleHiMask = (u64(1) << 47u) - 1u;
        constexpr u64 kRootZetaEtaHi = (u64(1) << 46u) - 1u;

        __device__ __forceinline__ bool rootZetaRejected(u64 lo, u64 hi)
        {
            return lo == ~u64(0) && hi == kRootZetaSampleHiMask;
        }

        __device__ __forceinline__ void storeRootZetaRho4(
            const GpuModulus* mods,
            u64 rawLo,
            u64 rawHi,
            u32 poly,
            u32 coeff,
            u64* out)
        {
            constexpr u32 kN = 8192u;
            constexpr u32 kRho = 4u;
            const Wide raw{ rawLo, rawHi };
            const Wide eta{ ~u64(0), kRootZetaEtaHi };
            // eta's low word is maximal, so comparing the high word suffices.
            const bool negative = rawHi <= kRootZetaEtaHi;
            const Wide magnitude = negative ? wideSub(eta, raw) : wideSub(raw, eta);
            u64* polyOut = out + static_cast<size_t>(poly) * kRho * kN;
#pragma unroll
            for (u32 limb = 0; limb < kRho; ++limb)
            {
                const GpuModulus mod = mods[limb];
                const u64 reduced =
                    barrettReduce128(magnitude.mLo, magnitude.mHi, mod);
                polyOut[static_cast<size_t>(limb) * kN + coeff] =
                    (negative && reduced != 0u) ? (mod.mValue - reduced) : reduced;
            }
        }

        constexpr u32 kRootZetaPolys = 3u;

        // Key expansion is deliberately separate from coefficient encryption.
        // One small thread per task writes the 11 round keys once, allowing the
        // coefficient threads below to keep only their AES state live.
        __global__ __launch_bounds__(128) void rootZetaExpandKeysKernel(
            const u64* __restrict__ seeds,
            unsigned char* __restrict__ roundKeys,
            u32* __restrict__ firstReject,
            u32 tasks,
            u32 rangeCoeffs)
        {
            const u32 task = blockIdx.x * blockDim.x + threadIdx.x;
            if (task >= tasks) return;
            firstReject[task] = rangeCoeffs;
            aes128ExpandToGlobal(
                seeds[2u * task], seeds[2u * task + 1u],
                roundKeys + static_cast<size_t>(task) * 176u);
        }

        __global__ __launch_bounds__(256) void rootZetaSampleRho4Kernel(
            const GpuModulus* __restrict__ mods,
            const unsigned char* __restrict__ roundKeys,
            u32* __restrict__ firstReject,
            u64* __restrict__ out,
            u32 rangesPerPoly,
            u32 rangeCoeffs,
            bool forceFirstReject)
        {
            constexpr u32 kN = 8192u;
            const u32 task = blockIdx.y;
            const u32 inRange = blockIdx.x * blockDim.x + threadIdx.x;
            const u32 range = task % rangesPerPoly;
            const u32 coeff = range * rangeCoeffs + inRange;
            if (inRange >= rangeCoeffs || coeff >= kN) return;

            u64 rawLo = 0;
            u64 rawHi = 0;
            aes128EncryptCounter(
                roundKeys + static_cast<size_t>(task) * 176u,
                inRange, rawLo, rawHi);
            rawHi &= kRootZetaSampleHiMask;
            const bool rejected = rootZetaRejected(rawLo, rawHi) ||
                (forceFirstReject && task == 0u && inRange == 0u);
            if (rejected)
            {
                atomicMin(firstReject + task, inRange);
                // The ordered repair owns this coefficient and its suffix. In
                // particular, do not feed the rejected all-ones sample to the
                // Barrett reducer: its high magnitude word is 2^46, whereas
                // every accepted sample is strictly below that bound.
                return;
            }

            const u32 poly = task / rangesPerPoly;
            storeRootZetaRho4(mods, rawLo, rawHi, poly, coeff, out);
        }

        // Cold exact repair. A rejecting task is owned by one lane, which
        // restarts at its first rejected coefficient and consumes AES counters
        // in strict PRNG order. All later provisional outputs in that range are
        // overwritten because every rejection shifts the stream by one block.
        __global__ __launch_bounds__(32) void rootZetaRepairRho4Kernel(
            const GpuModulus* __restrict__ mods,
            const unsigned char* __restrict__ roundKeys,
            const u32* __restrict__ firstReject,
            u64* __restrict__ out,
            u32 rangesPerPoly,
            u32 rangeCoeffs,
            bool forceFirstReject)
        {
            constexpr u32 kN = 8192u;
            const u32 tasks = kRootZetaPolys * rangesPerPoly;
            const u32 task = blockIdx.x * blockDim.x + threadIdx.x;
            if (task >= tasks) return;
            const u32 begin = firstReject[task];
            if (begin >= rangeCoeffs) return;

            const u32 poly = task / rangesPerPoly;
            const u32 range = task % rangesPerPoly;
            u64 counter = begin;
            for (u32 inRange = begin;
                 inRange < rangeCoeffs && range * rangeCoeffs + inRange < kN;
                 ++inRange)
            {
                u64 rawLo = 0;
                u64 rawHi = 0;
                bool rejected = false;
                do
                {
                    const u64 usedCounter = counter++;
                    aes128EncryptCounter(
                        roundKeys + static_cast<size_t>(task) * 176u,
                        usedCounter, rawLo, rawHi);
                    rawHi &= kRootZetaSampleHiMask;
                    rejected = rootZetaRejected(rawLo, rawHi) ||
                        (forceFirstReject && task == 0u && usedCounter == 0u);
                } while (rejected);

                const u32 coeff = range * rangeCoeffs + inRange;
                storeRootZetaRho4(mods, rawLo, rawHi, poly, coeff, out);
            }
        }

        // NoGoldenSeed draws 209 bits for g=208: four consecutive PRNG words,
        // hence TWO AES counters per candidate. Keep the historical range keys
        // and replay a rejected range in order; dropping just one AES block
        // would silently change every subsequent coefficient in that range.
        constexpr u64 kRootZeta208SampleMask = (u64(1) << 17u) - 1u;
        constexpr u64 kRootZeta208EtaHi = (u64(1) << 16u) - 1u;

        __device__ __forceinline__ bool rootZeta208Rejected(const u64 (&raw)[4])
        {
            return raw[0] == ~u64(0) && raw[1] == ~u64(0) &&
                raw[2] == ~u64(0) && raw[3] == kRootZeta208SampleMask;
        }

        __device__ __forceinline__ void storeRootZetaRho8(
            const GpuModulus* mods, const u64 (&raw)[4],
            u32 poly, u32 coeff, u64* out)
        {
            constexpr u32 n = 16384u;
            const u64 eta[4]{ ~u64(0), ~u64(0), ~u64(0), kRootZeta208EtaHi };
            const bool negative = raw[3] <= kRootZeta208EtaHi;
            u64 magnitude[4];
            if (negative) mpSub(eta, raw, magnitude);
            else mpSub(raw, eta, magnitude);
            u64* polyOut = out + static_cast<size_t>(poly) * 8u * n;
#pragma unroll
            for (u32 limb = 0u; limb < 8u; ++limb)
            {
                const GpuModulus mod = mods[limb];
                const u64 reduced = mpModulo(magnitude, mod);
                polyOut[static_cast<size_t>(limb) * n + coeff] =
                    negative && reduced != 0u ? mod.mValue - reduced : reduced;
            }
        }

        __device__ __forceinline__ void rootZeta208DrawShared(
            const unsigned char* roundKeys, const unsigned char* sbox,
            u64 candidate, u64 (&raw)[4])
        {
#pragma unroll
            for (u32 half = 0u; half < 2u; ++half)
            {
                const u64 counter = 2u * candidate + half;
                unsigned char state[16]{};
#pragma unroll
                for (u32 i = 0u; i < 8u; ++i)
                    state[i] = static_cast<unsigned char>(counter >> (8u * i));
                aes128EncryptSharedSbox(roundKeys, state, sbox);
                u64 lo = 0u, hi = 0u;
#pragma unroll
                for (u32 i = 0u; i < 8u; ++i)
                {
                    lo |= static_cast<u64>(state[i]) << (8u * i);
                    hi |= static_cast<u64>(state[8u + i]) << (8u * i);
                }
                raw[2u * half] = lo;
                raw[2u * half + 1u] = hi;
            }
            raw[3] &= kRootZeta208SampleMask;
        }


        __global__ __launch_bounds__(128) void rootZetaExpandKeysRho8Kernel(
            const u64* __restrict__ seeds,
            unsigned char* __restrict__ roundKeys,
            u32* __restrict__ firstReject, u32 tasks, u32 rangeCoeffs)
        {
            const u32 task = blockIdx.x * blockDim.x + threadIdx.x;
            if (task >= tasks) return;
            firstReject[task] = rangeCoeffs;
            aes128ExpandToGlobal(seeds[2u * task], seeds[2u * task + 1u],
                roundKeys + static_cast<size_t>(task) * 176u);
        }

        __global__ __launch_bounds__(256) void rootZetaSampleRho8Kernel(
            const GpuModulus* __restrict__ mods,
            const unsigned char* __restrict__ roundKeys,
            u32* __restrict__ firstReject, u64* __restrict__ out,
            u32 ranges, u32 rangeCoeffs, bool forceFirstReject)
        {
            // Each CTA owns one key and adjacent coefficients. Port the accepted
            // GoldenSeed shared-S-box AES optimization, retaining only one copy
            // of the 176-byte expanded key per CTA.
            __shared__ unsigned char sbox[256];
            __shared__ unsigned char key[176];
            const u32 task = blockIdx.y;
            for (u32 i = threadIdx.x; i < 256u; i += blockDim.x)
                sbox[i] = kAesSbox[i];
            for (u32 i = threadIdx.x; i < 176u; i += blockDim.x)
                key[i] = roundKeys[static_cast<size_t>(task) * 176u + i];
            __syncthreads();
            const u32 poly = task / ranges;
            const u32 range = task % ranges;
            const u32 inRange = blockIdx.x * blockDim.x + threadIdx.x;
            const u32 coeff = range * rangeCoeffs + inRange;
            if (inRange >= rangeCoeffs || coeff >= 16384u) return;
            u64 raw[4];
            rootZeta208DrawShared(key, sbox, inRange, raw);
            if (rootZeta208Rejected(raw) ||
                (forceFirstReject && task == 0u && inRange == 0u))
            {
                atomicMin(firstReject + task, inRange);
                return;
            }
            storeRootZetaRho8(mods, raw, poly, coeff, out);
        }

        __global__ __launch_bounds__(32) void rootZetaRepairRho8Kernel(
            const GpuModulus* __restrict__ mods,
            const unsigned char* __restrict__ roundKeys,
            const u32* __restrict__ firstReject, u64* __restrict__ out,
            u32 ranges, u32 rangeCoeffs, bool forceFirstReject)
        {
            const u32 task = blockIdx.x * blockDim.x + threadIdx.x;
            if (task >= 3u * ranges) return;
            const u32 begin = firstReject[task];
            if (begin >= rangeCoeffs) return;
            const u32 poly = task / ranges;
            const u32 range = task % ranges;
            u64 candidate = begin;
            const auto* key = roundKeys + static_cast<size_t>(task) * 176u;
            for (u32 inRange = begin; inRange < rangeCoeffs &&
                 range * rangeCoeffs + inRange < 16384u; ++inRange)
            {
                u64 raw[4];
                bool rejected;
                do
                {
                    const u64 used = candidate++;
                    aes128EncryptCounter(key, 2u * used, raw[0], raw[1]);
                    aes128EncryptCounter(key, 2u * used + 1u, raw[2], raw[3]);
                    raw[3] &= kRootZeta208SampleMask;
                    rejected = rootZeta208Rejected(raw) ||
                        (forceFirstReject && task == 0u && used == 0u);
                } while (rejected);
                storeRootZetaRho8(mods, raw, poly,
                    range * rangeCoeffs + inRange, out);
            }
        }

        // Mirrors sealSeedFromBlock(polySeed): the first 64 bytes of
        // PRNG(polySeed), i.e. AES_polySeed(0..3).
        __device__ inline void sealSeedFromBlock(u64 lo, u64 hi, u64* out8)
        {
            unsigned char key[16];
#pragma unroll
            for (u32 i = 0; i < 8; ++i)
            {
                key[i] = static_cast<unsigned char>(lo >> (8 * i));
                key[8 + i] = static_cast<unsigned char>(hi >> (8 * i));
            }
            unsigned char rk[176];
            aes128Expand(key, rk);
#pragma unroll
            for (u32 j = 0; j < 4; ++j)
            {
                unsigned char s[16];
#pragma unroll
                for (u32 i = 0; i < 16; ++i) s[i] = 0;
                s[0] = static_cast<unsigned char>(j);   // block(j): low 64 bits, little endian
                aes128Encrypt(rk, s);
                u64 w0 = 0, w1 = 0;
#pragma unroll
                for (u32 i = 0; i < 8; ++i)
                {
                    w0 |= static_cast<u64>(s[i]) << (8 * i);
                    w1 |= static_cast<u64>(s[8 + i]) << (8 * i);
                }
                out8[2 * j + 0] = w0;
                out8[2 * j + 1] = w1;
            }
        }

        // Phase 1 of the ct2 seed derivation: one thread per chunk computes
        //   deriveSeedInstanceBlockFromDigestHash(seed, sid, digestHash,
        //                                         instanceBase + c, mu)
        // = Blake2b-16 over
        //   label | sid | fallbackNonce | instanceIdx | seedSize | digestHash
        //   | seed
        // The digest itself was committed to once by the host (hashSeedDigest),
        // so this is a single compression per chunk instead of a 2049-compression
        // chain over 256 KiB.
        //
        // `prefix` is the 9-word message with slot 3 reserved for instanceIdx:
        //   0 label | 1 sid | 2 fallbackNonce | 3 (per chunk) | 4 seedSize
        //   | 5,6 digestHash | 7,8 goldenSeed
        // i.e. 72 bytes, one Blake2b block.
        __global__ __launch_bounds__(128) void ct2InstanceSeedKernel(
            const u64* __restrict__ prefix,   // [9]
            u64 instanceBase,
            u32 chunkCount,
            u64* __restrict__ out)            // [chunkCount][2]
        {
            const u32 c = blockIdx.x * blockDim.x + threadIdx.x;
            if (c >= chunkCount) return;

            u64 h[8];
            h[0] = kBlake2bIV[0] ^ roParamWord0(16);
#pragma unroll
            for (u32 i = 1; i < 8; ++i) h[i] = kBlake2bIV[i];

            u64 m[16];
#pragma unroll
            for (u32 j = 0; j < 9; ++j) m[j] = prefix[j];
            m[3] = instanceBase + c;
#pragma unroll
            for (u32 j = 9; j < 16; ++j) m[j] = 0;

            blake2bCompress(h, m, kCt2SeedMessageBytes, 0ull, ~u64(0));

            out[2 * c + 0] = h[0];
            out[2 * c + 1] = h[1];
        }

        // Phase 2: one thread per (chunk, row) turns a ct2 seed into the 64-byte
        // SEAL prng seed, mirroring appendPolySeeds / deriveUniformPolyFromSeed:
        //   polySeed = Blake2b-16(label | ct2Seed | domainTag | index(u32)
        //                         | polyModulusDegree(u32) | modulusCount)
        //   sealSeed = first 64 bytes of PRNG(polySeed)
        __global__ __launch_bounds__(128) void ct2PolySeedKernel(
            const u64* __restrict__ ct2Seeds,
            u32 mu,
            u64 domainTag,
            u32 polyModulusDegree,
            u64 modulusCount,
            u32 total,
            u64* __restrict__ out)            // [total][8]
        {
            const u32 gid = blockIdx.x * blockDim.x + threadIdx.x;
            if (gid >= total) return;
            const u32 c = gid / mu;
            const u32 index = gid - c * mu;

            u64 h[8];
            h[0] = kBlake2bIV[0] ^ roParamWord0(16);
#pragma unroll
            for (u32 i = 1; i < 8; ++i) h[i] = kBlake2bIV[i];

            constexpr u64 label = 0x4C4F47564F4C5059ull;
            u64 m[16];
            m[0] = label;
            m[1] = ct2Seeds[2 * c + 0];
            m[2] = ct2Seeds[2 * c + 1];
            m[3] = domainTag;
            // index (u32) then polyModulusDegree (u32) pack into one word.
            m[4] = static_cast<u64>(index) | (static_cast<u64>(polyModulusDegree) << 32);
            m[5] = modulusCount;
#pragma unroll
            for (u32 j = 6; j < 16; ++j) m[j] = 0;
            blake2bCompress(h, m, 48ull, 0ull, ~u64(0));

            sealSeedFromBlock(h[0], h[1], out + static_cast<size_t>(gid) * 8);
        }

        __global__ __launch_bounds__(128) void ct2PolySeedExpandKernel(
            const u64* __restrict__ ct2Seeds,
            u32 mu,
            u64 domainTag,
            u32 polyModulusDegree,
            u64 modulusCount,
            u32 total,
            unsigned char* __restrict__ roundKeys)
        {
            const u32 gid = blockIdx.x * blockDim.x + threadIdx.x;
            if (gid >= total) return;
            const u32 c = gid / mu;
            const u32 index = gid - c * mu;

            u64 h[8];
            h[0] = kBlake2bIV[0] ^ roParamWord0(16);
#pragma unroll
            for (u32 i = 1; i < 8; ++i) h[i] = kBlake2bIV[i];

            constexpr u64 label = 0x4C4F47564F4C5059ull;
            u64 m[16];
            m[0] = label;
            m[1] = ct2Seeds[2 * c + 0];
            m[2] = ct2Seeds[2 * c + 1];
            m[3] = domainTag;
            m[4] = static_cast<u64>(index) | (static_cast<u64>(polyModulusDegree) << 32);
            m[5] = modulusCount;
#pragma unroll
            for (u32 j = 6; j < 16; ++j) m[j] = 0;
            blake2bCompress(h, m, 48ull, 0ull, ~u64(0));

            aes128ExpandToGlobal(h[0], h[1], roundKeys + static_cast<size_t>(gid) * 176);
        }







        __global__ __launch_bounds__(128) void ct2PolySeedEncryptKernel(
            const unsigned char* __restrict__ roundKeys,
            u32 total,
            u64* __restrict__ out)
        {
            const u32 gid = blockIdx.x * blockDim.x + threadIdx.x;
            const u32 poly = gid >> 2;
            if (poly >= total) return;
            const u32 counter = gid & 3u;

            unsigned char state[16];
#pragma unroll
            for (u32 i = 0; i < 16; ++i) state[i] = 0;
            state[0] = static_cast<unsigned char>(counter);
            aes128Encrypt(roundKeys + static_cast<size_t>(poly) * 176, state);

            u64 w0 = 0, w1 = 0;
#pragma unroll
            for (u32 i = 0; i < 8; ++i)
            {
                w0 |= static_cast<u64>(state[i]) << (8 * i);
                w1 |= static_cast<u64>(state[8 + i]) << (8 * i);
            }
            out[static_cast<size_t>(poly) * 8 + 2 * counter + 0] = w0;
            out[static_cast<size_t>(poly) * 8 + 2 * counter + 1] = w1;
        }

        // Full-CTA AES specialization. Sixteen lanes copy one aligned 16-byte
        // table chunk each; every lane reaches the sole barrier before the
        // ordinary validity guard. Host dispatch admits only total%32==0, so the
        // guard is cold insurance and no production lane exits after staging.
        __global__ __launch_bounds__(128) void ct2PolySeedEncryptSharedSboxKernel(
            const unsigned char* __restrict__ roundKeys,
            u32 total,
            u64* __restrict__ out)
        {
            __shared__ __align__(16) unsigned char sharedSbox[256];
            if (threadIdx.x < 16u)
            {
                const uint4 chunk =
                    reinterpret_cast<const uint4*>(kAesSbox)[threadIdx.x];
                reinterpret_cast<uint4*>(sharedSbox)[threadIdx.x] = chunk;
            }
            __syncthreads();

            const u32 gid = blockIdx.x * blockDim.x + threadIdx.x;
            const u32 poly = gid >> 2;
            if (poly >= total) return;
            const u32 counter = gid & 3u;

            unsigned char state[16];
#pragma unroll
            for (u32 i = 0; i < 16; ++i) state[i] = 0;
            state[0] = static_cast<unsigned char>(counter);
            aes128EncryptSharedSbox(
                roundKeys + static_cast<size_t>(poly) * 176,
                state,
                sharedSbox);

            u64 w0 = 0, w1 = 0;
#pragma unroll
            for (u32 i = 0; i < 8; ++i)
            {
                w0 |= static_cast<u64>(state[i]) << (8 * i);
                w1 |= static_cast<u64>(state[8 + i]) << (8 * i);
            }
            out[static_cast<size_t>(poly) * 8 + 2 * counter + 0] = w0;
            out[static_cast<size_t>(poly) * 8 + 2 * counter + 1] = w1;
        }

        __global__ __launch_bounds__(128) void aesPrngExpandKernel(
            const u64* seeds, unsigned char* roundKeys, u32 count)
        {
            for (u64 poly = static_cast<u64>(blockIdx.x) * blockDim.x + threadIdx.x;
                 poly < count; poly += static_cast<u64>(gridDim.x) * blockDim.x)
            {
                u64 h[8];
                h[0] = kBlake2bIV[0] ^ roParamWord0(16);
#pragma unroll
                for (u32 i = 1; i < 8; ++i) h[i] = kBlake2bIV[i];
                u64 message[16];
                message[0] = kAesPrngSeedDomain;
#pragma unroll
                for (u32 i = 0; i < 8; ++i) message[i + 1] = seeds[8u * poly + i];
#pragma unroll
                for (u32 i = 9; i < 16; ++i) message[i] = 0;
                blake2bCompress(h, message, 72ull, 0ull, ~u64(0));
                aes128ExpandToGlobal(h[0], h[1], roundKeys + 176u * poly);
            }
        }

        __device__ __forceinline__ void aesPrngPair(
            const unsigned char* roundKeys, const unsigned char* sbox,
            u64 counter, u64& lo, u64& hi)
        {
            unsigned char state[16]{};
#pragma unroll
            for (u32 i = 0; i < 8; ++i)
                state[i] = static_cast<unsigned char>(counter >> (8u * i));
            aes128EncryptSharedSbox(roundKeys, state, sbox);
            lo = hi = 0;
#pragma unroll
            for (u32 i = 0; i < 8; ++i)
            {
                lo |= static_cast<u64>(state[i]) << (8u * i);
                hi |= static_cast<u64>(state[8u + i]) << (8u * i);
            }
        }

        template<bool Uniform>
        __global__ __launch_bounds__(128) void aesPrngStreamKernel(
            const unsigned char* roundKeys, u64* out, u32 words, u32 count,
            DeviceRing ring, const u64* maxMultiple, const u32* outIdx,
            u32* rejectEpochs, u32 rejectEpoch)
        {
            __shared__ __align__(16) unsigned char key[176];
            __shared__ __align__(16) unsigned char sbox[256];
            if (threadIdx.x < 16)
                reinterpret_cast<uint4*>(sbox)[threadIdx.x] =
                    reinterpret_cast<const uint4*>(kAesSbox)[threadIdx.x];
            for (u64 poly = blockIdx.x; poly < count; poly += gridDim.x)
            {
                if (threadIdx.x < 11)
                    reinterpret_cast<uint4*>(key)[threadIdx.x] =
                        reinterpret_cast<const uint4*>(roundKeys + 176u * poly)[threadIdx.x];
                __syncthreads();
                const u64 destination = Uniform && outIdx ? outIdx[poly] : poly;
                const u64 blocks = (static_cast<u64>(words) + 1u) / 2u;
                for (u64 counter = threadIdx.x; counter < blocks; counter += blockDim.x)
                {
                    u64 values[2];
                    aesPrngPair(key, sbox, counter, values[0], values[1]);
#pragma unroll
                    for (u32 half = 0; half < 2; ++half)
                    {
                        const u64 index = 2u * counter + half;
                        if (index >= words) continue;
                        u64 value = values[half];
                        if constexpr (Uniform)
                        {
                            const u32 limb = static_cast<u32>(index) >> ring.mLogN;
                            if (value >= maxMultiple[limb])
                                atomicExch(rejectEpochs + poly, rejectEpoch);
                            value = barrettReduce64(value, ring.mMods[limb]);
                        }
                        out[destination * words + index] = value;
                    }
                }
                __syncthreads();
            }
        }

        // Regenerate initial candidates cooperatively; only replacement draw
        // consumption is serial. This avoids a full-polynomial scalar replay.
        __global__ __launch_bounds__(128) void aesUniformRepairKernel(
            DeviceRing ring, const unsigned char* roundKeys, const u64* maxMultiple,
            u64* out, const u32* outIdx, u32 count, const u32* rejectEpochs, u32 epoch)
        {
            __shared__ __align__(16) unsigned char key[176];
            __shared__ __align__(16) unsigned char sbox[256];
            __shared__ u64 candidates[256];
            if (threadIdx.x < 16)
                reinterpret_cast<uint4*>(sbox)[threadIdx.x] =
                    reinterpret_cast<const uint4*>(kAesSbox)[threadIdx.x];
            __syncthreads();
            const u64 words = static_cast<u64>(ring.mN) * ring.mRho;
            for (u64 poly = blockIdx.x; poly < count; poly += gridDim.x)
            {
                if (rejectEpochs[poly] != epoch) continue;
                if (threadIdx.x < 11)
                    reinterpret_cast<uint4*>(key)[threadIdx.x] =
                        reinterpret_cast<const uint4*>(roundKeys + 176u * poly)[threadIdx.x];
                __syncthreads();
                u64 cursor = words;
                u64 cachedCounter = ~u64(0), tailLo = 0, tailHi = 0;
                const u64 destination = outIdx ? outIdx[poly] : poly;
                for (u64 base = 0; base < words; base += 256u)
                {
                    u64 lo, hi;
                    aesPrngPair(key, sbox, (base >> 1u) + threadIdx.x, lo, hi);
                    candidates[2u * threadIdx.x] = lo;
                    candidates[2u * threadIdx.x + 1u] = hi;
                    __syncthreads();
                    if (threadIdx.x == 0)
                    {
                        const u32 active = static_cast<u32>(words - base < 256u ? words - base : 256u);
                        for (u32 i = 0; i < active; ++i)
                        {
                            const u64 index = base + i;
                            const u32 limb = static_cast<u32>(index) >> ring.mLogN;
                            const u64 limit = maxMultiple[limb];
                            if (candidates[i] < limit) continue;
                            u64 value;
                            do
                            {
                                const u64 counter = cursor >> 1u;
                                if (counter != cachedCounter)
                                {
                                    aesPrngPair(key, sbox, counter, tailLo, tailHi);
                                    cachedCounter = counter;
                                }
                                value = cursor & 1u ? tailHi : tailLo;
                                ++cursor;
                            } while (value >= limit);
                            out[destination * words + index] = barrettReduce64(value, ring.mMods[limb]);
                        }
                    }
                    __syncthreads();
                }
            }
        }

        // Input generation uses cryptoTools AES, independently of SEAL's
        // BLAKE2xb correlation sampler. Share the one key schedule per CTA.
        __global__ __launch_bounds__(256) void aesCtrScalarsKernel(
            const u64* __restrict__ seed, u64* __restrict__ out,
            u64 count, u64 modulus)
        {
            __shared__ unsigned char roundKeys[176];
            __shared__ unsigned char sbox[256];
            sbox[threadIdx.x] = kAesSbox[threadIdx.x];
            if (threadIdx.x == 0)
                aes128Expand(reinterpret_cast<const unsigned char*>(seed), roundKeys);
            __syncthreads();
            const u64 blocks = (count >> 1u) + (count & 1u);
            for (u64 counter = static_cast<u64>(blockIdx.x) * blockDim.x + threadIdx.x;
                 counter < blocks; counter += static_cast<u64>(gridDim.x) * blockDim.x)
            {
                unsigned char state[16]{};
#pragma unroll
                for (u32 i = 0; i < 8; ++i)
                    state[i] = static_cast<unsigned char>(counter >> (8u * i));
                aes128EncryptSharedSbox(roundKeys, state, sbox);
                u64 lo = 0, hi = 0;
#pragma unroll
                for (u32 i = 0; i < 8; ++i)
                {
                    lo |= static_cast<u64>(state[i]) << (8u * i);
                    hi |= static_cast<u64>(state[8u + i]) << (8u * i);
                }
                out[2u * counter] = lo % modulus;
                if (2u * counter + 1u < count) out[2u * counter + 1u] = hi % modulus;
            }
        }

        // 2D launch geometry: x covers the elements of one polynomial, y covers
        // the polynomials. This keeps all index arithmetic to shifts and masks.
        dim3 grid2D(u32 elemsPerPoly, u32 polyCount, u32 threads)
        {
            const u32 x = (elemsPerPoly + threads - 1u) / threads;
            const u32 y = polyCount < 65535u ? polyCount : 65535u;
            return dim3(x, y == 0 ? 1u : y, 1);
        }



        // Launchers retain the device/stream contract of the borrowed tables.
        // Only cold initialization queries CUDA; warm dispatch is an atomic load.
        bool lockKernelInitialization(KernelInitializationState& state,
            std::atomic<bool>& configured, std::unique_lock<std::mutex>& lock, bool& ready)
        {
            lock = std::unique_lock<std::mutex>(state.mMutex);
            ready = configured.load(std::memory_order_relaxed);
            if (ready) return true;
            int device = -1;
            return check(cudaGetDevice(&device), "kernel initialization device") &&
                device == state.mDevice;
        }

        // Request the tile size rather than the ring degree. Two reasons: a degree
        // above kNttMaxTileLen would ask for more than the 100 KiB a block can
        // opt into on sm_89 (N = 16384 wants 128 KiB), and the request is a cap, so
        // making it constant also removes the latent bug where the first n seen in
        // a process fixed the limit for every later, possibly larger, n.
        bool configureShared(const RingConstView& rc)
        {
            auto* state = rc.mKernelInitialization;
            if (!state) return false;
            if (state->mSharedConfigured.load(std::memory_order_acquire)) return true;
            std::unique_lock<std::mutex> lock;
            bool ready = false;
            if (!lockKernelInitialization(*state, state->mSharedConfigured, lock, ready)) return false;
            if (ready) return true;
            const size_t bytes = static_cast<size_t>(kNttMaxTileLen) * sizeof(u64);
            if (!check(
                    cudaFuncSetAttribute(
                        nttForwardKernel<false, false, false>, cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(forward)"))
                return false;
            if (!check(
                    cudaFuncSetAttribute(
                        nttForwardKernel<
                            false, false, false, false, 0u, false, false, true>,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(forwardCrossingPrepared)"))
                return false;
            {
                if (!check(
                        cudaFuncSetAttribute(
                            nttForwardWarpStages7128192Rho4Kernel,
                            cudaFuncAttributeMaxDynamicSharedMemorySize,
                            static_cast<int>(bytes)),
                        "cudaFuncSetAttribute(forward8192WarpStages712)"))
                    return false;
                if (!check(
                        cudaFuncSetAttribute(
                            nttForwardFromPlainBroadcastWarpStages7128192Rho4Kernel,
                            cudaFuncAttributeMaxDynamicSharedMemorySize,
                            static_cast<int>(bytes)),
                        "cudaFuncSetAttribute(forwardPlainBroadcastWarpStages712)"))
                    return false;
                if (!check(
                        cudaFuncSetAttribute(
                            nttForwardCenteredLimbFromWarpStages7128192Rho4Kernel,
                            cudaFuncAttributeMaxDynamicSharedMemorySize,
                            static_cast<int>(bytes)),
                        "cudaFuncSetAttribute(forwardCenteredWarpStages712)"))
                    return false;
            }
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseKernel<false>, cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inversePlain)"))
                return false;
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseFixed8192Kernel<4u, true>,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inversePlain8192SimpleIndex)"))
                return false;
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseFusedLastThree8192Rho4ReverseSubKernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inversePlain8192SimpleIndexReverseSubFusedLastThree)"))
                return false;
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseFusedLastThree8192Rho4PostKernel<0u>,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inversePlain8192SimpleIndexAddFusedLastThree)"))
                return false;
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseFusedLastThree8192Rho4PostKernel<2u>,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inversePlain8192SimpleIndexNegateFusedLastThree)"))
                return false;
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseTreePairNegateFusedFirstStageKernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inverseTreePairNegateSimpleIndexFusedFirstStage)"))
                return false;
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseRecursiveLeafSparseNegateKernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inverseRecursiveLeafSparseNegate)"))
                return false;
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseRecursiveLeafSparseNegateNoZeroKernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inverseRecursiveLeafSparseNegateNoZero)"))
                return false;
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseKernel<true>, cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inverseFusedIp)"))
                return false;
            state->mSharedConfigured.store(true, std::memory_order_release);
            return true;
        }


        // Keep Stage-110's opt-in attributes out of the common configureShared
        // path. Only an explicit alpha=2 production dispatch (or its focused
        // test hook) touches these separate candidate symbols.
        bool configureNttInversePostWarpStages05Shared(const RingConstView& rc)
        {
            auto* state = rc.mKernelInitialization;
            if (!state) return false;
            if (state->mNttInversePostWarpStages05SharedConfigured.load(std::memory_order_acquire)) return true;
            std::unique_lock<std::mutex> lock;
            bool ready = false;
            if (!lockKernelInitialization(*state, state->mNttInversePostWarpStages05SharedConfigured, lock, ready)) return false;
            if (ready) return true;
            const size_t bytes =
                static_cast<size_t>(kNttMaxTileLen) * sizeof(u64);
            if (!check(
                    cudaFuncSetAttribute(
                        nttInversePostWarpStages05Add8192Rho4Kernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inversePostWarpStages05Add)"))
                return false;
            if (!check(
                    cudaFuncSetAttribute(
                        nttInversePostWarpStages05Negate8192Rho4Kernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inversePostWarpStages05Negate)"))
                return false;
            if (!check(
                    cudaFuncSetAttribute(
                        nttInversePostWarpStages05ReverseSub8192Rho4Kernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inversePostWarpStages05ReverseSub)"))
                return false;
            state->mNttInversePostWarpStages05SharedConfigured.store(true, std::memory_order_release);
            return true;
        }

        bool configurePointwisePseudo55TreeWarpShared(const RingConstView& rc)
        {
            auto* state = rc.mKernelInitialization;
            if (!state) return false;
            if (state->mPointwisePseudo55TreeWarpSharedConfigured.load(std::memory_order_acquire)) return true;
            std::unique_lock<std::mutex> lock;
            bool ready = false;
            if (!lockKernelInitialization(*state, state->mPointwisePseudo55TreeWarpSharedConfigured, lock, ready)) return false;
            if (ready) return true;
            const size_t bytes =
                static_cast<size_t>(kNttMaxTileLen) * sizeof(u64);
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseTreePairNegateWarpStagesPseudo55Kernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inverseTreePairWarpStagesPseudo55)"))
                return false;
            state->mPointwisePseudo55TreeWarpSharedConfigured.store(true, std::memory_order_release);
            return true;
        }

        bool configurePointwisePseudo55TreeProductWarpShared(const RingConstView& rc)
        {
            auto* state = rc.mKernelInitialization;
            if (!state) return false;
            if (state->mPointwisePseudo55TreeProductWarpSharedConfigured.load(std::memory_order_acquire)) return true;
            std::unique_lock<std::mutex> lock;
            bool ready = false;
            if (!lockKernelInitialization(*state, state->mPointwisePseudo55TreeProductWarpSharedConfigured, lock, ready)) return false;
            if (ready) return true;
            const size_t bytes =
                static_cast<size_t>(kNttMaxTileLen) * sizeof(u64);
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseTreePairNegateProductWarpStages05Pseudo55Kernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inverseTreePairProductWarpStages05Pseudo55)"))
                return false;
            state->mPointwisePseudo55TreeProductWarpSharedConfigured.store(true, std::memory_order_release);
            return true;
        }

        bool configurePointwisePseudo55TreeProductWarpVectorShared(const RingConstView& rc)
        {
            auto* state = rc.mKernelInitialization;
            if (!state) return false;
            if (state->mPointwisePseudo55TreeProductWarpVectorSharedConfigured.load(std::memory_order_acquire)) return true;
            std::unique_lock<std::mutex> lock;
            bool ready = false;
            if (!lockKernelInitialization(*state, state->mPointwisePseudo55TreeProductWarpVectorSharedConfigured, lock, ready)) return false;
            if (ready) return true;
            const size_t bytes =
                static_cast<size_t>(kNttMaxTileLen) * sizeof(u64);
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseTreePairNegateProductWarpStages05VectorPairsPseudo55Kernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inverseTreePairProductWarpStages05VectorPairsPseudo55)"))
                return false;
            state->mPointwisePseudo55TreeProductWarpVectorSharedConfigured.store(true, std::memory_order_release);
            return true;
        }

        bool configurePointwisePseudo55SparseShared(const RingConstView& rc)
        {
            auto* state = rc.mKernelInitialization;
            if (!state) return false;
            if (state->mPointwisePseudo55SparseSharedConfigured.load(std::memory_order_acquire)) return true;
            std::unique_lock<std::mutex> lock;
            bool ready = false;
            if (!lockKernelInitialization(*state, state->mPointwisePseudo55SparseSharedConfigured, lock, ready)) return false;
            if (ready) return true;
            const size_t bytes =
                static_cast<size_t>(kNttMaxTileLen) * sizeof(u64);
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseRecursiveLeafSparseNegateNoZeroPseudo55Kernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(bytes)),
                    "cudaFuncSetAttribute(inverseRecursiveLeafSparsePseudo55)"))
                return false;
            state->mPointwisePseudo55SparseSharedConfigured.store(true, std::memory_order_release);
            return true;
        }

        u32 log2Exact(u32 value)
        {
            u32 bits = 0;
            while ((1u << bits) < value) ++bits;
            return bits;
        }
    }

    // ---- public host API --------------------------------------------------

    bool gpuDeviceAvailable()
    {
        int count = 0;
        if (cudaGetDeviceCount(&count) != cudaSuccess) return false;
        // Note: cudaDeviceScheduleBlockingSync was measured here and is slightly
        // slower (28.5 vs 29.0 M/s at n = 2^24). The ~26% of host cycles that
        // perf attributes to libcuda is the host spin-waiting for the device, not
        // removable overhead: the protocol is a serial request/response chain, so
        // the host genuinely has nothing else to do at those points, and blocking
        // only adds wake-up latency.
        return count > 0;
    }

    std::string gpuDeviceName()
    {
        char name[256]{};
        cudaDeviceProp prop{};
        if (cudaGetDeviceProperties(&prop, 0) != cudaSuccess) return "unknown";
        std::snprintf(name, sizeof(name), "%s (sm_%d%d, %d SMs)", prop.name, prop.major, prop.minor,
                      prop.multiProcessorCount);
        return name;
    }

    bool gpuStreamWaitEvent(void* stream, void* event)
    {
        if (!event) return false;
        return check(
            cudaStreamWaitEvent(asStream(stream), static_cast<cudaEvent_t>(event), 0), "streamWaitEvent");
    }

    bool gpuTryRegisterHost(void* ptr, std::size_t bytes, bool& registered)
    {
        registered = false;
        if (!ptr || !bytes) return false;
        // CUDA registers the supplied byte range, including unaligned wire
        // payloads. Do not widen it to pages outside the caller's allocation.
        const auto error = cudaHostRegister(ptr, bytes, cudaHostRegisterDefault);
        if (error == cudaSuccess)
        {
            registered = true;
            return true;
        }
        if (error == cudaErrorInvalidValue || error == cudaErrorMemoryAllocation ||
            error == cudaErrorHostMemoryAlreadyRegistered || error == cudaErrorNotSupported)
        {
            // Registration is an optional optimization. Clear its own benign
            // error so a later kernel check does not report the declined hint;
            // preserve any unrelated asynchronous CUDA failure.
            const auto pending = cudaPeekAtLastError();
            if (pending == error) (void)cudaGetLastError();
            else if (pending != cudaSuccess) return check(pending, "hostRegister async");
            return true;
        }
        return check(error, "hostRegister");
    }

    bool gpuUnregisterHost(void* ptr)
    {
        return check(cudaHostUnregister(ptr), "hostUnregister");
    }

    bool gpuMemcpyH2D(void* dst, const void* src, std::size_t bytes, void* stream)
    {
        return check(cudaMemcpyAsync(dst, src, bytes, cudaMemcpyHostToDevice, asStream(stream)), "H2D");
    }

    bool gpuMemcpyD2H(void* dst, const void* src, std::size_t bytes, void* stream)
    {
        return check(cudaMemcpyAsync(dst, src, bytes, cudaMemcpyDeviceToHost, asStream(stream)), "D2H");
    }

    bool gpuMemcpyD2D(void* dst, const void* src, std::size_t bytes, void* stream)
    {
        return check(cudaMemcpyAsync(dst, src, bytes, cudaMemcpyDeviceToDevice, asStream(stream)), "D2D");
    }

    bool gpuMemsetZero(void* dst, std::size_t bytes, void* stream)
    {
        return check(cudaMemsetAsync(dst, 0, bytes, asStream(stream)), "memset");
    }

    void* gpuStreamCreate()
    {
        cudaStream_t s = nullptr;
        const auto error = cudaStreamCreate(&s);
        if (error == cudaErrorMemoryAllocation)
        {
            if (cudaPeekAtLastError() == error) (void)cudaGetLastError();
            return nullptr;
        }
        check(error, "streamCreate");
        return s;
    }

    void gpuStreamDestroy(void* stream)
    {
        if (!stream) return;
        cudaStreamDestroy(asStream(stream));
    }

    bool gpuStreamSync(void* stream)
    {
        return check(cudaStreamSynchronize(asStream(stream)), "streamSync");
    }

    void* gpuEventCreate()
    {
        cudaEvent_t e = nullptr;
        const auto error = cudaEventCreateWithFlags(&e, cudaEventDisableTiming);
        if (error == cudaErrorMemoryAllocation)
        {
            if (cudaPeekAtLastError() == error) (void)cudaGetLastError();
            return nullptr;
        }
        check(error, "eventCreate");
        return e;
    }

    void gpuEventDestroy(void* event)
    {
        if (event) cudaEventDestroy(static_cast<cudaEvent_t>(event));
    }

    bool gpuEventRecord(void* event, void* stream)
    {
        return check(
            cudaEventRecord(static_cast<cudaEvent_t>(event), asStream(stream)), "eventRecord");
    }

    bool gpuEventSync(void* event)
    {
        return check(cudaEventSynchronize(static_cast<cudaEvent_t>(event)), "eventSync");
    }

    bool gpuDeviceSync()
    {
        return check(cudaDeviceSynchronize(), "deviceSync");
    }

    bool launchNttForward(
        const RingConstView& rc, u64* data, u32 polyCount, const u32* polyIdx, void* stream)
    {
        if (polyCount == 0) return true;
        if (!configureShared(rc)) return false;
        if (!configureH200RootPersistence(rc, stream, false)) return false;
        const DeviceRing rg = toDevice(rc);
        const u32 tiles = nttTileCount(rc.mN);
        const u32 logTiles = log2Exact(tiles);
        const size_t shBytes = static_cast<size_t>(rc.mN >> logTiles) * sizeof(u64);
        const auto st = asStream(stream);

        // Two ways to spend the crossing stage, and which one wins depends on how
        // much of the device the batch fills.
        //
        // nttForwardTwoTileKernel reads each element once (2n of traffic) but gives
        // one block per (poly, limb). nttForwardKernel recomputes the crossing
        // butterfly per half (3n) and gives two. Measured at 256 polynomials the
        // first is 5% faster; inside the protocol, where most batches are far
        // smaller than the device's SM count, halving the block count costs more than the
        // traffic saves - the whole level ladder came out 6% slower. So the
        // register-parked variant is used only when there are already enough blocks
        // to fill the device twice over.
        if (tiles == 2u && (rc.mN >> 1) == kNttThreads * kInvRegs &&
            polyCount * rc.mRho >= 2u * rc.mSmCount)
        {
            if (log14H200Shape(rc))
            {
                if (rc.mMinModulus > (u64{1} << 51u) &&
                    rc.mMinModulus <= rc.mMaxModulus && rc.mMaxModulus < (u64{1} << 52u))
                {
                    return launchForwardFp52Tail<0u>(rg, data, polyIdx, nullptr, data, polyIdx, polyCount, st);
                }
                if (!check(cudaFuncSetAttribute(
                        nttForwardTwoTile16384Rho8Kernel<true, 512u>,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                        "cudaFuncSetAttribute(forwardLog14Paired512)"))
                    return false;
                nttForwardTwoTile16384Rho8Kernel<true, 512u><<<
                    polyCount * 8u, 512u, shBytes, st>>>(rg, data, polyIdx);
                return check(cudaGetLastError(), "nttForwardLog14Paired");

            }
            if (!check(
                    cudaFuncSetAttribute(
                        nttForwardTwoTileKernel, cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(forwardTwoTile)"))
                return false;
            nttForwardTwoTileKernel<<<polyCount * rc.mRho, kNttThreads, shBytes, st>>>(
                rg, data, polyIdx);
            return check(cudaGetLastError(), "nttForward");
        }

        // The stages that cross tiles come first for the forward transform. An
        // in-place two-tile transform must also launch its crossing stage here:
        // two independent tile CTAs cannot safely read both halves while either
        // CTA may overwrite one of them.
        if (logTiles != 0u)
        {
            for (u32 stage = 0; stage < logTiles; ++stage)
            {
                constexpr u32 threads = 256;
                const u32 half = rc.mN >> 1;
                const dim3 grid((half + threads - 1u) / threads, polyCount * rc.mRho, 1);
                nttForwardCrossKernel<<<grid, threads, 0, st>>>(rg, data, polyIdx, stage);
            }
        }

        if (rc.mN == 8192u && rc.mRho == 4u && tiles == 1u)
        {
            nttForwardWarpStages7128192Rho4Kernel<<<
                polyCount * rc.mRho, kNttThreads, shBytes, st>>>(
                rg, data, polyIdx);


        }
        else
        {
            if (logTiles == 1u)
            {
                nttForwardKernel<
                    false, false, false, false, 0u, false, false, true><<<
                    polyCount * rc.mRho * tiles, 1024u, shBytes, st>>>(
                    rg, data, polyIdx, logTiles, nullptr, nullptr, nullptr);
            }
            else
            {
                nttForwardKernel<false, false, false><<<
                    polyCount * rc.mRho * tiles, 1024u, shBytes, st>>>(
                    rg, data, polyIdx, logTiles, nullptr, nullptr, nullptr);
            }
        }
        return check(cudaGetLastError(), "nttForward");
    }

    bool launchNttForwardGather(
        const RingConstView& rc,
        u64* data,
        u32 polyCount,
        const u32* inverseSlotMap,
        u32 slotCount,
        u64* out,
        u64 outCount,
        void* stream)
    {
        if (polyCount == 0 || outCount == 0) return true;
        if (!data || !inverseSlotMap || !out || rc.mRho != 1u || slotCount != rc.mN ||
            outCount > static_cast<u64>(polyCount) * slotCount || !configureShared(rc))
            return false;

        const u32 tiles = nttTileCount(rc.mN);
        const u32 logTiles = log2Exact(tiles);
        const size_t shBytes = static_cast<size_t>(rc.mN >> logTiles) * sizeof(u64);
        const DeviceRing rg = toDevice(rc);
        const auto st = asStream(stream);

        // For degrees above one shared-memory tile, preserve the exact crossing
        // stages in coefficient storage. The tile-local transform then owns each
        // final coefficient and can scatter it straight to its decoded slot.
        if (logTiles > 1u)
        {
            for (u32 stage = 0; stage < logTiles; ++stage)
            {
                constexpr u32 threads = 256;
                const u32 half = rc.mN >> 1;
                const dim3 grid((half + threads - 1u) / threads, polyCount, 1);
                nttForwardCrossKernel<<<grid, threads, 0, st>>>(rg, data, nullptr, stage);
            }
        }

        if (rc.mN == 8192u && rc.mRho == 1u && tiles == 1u)
        {
            constexpr bool fusedFirstStage = true;
            if (!check(
                    cudaFuncSetAttribute(
                        nttForwardKernel<
                            false, false, true, true, 1u, true, true>,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(forwardGather8192SimpleIndexVectorShoup)"))
                return false;
            nttForwardKernel<
                false, false, true, true, 1u, true, true><<<
                polyCount, 1024u, shBytes, st>>>(
                rg, data, nullptr, 0u, nullptr, nullptr, nullptr,
                inverseSlotMap, slotCount, out, outCount, fusedFirstStage);


        }
        else
        {
            if (!check(
                    cudaFuncSetAttribute(
                        nttForwardKernel<false, false, true>,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(forwardGather)"))
                return false;
            nttForwardKernel<false, false, true><<<
                polyCount * tiles, 1024u, shBytes, st>>>(
                rg, data, nullptr, logTiles, nullptr, nullptr, nullptr,
                inverseSlotMap, slotCount, out, outCount);
        }
        return check(cudaGetLastError(), "nttForwardGather");
    }

    bool launchNttForwardFrom(
        const RingConstView& rc,
        const u64* in,
        const u32* inIdx,
        u64* out,
        const u32* outIdx,
        u32 polyCount,
        void* stream)
    {
        if (polyCount == 0) return true;
        if (!in || !out || !configureShared(rc)) return false;
        const u32 tiles = nttTileCount(rc.mN);
        // The two-tile load recomputes the one crossing stage directly from the
        // immutable source. More than two tiles need separate in-place crossing
        // launches and retain the materialized fallback.
        if (tiles > 2u) return false;
        const DeviceRing rg = toDevice(rc);
        const u32 logTiles = log2Exact(tiles);
        const size_t shBytes = static_cast<size_t>(rc.mN >> logTiles) * sizeof(u64);
        if (rc.mN == 8192u && rc.mRho == 4u && tiles == 1u)
        {
            constexpr bool fusedFirstStage = true;
            if (!check(
                    cudaFuncSetAttribute(
                        nttForwardKernel<
                            true, false, false, true, 4u, true, true>,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(forwardFrom8192SimpleIndexVectorShoup)"))
                return false;
            nttForwardKernel<
                true, false, false, true, 4u, true, true><<<
                polyCount * rc.mRho, 1024u, shBytes,
                asStream(stream)>>>(
                rg, out, outIdx, 0u, in, inIdx, nullptr,
                nullptr, 0u, nullptr, 0u, fusedFirstStage);


        }
        else
        {
            if (!check(
                    cudaFuncSetAttribute(
                        nttForwardKernel<true, false, false>,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(forwardFrom)"))
                return false;
            nttForwardKernel<true, false, false><<<
                polyCount * rc.mRho * tiles, 1024u, shBytes, asStream(stream)>>>(
                rg, out, outIdx, logTiles, in, inIdx, nullptr);
        }
        return check(cudaGetLastError(), "nttForwardFrom");
    }

    bool canLaunchNttForwardFromPlainBroadcast(const RingConstView& rc)
    {
        if (!rc.mMods || !rc.mRoots)
            return false;
        if (log14H200Shape(rc)) return true;
        return rc.mN == 8192u && rc.mLogN == 13u && rc.mRho == 4u;
    }

    bool launchNttForwardFromPlainBroadcast(
        const RingConstView& rc,
        const u64* in,
        const u32* inIdx,
        u64* out,
        const u32* outIdx,
        u32 polyCount,
        void* stream)
    {
        if (polyCount == 0u) return true;
        if (!canLaunchNttForwardFromPlainBroadcast(rc) || !in || !out ||
            !configureShared(rc))
            return false;
        if (!configureH200RootPersistence(rc, stream, false)) return false;

        const size_t shBytes = static_cast<size_t>(
            rc.mN == 16384u ? 8192u : rc.mN) * sizeof(u64);
        if (log14H200Shape(rc))
        {
            if (in != out &&
                polyCount * rc.mRho >= 2u * rc.mSmCount &&
                rc.mMinModulus > (u64{1} << 51u) && rc.mMinModulus <= rc.mMaxModulus &&
                rc.mMaxModulus < (u64{1} << 52u))
            {
                return launchForwardFp52Tail<1u>(toDevice(rc), in, inIdx, nullptr, out, outIdx, polyCount, asStream(stream));
            }
            if (polyCount * rc.mRho >= 2u * rc.mSmCount)
            {
                if (!check(cudaFuncSetAttribute(
                        nttForwardFromPlainBroadcast16384Rho8Kernel<true, 512u>,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                        "cudaFuncSetAttribute(forwardPlainLog14Paired512)"))
                    return false;
                nttForwardFromPlainBroadcast16384Rho8Kernel<true, 512u><<<
                    polyCount * 8u, 512u, shBytes, asStream(stream)>>>(
                    toDevice(rc), in, inIdx, out, outIdx);
                return check(cudaGetLastError(), "nttForwardPlainLog14Paired");
            }
            if (!check(
                    cudaFuncSetAttribute(
                        nttForwardFromPlainBroadcast16384Rho8Kernel<>,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(forwardFromPlainBroadcast16384Rho8Warp712)"))
                return false;
            nttForwardFromPlainBroadcast16384Rho8Kernel<><<<
                polyCount * 8u, kNttThreads, shBytes,
                asStream(stream)>>>(
                toDevice(rc), in, inIdx, out, outIdx);

            return check(
                cudaGetLastError(),
                "nttForwardFromPlainBroadcast16384Rho8");
        }

        nttForwardFromPlainBroadcastWarpStages7128192Rho4Kernel<<<
            polyCount * 4u, kNttThreads, shBytes, asStream(stream)>>>(
            toDevice(rc), in, inIdx, out, outIdx);
        return check(cudaGetLastError(), "nttForwardFromPlainBroadcastWarpStages712");
    }


    bool launchNttForwardCenteredLimbFrom(
        const RingConstView& rc,
        const u64* in,
        const u32* inIdx,
        const u32* limbSel,
        u64* out,
        const u32* outIdx,
        u32 polyCount,
        void* stream)
    {
        if (polyCount == 0) return true;
        if (!in || !limbSel || !out || !configureShared(rc)) return false;
        if (!configureH200RootPersistence(rc, stream, false)) return false;
        const u32 tiles = nttTileCount(rc.mN);
        if (tiles > 2u) return false;
        const DeviceRing rg = toDevice(rc);
        const u32 logTiles = log2Exact(tiles);
        const size_t shBytes = static_cast<size_t>(rc.mN >> logTiles) * sizeof(u64);
        if (rc.mN == 8192u && rc.mRho == 4u && tiles == 1u)
        {
            constexpr bool fusedFirstStage = true;
            nttForwardCenteredLimbFromWarpStages7128192Rho4Kernel<<<
                polyCount * rc.mRho, kNttThreads, shBytes,
                asStream(stream)>>>(
                rg, in, inIdx, limbSel, out, outIdx);




        }
        else if (log14H200Shape(rc) &&
            in != out &&
            polyCount * rc.mRho >= 2u * rc.mSmCount)
        {
            if (rc.mMinModulus > (u64{1} << 51u) && rc.mMinModulus <= rc.mMaxModulus &&
                rc.mMaxModulus < (u64{1} << 52u))
            {
                return launchForwardFp52Tail<2u>(rg, in, inIdx, limbSel, out, outIdx, polyCount, asStream(stream));
            }
            if (!check(cudaFuncSetAttribute(
                    nttForwardCenteredLimbFrom16384Rho8Kernel<true, 512u>,
                    cudaFuncAttributeMaxDynamicSharedMemorySize,
                    static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(forwardCenteredLog14Paired512)"))
                return false;
            nttForwardCenteredLimbFrom16384Rho8Kernel<true, 512u><<<
                polyCount * 8u, 512u, shBytes, asStream(stream)>>>(
                rg, in, inIdx, limbSel, out, outIdx);
            return check(cudaGetLastError(), "nttForwardCenteredLog14Paired");

        }
        else
        {
            if (!check(
                    cudaFuncSetAttribute(
                        nttForwardKernel<true, true, false>,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(forwardCenteredLimbFrom)"))
                return false;
            nttForwardKernel<true, true, false><<<
                polyCount * rc.mRho * tiles, 1024u, shBytes,
                asStream(stream)>>>(
                rg, out, outIdx, logTiles, in, inIdx, limbSel);

        }
        return check(cudaGetLastError(), "nttForwardCenteredLimbFrom");
    }






    bool launchNttInverse(
        const RingConstView& rc, u64* data, u32 polyCount, const u32* polyIdx, void* stream)
    {
        return launchNttInverseFused(
            rc, data, polyCount, polyIdx, kElemOpNoneHost, nullptr, kElemOpNoneHost, nullptr, stream);
    }


    bool canLaunchNttInverseScatterBroadcast(
        const RingConstView& plainRc, const RingConstView& ringRc)
    {
        return plainRc.mN >= 2u && plainRc.mRho == 1u &&
               (nttTileCount(plainRc.mN) == 1u || log14H200Shape(ringRc)) &&
               ringRc.mN == plainRc.mN &&
               ringRc.mRho != 0u && plainRc.mMods && plainRc.mInvRoots &&
               plainRc.mInvDegree && plainRc.mScaledInvRoot;
    }

    bool launchNttInverseScatterBroadcast(
        const RingConstView& plainRc,
        const RingConstView& ringRc,
        const u64* labels,
        u64 labelCount,
        u64 padValue,
        const u32* inverseSlotMap,
        u32 chunkCount,
        u64* out,
        void* stream,
        bool garbledInput)
    {
        if (chunkCount == 0u) return true;
        if (!canLaunchNttInverseScatterBroadcast(plainRc, ringRc) || !labels ||
            !inverseSlotMap || !out ||
            labelCount > static_cast<u64>(chunkCount) * plainRc.mN ||
            !configureShared(plainRc))
            return false;

        const size_t shBytes = static_cast<size_t>(plainRc.mN) * sizeof(u64);
        if (plainRc.mN == 8192u &&
            plainRc.mLogN == 13u && ringRc.mRho == 4u)
        {
            const DeviceInverseRho4 iv = toDeviceInverseRho4(plainRc);
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseScatterBroadcast8192Rho4Kernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(inverseScatterBroadcast8192Rho4SimpleIndex)"))
                return false;
            nttInverseScatterBroadcast8192Rho4Kernel<<<
                chunkCount, kNttThreads, shBytes, asStream(stream)>>>(
                iv, labels, labelCount, padValue, inverseSlotMap, out, garbledInput);

            return check(cudaGetLastError(), "nttInverseScatterBroadcast8192Rho4");
        }

        if (!check(
                cudaFuncSetAttribute(
                    nttInverseScatterBroadcastKernel,
                    cudaFuncAttributeMaxDynamicSharedMemorySize,
                    static_cast<int>(shBytes)),
                "cudaFuncSetAttribute(inverseScatterBroadcast)"))
            return false;

        nttInverseScatterBroadcastKernel<<<
            chunkCount, 1024u, shBytes, asStream(stream)>>>(
            toDevice(plainRc), labels, labelCount, padValue, inverseSlotMap,
            ringRc.mRho, ringRc.mRho, out, garbledInput);
        return check(cudaGetLastError(), "nttInverseScatterBroadcast");
    }

    bool canLaunchNttInverseScatterSingleLimb(
        const RingConstView& plainRc, const RingConstView& ringRc)
    {
        if (!canLaunchNttInverseScatterBroadcast(plainRc, ringRc) ||
            !canLaunchNttForwardFromPlainBroadcast(ringRc))
            return false;
        if (log14H200Shape(ringRc))
            return plainRc.mN == 16384u && plainRc.mLogN == 14u;
        return plainRc.mN == 8192u && plainRc.mLogN == 13u &&
               ringRc.mN == 8192u && ringRc.mLogN == 13u &&
               ringRc.mRho == 4u;
    }

    bool launchNttInverseScatterSingleLimb(
        const RingConstView& plainRc,
        const RingConstView& ringRc,
        const u64* labels,
        u64 labelCount,
        u64 padValue,
        const u32* inverseSlotMap,
        u32 chunkCount,
        u64* out,
        void* stream,
        bool garbledInput)
    {
        if (chunkCount == 0u) return true;
        if (!canLaunchNttInverseScatterSingleLimb(plainRc, ringRc) ||
            !labels || !inverseSlotMap || !out ||
            labelCount > static_cast<u64>(chunkCount) * plainRc.mN ||
            !configureShared(plainRc))
            return false;

        const size_t shBytes = static_cast<size_t>(plainRc.mN) * sizeof(u64);
        if (log14H200Shape(ringRc))
        {
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseScatterBroadcastKernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(inverseScatterSingleLimb16384Rho8)"))
                return false;
            nttInverseScatterBroadcastKernel<<<
                chunkCount, kNttThreads, shBytes, asStream(stream)>>>(
                toDevice(plainRc), labels, labelCount, padValue,
                inverseSlotMap, ringRc.mRho, 1u, out, garbledInput);
            return check(
                cudaGetLastError(),
                "nttInverseScatterSingleLimb16384Rho8");
        }

        if (!check(
                cudaFuncSetAttribute(
                    nttInverseScatterSingleLimb8192Rho4Kernel,
                    cudaFuncAttributeMaxDynamicSharedMemorySize,
                    static_cast<int>(shBytes)),
                "cudaFuncSetAttribute(inverseScatterSingleLimb8192Rho4)"))
            return false;
        nttInverseScatterSingleLimb8192Rho4Kernel<<<
            chunkCount, kNttThreads, shBytes, asStream(stream)>>>(
            toDeviceInverseRho4(plainRc), labels, labelCount, padValue,
            inverseSlotMap, out, garbledInput);
        return check(
            cudaGetLastError(), "nttInverseScatterSingleLimb8192Rho4");
    }

    bool launchMaterializePlainBroadcast(
        const RingConstView& rc, u64* data, u32 polyCount, void* stream)
    {
        if (polyCount == 0u) return true;
        if (!data || rc.mN == 0u || rc.mRho == 0u) return false;
        constexpr u32 threads = 256u;
        const u64 count = static_cast<u64>(polyCount) * rc.mN;
        const u64 blocks = (count + threads - 1u) / threads;
        if (blocks > std::numeric_limits<u32>::max()) return false;
        materializePlainBroadcastKernel<<<
            static_cast<u32>(blocks), threads, 0, asStream(stream)>>>(
            data, polyCount, rc.mN, rc.mRho);
        return check(cudaGetLastError(), "materializePlainBroadcast");
    }

    bool launchNttInverseFused(
        const RingConstView& rc,
        u64* data,
        u32 polyCount,
        const u32* polyIdx,
        u32 preOp,
        const u64* preB,
        u32 postOp,
        const u64* postB,
        void* stream,
        const NttFusedIp& ip)
    {
        return launchNttInverseFused(
            rc, data, polyCount, polyIdx, preOp, preB, postOp, postB,
            stream, ip, false);
    }

    bool launchNttInverseFused(
        const RingConstView& rc,
        u64* data,
        u32 polyCount,
        const u32* polyIdx,
        u32 preOp,
        const u64* preB,
        u32 postOp,
        const u64* postB,
        void* stream,
        const NttFusedIp& ip,
        bool alphaIsTwo)
    {
        if (polyCount == 0) return true;
        if (!configureShared(rc)) return false;
        if (!configureH200RootPersistence(rc, stream, true)) return false;
        const DeviceRing rg = toDevice(rc);
        const u32 tiles = nttTileCount(rc.mN);
        const u32 logTiles = log2Exact(tiles);
        const u32 logTileLen = rc.mLogN - logTiles;
        const size_t shBytes = static_cast<size_t>(rc.mN >> logTiles) * sizeof(u64);
        const auto st = asStream(stream);

        // Two tiles is the case the register-parked variant was written for, and it
        // is the only one the ring degrees in use reach (tiles = n / 8192).
        const bool narrowFp1024 = polyCount * rc.mRho >= 64u &&
            ip.mTerms == 0u && log14H200Shape(rc) &&
            rc.mMinModulus > (u64{1} << 51u) && rc.mMinModulus <= rc.mMaxModulus &&
            rc.mMaxModulus < (u64{1} << 52u);
        if (tiles == 2u && (rc.mN >> 1) == kNttThreads * kInvRegs &&
            (polyCount * rc.mRho >= (2u * rc.mSmCount) || narrowFp1024))
        {
            if (ip.mTerms == 0u && log14H200Shape(rc))
            {
                if (rc.mMinModulus > (u64{1} << 51u) &&
                    rc.mMinModulus <= rc.mMaxModulus && rc.mMaxModulus < (u64{1} << 52u))
                {
                    if (polyCount * rc.mRho < (2u * rc.mSmCount))
                    {
                        const auto launch1024 = [&](auto packed) {
                            constexpr bool p = decltype(packed)::value;
                            constexpr int bytes = 16384u * sizeof(double);
                            if (!check(cudaFuncSetAttribute(nttInverseTwoTile16384Rho8Fp52Kernel<1u, p, 1024u>,
                                    cudaFuncAttributeMaxDynamicSharedMemorySize, bytes), "inverse FP52 tile1024 shared"))
                                return false;
                            nttInverseTwoTile16384Rho8Fp52Kernel<1u, p, 1024u><<<polyCount * 8u, 1024u, bytes, st>>>(
                                rg, data, polyIdx, preOp, preB, postOp, postB, rc.mFp52InvRoots);
                            return check(cudaGetLastError(), "inverse FP52 tile1024");
                        };
                        return rc.mFp52InvRoots ? launch1024(std::true_type{}) : launch1024(std::false_type{});
                    }
                    constexpr int bytes = 12288u * sizeof(double);
                    if (rc.mFp52InvRoots)
                    {
                        if (rc.mKernelOptions.mNoGoldH200InverseOpTrace)
                            std::fprintf(stderr, "[inverse-ops] polys=%u pre=%u post=%u indexed=%u\n",
                                polyCount, preOp, postOp, polyIdx ? 1u : 0u);
                        if (!check(cudaFuncSetAttribute(nttInverseTwoTile16384Rho8Fp52Kernel<2u, true, 512u, true>,
                                cudaFuncAttributeMaxDynamicSharedMemorySize, bytes), "inverse FP52 prefix shared"))
                            return false;
                        nttInverseTwoTile16384Rho8Fp52Kernel<2u, true, 512u, true><<<polyCount * 8u, 512u, bytes, st>>>(
                            rg, data, polyIdx, preOp, preB, postOp, postB, rc.mFp52InvRoots);
                        return check(cudaGetLastError(), "inverse FP52 prefix");
                    }
                    if (!check(cudaFuncSetAttribute(nttInverseTwoTile16384Rho8Fp52Kernel<2u, false, 512u>,
                            cudaFuncAttributeMaxDynamicSharedMemorySize, bytes), "inverse FP52 two-tile shared"))
                        return false;
                    nttInverseTwoTile16384Rho8Fp52Kernel<2u, false, 512u><<<polyCount * 8u, 512u, bytes, st>>>(
                        rg, data, polyIdx, preOp, preB, postOp, postB);
                    return check(cudaGetLastError(), "inverse FP52 two-tile");
                }
                // The direct prefix uses 128-bit input loads. Unaligned
                // caller-owned arrays retain the scalar shared-input path.
                const bool alignedInputs =
                    (reinterpret_cast<size_t>(data) & 15u) == 0u &&
                    (preOp == kElemOpNone ||
                     (reinterpret_cast<size_t>(preB) & 15u) == 0u);
                if (alignedInputs)
                {
                    if (!check(cudaFuncSetAttribute(nttInverseTwoTile16384Rho8Kernel<true>,
                            cudaFuncAttributeMaxDynamicSharedMemorySize, static_cast<int>(shBytes)),
                            "cudaFuncSetAttribute(inverseLog14PairedSuffix)"))
                        return false;
                    nttInverseTwoTile16384Rho8Kernel<true><<<polyCount * 8u, 512u, shBytes, st>>>(
                        rg, data, polyIdx, preOp, preB, postOp, postB);
                    return check(cudaGetLastError(), "nttInverseLog14PairedSuffix");
                }
                if (!check(cudaFuncSetAttribute(nttInverseTwoTile16384Rho8Kernel<false>,
                        cudaFuncAttributeMaxDynamicSharedMemorySize, static_cast<int>(shBytes)),
                        "cudaFuncSetAttribute(inverseTwoTile16384Rho8x512Warp05)"))
                    return false;
                nttInverseTwoTile16384Rho8Kernel<false><<<polyCount * 8u, 512u, shBytes, st>>>(
                    rg, data, polyIdx, preOp, preB, postOp, postB);
                return check(
                    cudaGetLastError(), "nttInverseTwoTile16384Rho8");
            }
            if (!check(
                    cudaFuncSetAttribute(
                        nttInverseTwoTileKernel, cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(inverseTwoTile)"))
                return false;
            nttInverseTwoTileKernel<<<polyCount * rc.mRho, kNttThreads, shBytes, st>>>(
                rg, data, polyIdx, preOp, preB, postOp, postB, ip);
            return check(cudaGetLastError(), "nttInverse");
        }

        if (ip.mTerms != 0)
        {
            nttInverseKernel<true><<<
                polyCount * rc.mRho * tiles, 1024u, shBytes, st>>>(
                rg, data, polyIdx, preOp, preB, postOp, postB, ip, logTiles);
        }
        else
        {
            const u64 blocks = static_cast<u64>(polyCount) * rc.mRho;
            const bool fixedGeometry =
                rc.mN == 8192u &&
                rc.mRho == 4u && tiles == 1u;
            constexpr bool fusedFirstStage = true;
            const bool postWarpStages05 = alphaIsTwo;
            if (fixedGeometry && blocks >= 256u)
            {
                const bool direct =
                    preOp == kElemOpNoneHost;
                if (direct && postOp == static_cast<u32>(ElemOp::Add))
                {
                    if (postWarpStages05)
                    {
                        if (!configureNttInversePostWarpStages05Shared(rc))
                            return false;
                        nttInversePostWarpStages05Add8192Rho4Kernel<<<
                            polyCount * 4u, 512u, shBytes, st>>>(
                            toDeviceInverseRho4(rc), data, polyIdx, postB);
                    }
                    else
                    {
                        nttInverseFusedLastThree8192Rho4PostKernel<0u><<<
                            polyCount * 4u, 512u, shBytes, st>>>(
                            toDeviceInverseRho4(rc), data, polyIdx, postB);
                    }
                }
                else if (direct && postOp == static_cast<u32>(ElemOp::Negate))
                {
                    if (postWarpStages05)
                    {
                        if (!configureNttInversePostWarpStages05Shared(rc))
                            return false;
                        nttInversePostWarpStages05Negate8192Rho4Kernel<<<
                            polyCount * 4u, 512u, shBytes, st>>>(
                            toDeviceInverseRho4(rc), data, polyIdx, nullptr);
                    }
                    else
                    {
                        nttInverseFusedLastThree8192Rho4PostKernel<2u><<<
                            polyCount * 4u, 512u, shBytes, st>>>(
                            toDeviceInverseRho4(rc), data, polyIdx, nullptr);
                    }
                }
                else if (direct && postOp == static_cast<u32>(ElemOp::ReverseSub))
                {
                    if (postWarpStages05)
                    {
                        if (!configureNttInversePostWarpStages05Shared(rc))
                            return false;
                        nttInversePostWarpStages05ReverseSub8192Rho4Kernel<<<
                            polyCount * 4u, 512u, shBytes, st>>>(
                            toDeviceInverseRho4(rc), data, polyIdx, postB);
                    }
                    else
                    {
                        nttInverseFusedLastThree8192Rho4ReverseSubKernel<<<
                            polyCount * 4u, 512u, shBytes, st>>>(
                            toDeviceInverseRho4(rc), data, polyIdx, postB);
                    }
                }
                else
                {
                    nttInverseFixed8192Kernel<4u, true><<<
                        polyCount * rc.mRho, 512u, shBytes, st>>>(
                        rg, data, polyIdx, preOp, preB, postOp, postB, ip, 0u,
                        fusedFirstStage);
                }

            }
            else
            {
                nttInverseKernel<false><<<
                    polyCount * rc.mRho * tiles, 1024u, shBytes, st>>>(
                    rg, data, polyIdx, preOp, preB, postOp, postB, ip, logTiles);
            }
        }

        if (tiles != 1u)
        {
            // The tail of the transform, in global memory: the stages whose gap
            // spans more than one tile, then the m = 1 stage that carries the 1/n
            // scalar and the fused post-operation.
            constexpr u32 threads = 256;
            const u32 half = rc.mN >> 1;
            const dim3 grid((half + threads - 1u) / threads, polyCount * rc.mRho, 1);
            for (u32 stage = logTileLen; stage + 1u < rc.mLogN; ++stage)
            {
                nttInverseCrossKernel<<<grid, threads, 0, st>>>(rg, data, polyIdx, stage);
            }
            nttInverseFinalKernel<<<grid, threads, 0, st>>>(rg, data, polyIdx, postOp, postB);
        }
        return check(cudaGetLastError(), "nttInverse");
    }

    namespace
    {
        bool pointwisePseudo55ShapeEligible(const RingConstView& rc)
        {
            constexpr u64 kRadix55 = u64{ 1 } << 55u;
            constexpr u64 kMaxComplement = u64{ 1 } << 21u;
            return rc.mN == 8192u && rc.mLogN == 13u && rc.mRho == 4u &&
                rc.mMods && rc.mMinModulus > kRadix55 - kMaxComplement &&
                rc.mMaxModulus < kRadix55 &&
                rc.mMinModulus <= rc.mMaxModulus;
        }

        bool pointwisePseudo55ProductionEligible(const RingConstView& rc)
        {
            return rc.mKernelOptions.mPointwisePseudo55Reduce &&
                pointwisePseudo55ShapeEligible(rc);
        }

        bool expandAccumulatorGoldenPseudo55StructuralEligible(
            const RingConstView& rc,
            u32 mu,
            u32 treeTerms,
            u32 outCount)
        {
            return mu == 8u && treeTerms == 6u &&
                pointwisePseudo55ShapeEligible(rc) && outCount != 0u &&
                outCount <= 65535u && (outCount % 8u) == 0u;
        }


        bool expandAccumulatorWideTuple(u32 mu, u32 treeTerms)
        {
            return
                (mu == 16u && treeTerms == 8u) ||
                (mu == 32u && treeTerms == 10u) ||
                (mu == 64u && treeTerms == 12u) ||
                (mu == 128u && treeTerms == 14u);
        }

        bool expandAccumulatorWideStructuralEligible(
            const RingConstView& rc,
            u32 mu,
            u32 treeTerms,
            u32 outCount)
        {
            return expandAccumulatorWideTuple(mu, treeTerms) &&
                pointwisePseudo55ShapeEligible(rc) && outCount != 0u &&
                outCount <= 65535u && (outCount % mu) == 0u &&
                (rc.mN % 256u) == 0u;
        }

        bool expandAccumulatorNoGoldH200StructuralEligible(
            const RingConstView& rc,
            u32 mu,
            u32 treeTerms,
            u32 outCount)
        {
            return log14H200Shape(rc) && mu == 16u && treeTerms == 8u &&
                outCount != 0u && outCount <= 65535u &&
                (outCount % 16u) == 0u && rc.mMods &&
                rc.mMinModulus != 0u &&
                rc.mMinModulus <= rc.mMaxModulus &&
                rc.mMaxModulus < (u64{ 1 } << 60u);
        }

        bool launchExpandAccumulatorTau1NoGoldH200Impl(
            const RingConstView& rc,
            const u64* ct1,
            const u64* uDigits,
            const u64* publicA,
            const u64* skNtt,
            const u64* lacct,
            const u64* nodes,
            const u32* lacctAIdx,
            const u32* lacctBIdx,
            u64* out,
            u32 outCount,
            void* stream)
        {
            constexpr u32 kMu = 16u;
            constexpr u32 kRho = 8u;
            constexpr u32 kThreads = 256u;
            const u32 chunks = outCount / kMu;
            const u64 rowLimbPlanes =
                static_cast<u64>(kMu) * kRho * chunks;
            const u64 rawTileBlocks = 2048u / rowLimbPlanes;
            const u32 automaticTileBlocks = rawTileBlocks == 0u
                ? 1u
                : (rawTileBlocks > 64u
                       ? 64u
                       : static_cast<u32>(rawTileBlocks));
            const dim3 grid(automaticTileBlocks, kMu * kRho, chunks);
            constexpr u64 kRadix52 = u64{ 1 } << 52u;
            const bool pseudo52 =
                                rc.mMaxModulus < kRadix52 &&
                rc.mMinModulus > kRadix52 - (u64{ 1 } << 24u);
            if (pseudo52)
            {
                expandAccumulatorTau1NoGoldH200PackedKernel<<<
                    grid, kThreads, 0u, asStream(stream)>>>(
                    toDevice(rc), ct1, uDigits, publicA, skNtt, lacct,
                    nodes, lacctAIdx, lacctBIdx, out);
                return check(cudaGetLastError(), "expandAccumulatorTau1NoGoldH200Load");
            }
            else
            {
                expandAccumulatorTau1NoGoldH200Kernel<<<
                    grid, kThreads, 0u, asStream(stream)>>>(
                    toDevice(rc), ct1, uDigits, publicA, skNtt, lacct,
                    nodes, lacctAIdx, lacctBIdx, out);
            }
            return check(
                cudaGetLastError(),
                pseudo52
                    ? "expandAccumulatorTau1NoGoldH200Pseudo52"
                    : "expandAccumulatorTau1NoGoldH200");
        }

        template<u32 Mu, u32 TreeTerms>
        bool launchExpandAccumulatorTau1WidePseudo55DualPackedPairsImpl(
            const RingConstView& rc,
            const u64* ct1,
            const u64* uDigits,
            const u64* publicA,
            const u64* skNtt,
            const u64* lacct,
            const u64* nodes,
            const u32* lacctAIdx,
            const u32* lacctBIdx,
            u64* out,
            u32 outCount,
            void* stream)
        {
            static_assert(
                (Mu == 16u && TreeTerms == 8u) ||
                (Mu == 32u && TreeTerms == 10u) ||
                (Mu == 64u && TreeTerms == 12u) ||
                (Mu == 128u && TreeTerms == 14u));
            constexpr u32 kThreads = 256u;
            const u32 chunks = outCount / Mu;
            const u64 rowLimbPlanes =
                static_cast<u64>(Mu) * 4u * chunks;
            const u64 rawTileBlocks = 1024u / rowLimbPlanes;
            const u32 tileBlocks = rawTileBlocks == 0u
                ? 1u
                : (rawTileBlocks > 32u
                       ? 32u
                       : static_cast<u32>(rawTileBlocks));
            const dim3 grid(tileBlocks, Mu * 4u, chunks);
            expandAccumulatorTau1WidePseudo55DualPackedPairsKernel<
                Mu, TreeTerms><<<
                    grid, kThreads, 0u, asStream(stream)>>>(
                toDevice(rc), ct1, uDigits, publicA, skNtt, lacct, nodes,
                lacctAIdx, lacctBIdx, out);
            return check(
                cudaGetLastError(),
                "expandAccumulatorTau1WidePseudo55DualPackedPairs");
        }

        bool innerProductOuterWideMuStructuralEligible(
            const RingConstView& rc,
            u32 mu,
            u32 chunkCount)
        {
            return (mu == 32u || mu == 64u || mu == 128u) &&
                pointwisePseudo55ShapeEligible(rc) && chunkCount >= 8u &&
                chunkCount <= 65535u;
        }

        template<u32 Mu>
        bool launchInnerProductOuterWideMuRowReusePseudo55Impl(
            const RingConstView& rc,
            const u64* publicA,
            const u64* skNtt,
            u64* out,
            u32 chunkCount,
            void* stream)
        {
            static_assert(Mu == 32u || Mu == 64u || Mu == 128u);
            const dim3 grid(32u, 4u, chunkCount);
            innerProductOuterWideMuRowReusePseudo55Kernel<Mu><<<
                grid, 256u, 0u, asStream(stream)>>>(
                toDevice(rc), publicA, skNtt, out);
            return check(
                cudaGetLastError(),
                "innerProductOuterWideMuRowReusePseudo55");
        }


        bool fixedIpInverseEligible(const RingConstView& rc, u32 outCount)
        {
            const u64 blocks = static_cast<u64>(outCount) * 4u;
            return rc.mN == 8192u && rc.mLogN == 13u && rc.mRho == 4u &&
                rc.mMods && rc.mInvRoots && rc.mInvDegree && rc.mScaledInvRoot &&
                outCount != 0u && blocks >= 256u &&
                blocks <= 0x7fffffffu;
        }
    }

    bool canLaunchExpandAccumulatorTau1(
        const RingConstView& rc,
        u32 mu,
        u32 treeTerms,
        u32 outCount)
    {
        if (mu == 0u || outCount == 0u || outCount > 65535u ||
            (rc.mN % 256u) != 0u)
        {
            return false;
        }

        // Preserve the pre-existing runtime-geometry fallback for every
        // six-term tau=1 shape, including non-Golden rings and mu values other
        // than eight. Wider layouts have no safe runtime-stride fallback here.
        if (treeTerms == 6u) return true;

        if (expandAccumulatorNoGoldH200StructuralEligible(
                rc, mu, treeTerms, outCount))
        {
            return true;
        }

        return expandAccumulatorWideStructuralEligible(
                rc, mu, treeTerms, outCount);
    }


    bool tryLaunchInnerProductOuterMuRowReuse(
        const RingConstView& rc,
        const u64* publicA,
        const u64* skNtt,
        u64* out,
        u32 mu,
        u32 chunkCount,
        void* stream,
        bool& launched)
    {
        launched = false;
        if (!rc.mKernelOptions.mFixedIpMuRowReuse || (mu != 8u && mu != 16u) ||
            rc.mN != 8192u || rc.mLogN != 13u || rc.mRho != 4u || !rc.mMods ||
            chunkCount < 8u || chunkCount > 65535u ||
            !publicA || !skNtt || !out || publicA == skNtt ||
            out == publicA || out == skNtt)
        {
            return true;
        }

        const dim3 grid(32u, 4u, chunkCount);
        const bool usePseudo55 =
            pointwisePseudo55ProductionEligible(rc);
        if (mu == 8u)
        {
            if (usePseudo55)
                innerProductOuterMuRowReusePseudo55Kernel<8u><<<
                    grid, 256u, 0u, asStream(stream)>>>(
                    toDevice(rc), publicA, skNtt, out);
            else
                innerProductOuterMuRowReuseKernel<8u><<<
                    grid, 256u, 0u, asStream(stream)>>>(
                    toDevice(rc), publicA, skNtt, out);
        }
        else
        {
            if (usePseudo55)
                innerProductOuterMuRowReusePseudo55Kernel<16u><<<
                    grid, 256u, 0u, asStream(stream)>>>(
                    toDevice(rc), publicA, skNtt, out);
            else
                innerProductOuterMuRowReuseKernel<16u><<<
                    grid, 256u, 0u, asStream(stream)>>>(
                    toDevice(rc), publicA, skNtt, out);
        }
        launched = true;
        return check(
            cudaGetLastError(),
            usePseudo55 ? "innerProductOuterMuRowReusePseudo55" :
                          "innerProductOuterMuRowReuse");
    }

    bool tryLaunchInnerProductOuterWideMuRowReuse(
        const RingConstView& rc,
        const u64* publicA,
        const u64* skNtt,
        u64* out,
        u32 mu,
        u32 chunkCount,
        void* stream,
        bool& launched)
    {
        launched = false;
        if (!rc.mKernelOptions.mFixedIpWideMuRowReuse ||
            !pointwisePseudo55ProductionEligible(rc) ||
            !innerProductOuterWideMuStructuralEligible(rc, mu, chunkCount) ||
            !publicA || !skNtt || !out || publicA == skNtt ||
            out == publicA || out == skNtt)
        {
            return true;
        }

        launched = true;
        if (mu == 32u)
            return launchInnerProductOuterWideMuRowReusePseudo55Impl<32u>(
                rc, publicA, skNtt, out, chunkCount, stream);
        if (mu == 64u)
            return launchInnerProductOuterWideMuRowReusePseudo55Impl<64u>(
                rc, publicA, skNtt, out, chunkCount, stream);
        return launchInnerProductOuterWideMuRowReusePseudo55Impl<128u>(
            rc, publicA, skNtt, out, chunkCount, stream);
    }


    bool tryLaunchNttInverseTreePairNegate(
        const RingConstView& rc,
        u64* out,
        const u64* publicB,
        const u64* nodes,
        u32 outCount,
        u32 depth,
        u32 nodeCount,
        u32 publicCol,
        void* stream,
        bool& launched)
    {
        return tryLaunchNttInverseTreePairNegate(
            rc, out, publicB, nodes, outCount, depth, nodeCount, publicCol,
            stream, launched, false);
    }

    bool tryLaunchNttInverseTreePairNegate(
        const RingConstView& rc,
        u64* out,
        const u64* publicB,
        const u64* nodes,
        u32 outCount,
        u32 depth,
        u32 nodeCount,
        u32 publicCol,
        void* stream,
        bool& launched,
        bool alphaIsTwo)
    {
        launched = false;
        if (!fixedIpInverseEligible(rc, outCount) || !out || !publicB || !nodes ||
            out == publicB || out == nodes || depth >= 30u || publicCol > 1u)
            return true;

        const u32 nodesAtDepth = 1u << depth;
        const u64 requiredNodes = 4ull * nodesAtDepth - 1ull;
        if ((outCount % nodesAtDepth) != 0u || nodeCount < requiredNodes)
            return true;
        if (!configureShared(rc)) return false;

        const u32 blocks = outCount * 4u;
        const size_t shBytes = static_cast<size_t>(8192u) * sizeof(u64);
        const DeviceInverseRho4 iv = toDeviceInverseRho4(rc);
        const bool usePseudo55 = pointwisePseudo55ProductionEligible(rc);
        if (usePseudo55)
        {
            if (alphaIsTwo)
            {
                const bool vectorPairAligned =
                    ((reinterpret_cast<std::uintptr_t>(publicB) |
                      reinterpret_cast<std::uintptr_t>(nodes)) & 15u) == 0u;
                if (vectorPairAligned)
                {
                    if (!configurePointwisePseudo55TreeProductWarpVectorShared(rc))
                        return false;
                    nttInverseTreePairNegateProductWarpStages05VectorPairsPseudo55Kernel<<<
                        blocks, 512u, shBytes, asStream(stream)>>>(
                        iv, out, publicB, nodes, depth, nodeCount, publicCol);
                    launched = true;
                    return check(cudaGetLastError(),
                        "nttInverseTreePairNegateProductWarpStages05VectorPairsPseudo55");
                }
                if (!configurePointwisePseudo55TreeProductWarpShared(rc))
                    return false;
                nttInverseTreePairNegateProductWarpStages05Pseudo55Kernel<<<
                    blocks, 512u, shBytes, asStream(stream)>>>(
                    iv, out, publicB, nodes, depth, nodeCount, publicCol);
                launched = true;
                return check(cudaGetLastError(),
                    "nttInverseTreePairNegateProductWarpStages05Pseudo55");
            }
            if (!configurePointwisePseudo55TreeWarpShared(rc)) return false;
            nttInverseTreePairNegateWarpStagesPseudo55Kernel<<<
                blocks, 512u, shBytes, asStream(stream)>>>(
                iv, out, publicB, nodes, depth, nodeCount, publicCol);
            launched = true;
            return check(cudaGetLastError(), "nttInverseTreePairNegateWarpStagesPseudo55");
        }
        nttInverseTreePairNegateFusedFirstStageKernel<<<
            blocks, 512u, shBytes, asStream(stream)>>>(
            iv, out, publicB, nodes, depth, nodeCount, publicCol);

        launched = true;
        return check(cudaGetLastError(), "nttInverseTreePairNegate");
    }

    bool tryLaunchNttInverseRecursiveLeafSparseNegate(
        const RingConstView& rc,
        const u64* nodes,
        const u64* leftB,
        const u64* rightB,
        u64* packed,
        u64* out,
        u32 logicalCount,
        void* stream,
        bool& launched)
    {
        launched = false;
        if (logicalCount < 256u || (logicalCount & 7u) != 0u ||
            logicalCount > 0x3fffffffu)
            return true;

        const u32 parentCount = logicalCount >> 1u;
        if (!fixedIpInverseEligible(rc, parentCount) ||
            !nodes || !leftB || !rightB ||
            !packed || !out || packed == nodes || packed == leftB ||
            packed == rightB || packed == out || out == nodes ||
            out == leftB || out == rightB ||
            rightB != leftB + (size_t(4u) << 13u))
            return true;
        if (!configureShared(rc)) return false;

        constexpr u32 threads = 512u;
        const size_t shBytes = static_cast<size_t>(8192u) * sizeof(u64);
        nttInverseRecursiveLeafSparseNegateKernel<<<
            logicalCount, threads, shBytes, asStream(stream)>>>(
            toDeviceInverseRho4(rc), nodes, leftB, packed, out);
        launched = true;
        return check(
            cudaGetLastError(),
            "nttInverseRecursiveLeafSparseNegate");
    }

    bool tryLaunchNttInverseRecursiveLeafSparseNegateNoZero(
        const RingConstView& rc,
        const u64* nodes,
        const u64* leftB,
        const u64* rightB,
        u64* packed,
        u64* out,
        u32 logicalCount,
        void* stream,
        bool& launched)
    {
        launched = false;
        if (logicalCount < 256u || (logicalCount & 7u) != 0u ||
            logicalCount > 0x3fffffffu)
            return true;

        const u32 parentCount = logicalCount >> 1u;
        if (!fixedIpInverseEligible(rc, parentCount) ||
            !nodes || !leftB || !rightB ||
            !packed || !out || packed == nodes || packed == leftB ||
            packed == rightB || packed == out || out == nodes ||
            out == leftB || out == rightB ||
            rightB != leftB + (size_t(4u) << 13u))
            return true;
        if (!configureShared(rc)) return false;

        constexpr u32 threads = 512u;
        const size_t shBytes = static_cast<size_t>(8192u) * sizeof(u64);
        const bool usePseudo55 =
            pointwisePseudo55ProductionEligible(rc);
        if (usePseudo55)
        {
            if (!configurePointwisePseudo55SparseShared(rc)) return false;
            nttInverseRecursiveLeafSparseNegateNoZeroPseudo55Kernel<<<
                logicalCount, threads, shBytes, asStream(stream)>>>(
                toDeviceInverseRho4(rc), nodes, leftB, packed, out);
        }
        else
        {
            nttInverseRecursiveLeafSparseNegateNoZeroKernel<<<
                logicalCount, threads, shBytes, asStream(stream)>>>(
                toDeviceInverseRho4(rc), nodes, leftB, packed, out);
        }
        launched = true;
        return check(
            cudaGetLastError(),
            usePseudo55 ?
                "nttInverseRecursiveLeafSparseNegateNoZeroPseudo55" :
                "nttInverseRecursiveLeafSparseNegateNoZero");
    }





    bool tryLaunchExpandAccumulatorTau1Pseudo55WideForTest(
        const RingConstView& rc,
        const u64* ct1,
        const u64* uDigits,
        const u64* publicA,
        const u64* skNtt,
        const u64* lacct,
        const u64* nodes,
        const u32* lacctAIdx,
        const u32* lacctBIdx,
        u32 mu,
        u32 treeTerms,
        u64* out,
        u32 outCount,
        void* stream,
        bool& launched)
    {
        launched = false;
        if (!expandAccumulatorWideStructuralEligible(
                rc, mu, treeTerms, outCount) ||
            !ct1 || !uDigits || !publicA || !skNtt || !lacct || !nodes ||
            !lacctAIdx || !lacctBIdx || !out || out == ct1 ||
            out == uDigits || out == publicA || out == skNtt ||
            out == lacct || out == nodes)
        {
            return true;
        }

        launched = true;
        if (mu == 16u)
        {
            return launchExpandAccumulatorTau1WidePseudo55DualPackedPairsImpl<16u, 8u>(
                rc, ct1, uDigits, publicA, skNtt, lacct, nodes,
                lacctAIdx, lacctBIdx, out, outCount, stream);
        }
        if (mu == 32u)
        {
            return launchExpandAccumulatorTau1WidePseudo55DualPackedPairsImpl<32u, 10u>(
                rc, ct1, uDigits, publicA, skNtt, lacct, nodes,
                lacctAIdx, lacctBIdx, out, outCount, stream);
        }
        if (mu == 64u)
        {
            return launchExpandAccumulatorTau1WidePseudo55DualPackedPairsImpl<64u, 12u>(
                rc, ct1, uDigits, publicA, skNtt, lacct, nodes,
                lacctAIdx, lacctBIdx, out, outCount, stream);
        }
        return launchExpandAccumulatorTau1WidePseudo55DualPackedPairsImpl<128u, 14u>(
            rc, ct1, uDigits, publicA, skNtt, lacct, nodes,
            lacctAIdx, lacctBIdx, out, outCount, stream);
    }






    bool launchInnerProduct(
        const RingConstView& rc,
        const u64* aBase,
        const u64* bBase,
        const u32* aIdx,
        const u32* bIdx,
        u32 terms,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        bool accumulate,
        bool negate,
        void* stream,
        bool subtract)
    {
        if (outCount == 0 || terms == 0) return true;
        const DeviceRing rg = toDevice(rc);
        const u32 threads = 256;

        // These four shapes account for essentially all timed inner-product work
        // in the production parameters. The divisibility check guarantees that
        // every x block belongs to exactly one RNS limb, and the y bound gives the
        // fixed kernels exactly one output per block. Aliasing and less common
        // flag/index combinations retain the fully general implementation below.
        const bool fixedGeometry =
            aIdx && bIdx && !outIdx && outCount <= 65535u && (rc.mN % threads) == 0u &&
            out != aBase && out != bBase;
        const dim3 grid = grid2D(rc.mRho * rc.mN, outCount, threads);
        const bool usePseudo55 =
            fixedGeometry && pointwisePseudo55ProductionEligible(rc);
        if (fixedGeometry)
        {
            if (log14H200Shape(rc) && rc.mMods &&
                rc.mMinModulus > (u64{1} << 52u) - (u64{1} << 24u) &&
                rc.mMaxModulus < (u64{1} << 52u) && aBase && bBase && out &&
                !negate && ((terms == 1u && !accumulate) ||
                    (terms == 2u && !accumulate && !subtract) ||
                    (terms == 6u && accumulate && !subtract)))
            {
                const auto launch = [&](auto count, auto mode) {
                    innerProductFixedIndexedH200Kernel<decltype(count)::value,
                        decltype(mode)::value><<<grid, threads, 0u, asStream(stream)>>>(
                            rg, aBase, bBase, aIdx, bIdx, out, rc.mFp52GadgetConstants);
                };
                if (terms == 1u && subtract)
                    launch(std::integral_constant<u32, 1u>{}, std::integral_constant<FixedIpMode, FixedIpMode::Subtract>{});
                else if (terms == 1u)
                    launch(std::integral_constant<u32, 1u>{}, std::integral_constant<FixedIpMode, FixedIpMode::Replace>{});
                else if (terms == 2u)
                    launch(std::integral_constant<u32, 2u>{}, std::integral_constant<FixedIpMode, FixedIpMode::Replace>{});
                else launch(std::integral_constant<u32, 6u>{}, std::integral_constant<FixedIpMode, FixedIpMode::Accumulate>{});
                return check(cudaGetLastError(), "innerProductFixedH200");
            }
            if (terms == 1u && !accumulate && !negate)
            {
                if (subtract)
                {
                    if (usePseudo55)
                        innerProductFixedIndexedPseudo55Kernel<
                            1, FixedIpMode::Subtract>
                            <<<grid, threads, 0, asStream(stream)>>>(
                                rg, aBase, bBase, aIdx, bIdx, out);
                    else
                        innerProductFixedIndexedKernel<
                            1, FixedIpMode::Subtract>
                            <<<grid, threads, 0, asStream(stream)>>>(
                                rg, aBase, bBase, aIdx, bIdx, out);
                }
                else
                {
                    if (usePseudo55)
                        innerProductFixedIndexedPseudo55Kernel<
                            1, FixedIpMode::Replace>
                            <<<grid, threads, 0, asStream(stream)>>>(
                                rg, aBase, bBase, aIdx, bIdx, out);
                    else
                        innerProductFixedIndexedKernel<
                            1, FixedIpMode::Replace>
                            <<<grid, threads, 0, asStream(stream)>>>(
                                rg, aBase, bBase, aIdx, bIdx, out);
                }
                return check(
                    cudaGetLastError(),
                    usePseudo55 ? "innerProductFixed1Pseudo55" :
                                  "innerProductFixed1");
            }
            if (terms == 2u && !accumulate && !negate && !subtract)
            {
                if (usePseudo55)
                    innerProductFixedIndexedPseudo55Kernel<
                        2, FixedIpMode::Replace>
                        <<<grid, threads, 0, asStream(stream)>>>(
                            rg, aBase, bBase, aIdx, bIdx, out);
                else
                    innerProductFixedIndexedKernel<2, FixedIpMode::Replace>
                        <<<grid, threads, 0, asStream(stream)>>>(
                            rg, aBase, bBase, aIdx, bIdx, out);
                return check(
                    cudaGetLastError(),
                    usePseudo55 ? "innerProductFixed2Pseudo55" :
                                  "innerProductFixed2");
            }
            if (terms == 6u && accumulate && !negate && !subtract)
            {
                if (usePseudo55)
                    innerProductFixedIndexedPseudo55Kernel<
                        6, FixedIpMode::Accumulate>
                        <<<grid, threads, 0, asStream(stream)>>>(
                            rg, aBase, bBase, aIdx, bIdx, out);
                else
                    innerProductFixedIndexedKernel<6, FixedIpMode::Accumulate>
                        <<<grid, threads, 0, asStream(stream)>>>(
                            rg, aBase, bBase, aIdx, bIdx, out);
                return check(
                    cudaGetLastError(),
                    usePseudo55 ? "innerProductFixed6Pseudo55" :
                                  "innerProductFixed6");
            }
        }
        innerProductKernel<<<grid2D(rc.mRho * rc.mN, outCount, threads), threads, 0, asStream(stream)>>>(
            rg, aBase, bBase, aIdx, bIdx, terms, out, outIdx, outCount, accumulate, negate, subtract);
        return check(cudaGetLastError(), "innerProduct");
    }

    bool launchExpandAccumulatorTau1(
        const RingConstView& rc,
        const u64* ct1,
        const u64* uDigits,
        const u64* publicA,
        const u64* skNtt,
        const u64* lacct,
        const u64* nodes,
        const u32* lacctAIdx,
        const u32* lacctBIdx,
        u32 mu,
        u32 treeTerms,
        u64* out,
        u32 outCount,
        void* stream)
    {
        return launchExpandAccumulatorTau1(
            rc, ct1, uDigits, publicA, skNtt, lacct, nodes, lacctAIdx,
            lacctBIdx, mu, treeTerms, out, outCount, stream, false);
    }

    bool launchExpandAccumulatorTau1(
        const RingConstView& rc,
        const u64* ct1,
        const u64* uDigits,
        const u64* publicA,
        const u64* skNtt,
        const u64* lacct,
        const u64* nodes,
        const u32* lacctAIdx,
        const u32* lacctBIdx,
        u32 mu,
        u32 treeTerms,
        u64* out,
        u32 outCount,
        void* stream,
        bool alphaIsTwo)
    {
        if (outCount == 0) return true;
        if (!ct1 || !uDigits || !publicA || !skNtt || !lacct || !nodes || !lacctAIdx ||
            !lacctBIdx || !out || mu == 0 || outCount > 65535u || (rc.mN % 256u) != 0u)
        {
            return false;
        }
        if (!canLaunchExpandAccumulatorTau1(
                rc, mu, treeTerms, outCount))
        {
            return false;
        }
        if (expandAccumulatorNoGoldH200StructuralEligible(
                rc, mu, treeTerms, outCount))
        {
            return launchExpandAccumulatorTau1NoGoldH200Impl(
                rc, ct1, uDigits, publicA, skNtt, lacct, nodes,
                lacctAIdx, lacctBIdx, out, outCount, stream);
        }
        if (treeTerms != 6u)
        {
            bool launched = false;
            const bool ok =
                tryLaunchExpandAccumulatorTau1Pseudo55WideForTest(
                    rc, ct1, uDigits, publicA, skNtt, lacct, nodes,
                    lacctAIdx, lacctBIdx, mu, treeTerms, out, outCount,
                    stream, launched);
            return ok && launched;
        }
        const DeviceRing rg = toDevice(rc);
        constexpr u32 threads = 256;
        if (rc.mN == 8192u && rc.mRho == 4u &&
            mu == 8u && treeTerms == 6u && (outCount % 8u) == 0u)
        {
            const u32 chunks = outCount / 8u;
            // Keep about 1024 CTAs at small chunk counts, then let the larger
            // grids amortize pointer setup over progressively more of the 32
            // coefficient tiles per (chunk,row,limb).
            const u32 tileDenom = 32u * chunks;
            const u32 rawTileBlocks = 1024u / tileDenom;
            const u32 tileBlocks = rawTileBlocks == 0u
                ? 1u
                : (rawTileBlocks > 32u ? 32u : rawTileBlocks);
            const dim3 grid(tileBlocks, 8u * 4u, chunks);
            constexpr u64 kPseudo55Radix = u64{ 1 } << 55u;
            constexpr u64 kPseudo55MaxC = u64{ 1 } << 21u;
            // The pseudo-Mersenne proof additionally needs every limb
            // to satisfy q=2^55-c with 0<c<2^21. Host metadata guards
            // the whole table before the device reconstructs q from c.
            if (rc.mMinModulus > kPseudo55Radix - kPseudo55MaxC &&
                rc.mMaxModulus < kPseudo55Radix)
            {
                if (alphaIsTwo &&
                    expandAccumulatorGoldenPseudo55StructuralEligible(
                        rc, mu, treeTerms, outCount))
                {
                    expandAccumulatorTau1GoldenPseudo55DualKernel<<<
                        grid, threads, 0, asStream(stream)>>>(
                        rg, ct1, uDigits, publicA, skNtt, lacct,
                        nodes, lacctAIdx, lacctBIdx, out);
                }
                else
                {
                    expandAccumulatorTau1GoldenPseudo55Kernel<<<
                        grid, threads, 0, asStream(stream)>>>(
                        rg, ct1, uDigits, publicA, skNtt, lacct,
                        nodes, lacctAIdx, lacctBIdx, out);
                }
            }
            else
            {
                expandAccumulatorTau1GoldenExperimentalKernel<<<
                    grid, threads, 0, asStream(stream)>>>(
                    rg, ct1, uDigits, publicA, skNtt, lacct, nodes,
                    lacctAIdx, lacctBIdx, out);
            }

            return check(cudaGetLastError(), "expandAccumulatorTau1GoldenTiled");

        }
        expandAccumulatorTau1Kernel<<<
            grid2D(rc.mRho * rc.mN, outCount, threads), threads, 0, asStream(stream)>>>(
            rg, ct1, uDigits, publicA, skNtt, lacct, nodes, lacctAIdx, lacctBIdx, mu, out);
        return check(cudaGetLastError(), "expandAccumulatorTau1");
    }


    bool launchElementwise(
        const RingConstView& rc,
        const u64* aBase,
        const u32* aIdx,
        const u64* bBase,
        const u32* bIdx,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        ElemOp op,
        void* stream)
    {
        if (outCount == 0) return true;
        const DeviceRing rg = toDevice(rc);
        const u32 threads = 256;
        elementwiseKernel<<<grid2D(rc.mRho * rc.mN, outCount, threads), threads, 0, asStream(stream)>>>(
            rg, aBase, aIdx, bBase, bIdx, out, outIdx, outCount, static_cast<u32>(op));
        return check(cudaGetLastError(), "elementwise");
    }

    bool launchScaleByPow2(
        const RingConstView& rc,
        const u64* aBase,
        const u32* aIdx,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        const u64* factorsPerLimb,
        void* stream)
    {
        if (outCount == 0) return true;
        const DeviceRing rg = toDevice(rc);
        const u32 threads = 256;
        scalePow2Kernel<<<grid2D(rc.mRho * rc.mN, outCount, threads), threads, 0, asStream(stream)>>>(
            rg, aBase, aIdx, out, outIdx, outCount, factorsPerLimb);
        return check(cudaGetLastError(), "scalePow2");
    }

    bool launchCanonicalize(
        const RingConstView& rc, u64* data, const u32* polyIdx, u32 polyCount, void* stream)
    {
        if (polyCount == 0) return true;
        const DeviceRing rg = toDevice(rc);
        const u32 threads = 256;
        canonicalizeKernel<<<grid2D(rc.mRho * rc.mN, polyCount, threads), threads, 0, asStream(stream)>>>(
            rg, data, polyIdx, polyCount);
        return check(cudaGetLastError(), "canonicalize");
    }

    namespace
    {
        bool gadgetHi110Pseudo55SecondFoldEligible(
            const RingConstView& rc)
        {
            constexpr u64 radix55 = u64{ 1 } << 55u;
            constexpr u64 maxComplement = u64{ 1 } << 21u;
            return rc.mN == 8192u && rc.mLogN == 13u && rc.mRho == 4u &&
                rc.mMinModulus <= rc.mMaxModulus &&
                rc.mMinModulus > radix55 - maxComplement &&
                rc.mMaxModulus < radix55 && rc.mMods &&
                rc.mInvPuncturedProd && rc.mPuncturedProd &&
                rc.mBaseProd && rc.mBaseProdHalf;
        }

        bool gadgetDecomposeHi110RecursiveLeafSparsePairEligible(
            const RingConstView& rc,
            const u64* in,
            u32 parentCount,
            const u64* out)
        {
            return rc.mKernelOptions.mGadgetHi110Specialized &&
                rc.mKernelOptions.mGadgetHi110CompactCrt &&
                rc.mKernelOptions.mGadgetHi110Radix55Reduce &&
                !rc.mKernelOptions.mGadgetGarner &&
                rc.mN == 8192u && rc.mLogN == 13u && rc.mRho == 4u &&
                rc.mMinModulus > (u64(1) << 54u) &&
                rc.mMaxModulus < (u64(1) << 55u) &&
                rc.mMods && rc.mInvPuncturedProd && rc.mPuncturedProd &&
                rc.mBaseProd && rc.mBaseProdHalf &&
                parentCount >= 128u && parentCount <= 1024u &&
                (parentCount & 3u) == 0u && in && out && in != out;
        }
    }

    bool canLaunchGadgetDecomposeHi110RecursiveLeafSparsePair(
        const RingConstView& rc,
        const u64* in,
        u32 parentCount,
        const u64* out)
    {
        return rc.mKernelOptions.mGadgetHi110SparsePair &&
            gadgetDecomposeHi110RecursiveLeafSparsePairEligible(
                rc, in, parentCount, out);
    }

    bool launchGadgetDecomposeHi110RecursiveLeafSparsePair(
        const RingConstView& rc,
        const u64* in,
        u32 parentCount,
        u64* out,
        const u32* outIdx,
        void* stream)
    {
        // This is the explicit/direct entry point used after protocol preflight
        // and by the focused oracle. The opt-in toggle belongs to `canLaunch`;
        // once a no-zero producer has run, re-reading it here must not turn a
        // mandatory sparse consumer into a soft decline.
        if (!gadgetDecomposeHi110RecursiveLeafSparsePairEligible(
                rc, in, parentCount, out))
            return false;

        constexpr u32 threads = 128u;
        const u32 pairCount = parentCount >> 1u;
        const dim3 grid = grid2D(8192u, pairCount, threads);
        const DeviceRing rg = toDevice(rc);
        cudaStream_t st = asStream(stream);

        const bool pseudo55SecondFold =
            rc.mKernelOptions.mGadgetHi110Pseudo55SecondFold &&
            gadgetHi110Pseudo55SecondFoldEligible(rc);
        if (pseudo55SecondFold)
        {
            gadgetDecomposeHi110Rho4SparsePairCompactCrtPseudo55SecondFoldKernel<0u><<<
                grid, threads, 0, st>>>(
                rg, in, pairCount, out, outIdx);
        }
        else
        {
            gadgetDecomposeHi110Rho4SparsePairCompactCrtRadix55Kernel<0u><<<
                grid, threads, 0, st>>>(
                rg, in, pairCount, out, outIdx);
        }
        if (!check(
                cudaGetLastError(),
                pseudo55SecondFold
                    ? "gadgetDecomposeHi110Rho4SparsePairPseudo55SecondFoldFirst01"
                    : "gadgetDecomposeHi110Rho4SparsePairRadix55First01"))
            return false;

        if (pseudo55SecondFold)
        {
            gadgetDecomposeHi110Rho4SparsePairCompactCrtPseudo55SecondFoldKernel<2u><<<
                grid, threads, 0, st>>>(
                rg, in, pairCount, out, outIdx);
        }
        else
        {
            gadgetDecomposeHi110Rho4SparsePairCompactCrtRadix55Kernel<2u><<<
                grid, threads, 0, st>>>(
                rg, in, pairCount, out, outIdx);
        }
        return check(
            cudaGetLastError(),
            pseudo55SecondFold
                ? "gadgetDecomposeHi110Rho4SparsePairPseudo55SecondFoldFirst23"
                : "gadgetDecomposeHi110Rho4SparsePairRadix55First23");
    }




    bool prepareKernelDispatch(RingConstView& rc, const LogVoleGpuKernelOptions& options,
        KernelInitializationState& initialization)
    {
        if (!options.valid()) return false;
        rc.mKernelOptions = options;
        int device = 0;
        cudaDeviceProp prop{};
        if (!check(cudaGetDevice(&device), "kernel dispatch device") ||
            !check(cudaGetDeviceProperties(&prop, device), "kernel dispatch properties")) return false;
        // Preparation runs before the owning table record is published. Never
        // reset readiness or reuse an existing owner's state on another device.
        if (initialization.mDevice != -1 && initialization.mDevice != device) return false;
        initialization.mDevice = device;
        rc.mKernelInitialization = &initialization;
        rc.mSmCount = prop.multiProcessorCount > 0 ? static_cast<u32>(prop.multiProcessorCount) : 142u;
        rc.mH200Shared = prop.major == 9 && std::strstr(prop.name, "H200") &&
            prop.sharedMemPerBlockOptin >= 16384u * sizeof(u64);
        return true;
    }

    bool prepareH200RootPersistence(RingConstView& rc)
    {
        rc.mH200RootL2MaxWindow = 0u;
#if CUDART_VERSION >= 11000
        if (!rc.mKernelOptions.mNoGoldH200RootL2Mode || rc.mN != 16384u || rc.mLogN != 14u || rc.mRho != 8u) return true;
        int device = 0;
        cudaDeviceProp prop{};
        if (!check(cudaGetDevice(&device), "root L2 device") ||
            !check(cudaGetDeviceProperties(&prop, device), "root L2 properties")) return false;
        if (prop.major != 9 || !std::strstr(prop.name, "H200") ||
            !prop.persistingL2CacheMaxSize || !prop.accessPolicyMaxWindowSize) return true;
        const size_t mib = rc.mKernelOptions.mRootL2MiB;
        const size_t bytes = std::min(mib << 20u, static_cast<size_t>(prop.persistingL2CacheMaxSize));
        const cudaError_t status = cudaDeviceSetLimit(cudaLimitPersistingL2CacheSize, bytes);
        // Persistence is an optional performance hint. MIG/MPS configurations
        // that do not permit it keep the unchanged normal-cache implementation.
        if (status == cudaErrorUnsupportedLimit || status == cudaErrorNotSupported)
        {
            cudaGetLastError();
            return true;
        }
        if (!check(status, "root L2 set-aside")) return false;
        size_t actual = 0u;
        if (!check(cudaDeviceGetLimit(&actual, cudaLimitPersistingL2CacheSize), "root L2 limit")) return false;
        if (actual) rc.mH200RootL2MaxWindow = static_cast<size_t>(prop.accessPolicyMaxWindowSize);
        std::fprintf(stderr, "[h200-root-l2] set_aside_bytes=%zu max_window_bytes=%zu\n",
            actual, rc.mH200RootL2MaxWindow);
#endif
        return true;
    }

    bool launchPrepareH200Fp52GadgetConstants(
        const RingConstView& rc, double* out, void* stream)
    {
        if (rc.mN != 16384u || rc.mLogN != 14u || rc.mRho != 8u || !rc.mMods || !rc.mGarnerInv || !out ||
            rc.mMinModulus <= (u64{1} << 51u) || rc.mMaxModulus >= (u64{1} << 52u) ||
            rc.mMinModulus > rc.mMaxModulus)
            return false;
        prepareH200Fp52GadgetConstantsKernel<<<1u, 128u, 0u, asStream(stream)>>>(toDevice(rc), out);
        return check(cudaGetLastError(), "prepareH200Fp52GadgetConstants");
    }

    bool launchGadgetDecompose(
        const RingConstView& rc,
        const u64* in,
        const u32* inIdx,
        u32 inCount,
        u32 digitBits,
        u32 startLevel,
        u32 levels,
        bool centered,
        u64* out,
        const u32* outIdx,
        void* stream)
    {
        if (inCount == 0 || levels == 0) return true;
        if (rc.mRho > kMaxWords) return false;
        const DeviceRing rg = toDevice(rc);
        // LV_GADGET_GARNER=1 composes the coefficient by mixed radix instead of the
        // punctured-product CRT sum. Both produce the same integer; this exists to
        // measure the two against each other on one build.
        const bool garner = rc.mKernelOptions.mGadgetGarner;
        const u32 threads = 128;
        const dim3 grid = grid2D(rc.mN, inCount, threads);
        cudaStream_t st = asStream(stream);
        if (rc.mKernelOptions.mNoGoldH200Gadget208 && log14H200Shape(rc) &&
            rc.mGarnerInv && rc.mBaseProd && rc.mBaseProdHalf &&
            digitBits == 208u && startLevel == 1u && levels == 1u &&
            centered)
        {
            constexpr u64 kRadix52 = u64{ 1 } << 52u;
            const bool pseudo52 =
                rc.mKernelOptions.mNoGoldH200Gadget208Pseudo52 &&
                rc.mMaxModulus < kRadix52 &&
                rc.mMinModulus > kRadix52 - (u64{ 1 } << 24u);
            if (pseudo52 && rc.mFp52GadgetConstants)
            {
                gadgetDecomposeHi208Rho8ConstantsKernel<<<grid, threads, 0u, st>>>(
                    rg, in, inIdx, inCount, out, outIdx, rc.mFp52GadgetConstants);
                return check(cudaGetLastError(), "gadgetDecomposeHi208Rho8Constants");
            }
            if (pseudo52)
                gadgetDecomposeHi208Rho8H200Kernel<true><<<
                    grid, threads, 0, st>>>(
                    rg, in, inIdx, inCount, out, outIdx);
            else
                gadgetDecomposeHi208Rho8H200Kernel<false><<<
                    grid, threads, 0, st>>>(
                    rg, in, inIdx, inCount, out, outIdx);
            return check(
                cudaGetLastError(),
                pseudo52
                    ? "gadgetDecomposeHi208Rho8H200Pseudo52"
                    : "gadgetDecomposeHi208Rho8H200");
        }
        // The single 128-bit Barrett reduction per output limb requires the
        // high word to be below the modulus. A balanced 110-bit digit has
        // magnitude at most 2^109, so its high word is at most 2^45. Keep this
        // condition in host dispatch rather than adding a cold reduction branch
        // to every thread. LV_GADGET_GARNER retains its general mixed-radix body.
        if (rc.mKernelOptions.mGadgetHi110Specialized && !garner && rc.mRho == 4u &&
            digitBits == 110u && startLevel == 1u && levels == 1u && centered &&
            rc.mMinModulus > kGadgetHi110HalfHi)
        {
            // Four moduli below 2^55 give Q<2^220 and three-word punctured
            // products. Keep the bound in host dispatch so the compact kernel's
            // arithmetic contains no runtime guard or divergent fallback.
            if (rc.mKernelOptions.mGadgetHi110CompactCrt &&
                rc.mMaxModulus < (u64(1) << 55u))
            {
                // Radix-55 reduction additionally needs every q to have exactly
                // 55 bits. The strict lower bound also proves hi55<q for the
                // balanced 110-bit magnitude consumed by the candidate.
                if (rc.mKernelOptions.mGadgetHi110Radix55Reduce &&
                    rc.mMinModulus > (u64(1) << 54u))
                {
                    const bool pseudo55SecondFold =
                        rc.mKernelOptions.mGadgetHi110Pseudo55SecondFold &&
                        gadgetHi110Pseudo55SecondFoldEligible(rc);
                    if (pseudo55SecondFold)
                    {
                        gadgetDecomposeHi110Rho4CompactCrtPseudo55SecondFoldKernel<<<
                            grid, threads, 0, st>>>(
                            rg, in, inIdx, inCount, out, outIdx);
                    }
                    else
                    {
                        gadgetDecomposeHi110Rho4CompactCrtRadix55Kernel<<<
                            grid, threads, 0, st>>>(
                            rg, in, inIdx, inCount, out, outIdx);
                    }
                    return check(
                        cudaGetLastError(),
                        pseudo55SecondFold
                            ? "gadgetDecomposeHi110Rho4CompactCrtPseudo55SecondFold"
                            : "gadgetDecomposeHi110Rho4CompactCrtRadix55");
                }
                gadgetDecomposeHi110Rho4CompactCrtKernel<<<grid, threads, 0, st>>>(
                    rg, in, inIdx, inCount, out, outIdx);
                return check(
                    cudaGetLastError(), "gadgetDecomposeHi110Rho4CompactCrt");
            }
            gadgetDecomposeHi110Rho4Kernel<<<grid, threads, 0, st>>>(
                rg, in, inIdx, inCount, out, outIdx);
            return check(cudaGetLastError(), "gadgetDecomposeHi110Rho4");
        }
        // Dispatch on the limb count so the kernel's multi-precision temporaries
        // are register resident. rho is 4 for the LogVole parameter set; the
        // others are here so the path is not silently lost if that changes.
        switch (rc.mRho)
        {
        case 1:
            gadgetDecomposeKernelT<1><<<grid, threads, 0, st>>>(
                rg, in, inIdx, inCount, digitBits, startLevel, levels, centered, out, outIdx, garner);
            break;
        case 2:
            gadgetDecomposeKernelT<2><<<grid, threads, 0, st>>>(
                rg, in, inIdx, inCount, digitBits, startLevel, levels, centered, out, outIdx, garner);
            break;
        case 3:
            gadgetDecomposeKernelT<3><<<grid, threads, 0, st>>>(
                rg, in, inIdx, inCount, digitBits, startLevel, levels, centered, out, outIdx, garner);
            break;
        case 4:
            gadgetDecomposeKernelT<4><<<grid, threads, 0, st>>>(
                rg, in, inIdx, inCount, digitBits, startLevel, levels, centered, out, outIdx, garner);
            break;
        case 5:
            gadgetDecomposeKernelT<5><<<grid, threads, 0, st>>>(
                rg, in, inIdx, inCount, digitBits, startLevel, levels, centered, out, outIdx, garner);
            break;
        case 6:
            gadgetDecomposeKernelT<6><<<grid, threads, 0, st>>>(
                rg, in, inIdx, inCount, digitBits, startLevel, levels, centered, out, outIdx, garner);
            break;
        case 7:
            gadgetDecomposeKernelT<7><<<grid, threads, 0, st>>>(
                rg, in, inIdx, inCount, digitBits, startLevel, levels, centered, out, outIdx, garner);
            break;
        case 8:
            gadgetDecomposeKernelT<8><<<grid, threads, 0, st>>>(
                rg, in, inIdx, inCount, digitBits, startLevel, levels, centered, out, outIdx, garner);
            break;
        default:
            return false;
        }
        return check(cudaGetLastError(), "gadgetDecompose");
    }

    bool launchSeedLabelRep(const RingConstView& rc, const u64* input,
        u64* output, u32 tau, u32 count, bool gammaOne, void* stream)
    {
        if (!rc.mN || !rc.mRho || !tau || !count || !input || !output) return false;
        constexpr u32 threads = 256;
        const u64 words = static_cast<u64>(rc.mN) * rc.mRho * count;
        const u32 blocks = static_cast<u32>(std::min<u64>((words + threads - 1u) / threads, 4096));
        seedLabelRepKernel<<<blocks, threads, 0, asStream(stream)>>>(rc, input, output, tau, count, gammaOne);
        return check(cudaGetLastError(), "seedLabelRep");
    }

    bool launchSelectScaleLimb(
        const RingConstView& rc,
        const u64* aBase,
        const u32* aIdx,
        const u32* limbSel,
        const u64* scalePerLimb,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        void* stream)
    {
        if (outCount == 0) return true;
        const DeviceRing rg = toDevice(rc);
        const u32 threads = 256;
        selectScaleLimbKernel<<<grid2D(rc.mRho * rc.mN, outCount, threads), threads, 0, asStream(stream)>>>(
            rg, aBase, aIdx, limbSel, scalePerLimb, out, outIdx, outCount);
        return check(cudaGetLastError(), "selectScaleLimb");
    }

    bool launchLiftCenteredLimb(
        const RingConstView& rc,
        const u64* aBase,
        const u32* aIdx,
        const u32* limbSel,
        const u64* invScalePerLimb,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        void* stream)
    {
        if (outCount == 0) return true;
        const DeviceRing rg = toDevice(rc);
        const u32 threads = 256;
        liftCenteredLimbKernel<<<grid2D(rc.mN, outCount, threads), threads, 0, asStream(stream)>>>(
            rg, aBase, aIdx, limbSel, invScalePerLimb, out, outIdx, outCount);
        return check(cudaGetLastError(), "liftCenteredLimb");
    }

    bool launchExpandCenteredCompact(
        const RingConstView& rc, const u64* compactQ0, u64* out,
        u32 outCount, void* stream)
    {
        if (outCount == 0) return true;
        if (!compactQ0 || !out || rc.mN == 0 || rc.mRho == 0) return false;
        const u32 threads = 256;
        expandCenteredCompactKernel<<<grid2D(rc.mN, outCount, threads), threads, 0, asStream(stream)>>>(
            toDevice(rc), compactQ0, out, outCount);
        return check(cudaGetLastError(), "expandCenteredCompact");
    }

    bool launchPrepareDeltaSlots(u64 delta0, u64 delta1, u64 delta2,
        u32 slotCount, bool garbled, u64* out, void* stream)
    {
        if (!out || slotCount == 0 || (garbled && slotCount < 3u)) return false;
        constexpr u32 threads = 256;
        const u32 blocks = slotCount / threads + (slotCount % threads != 0);
        prepareDeltaSlotsKernel<<<blocks, threads, 0, asStream(stream)>>>(
            delta0, delta1, delta2, slotCount, garbled, out);
        return check(cudaGetLastError(), "prepareDeltaSlots");
    }

    bool launchPrepareConstantDelta(const RingConstView& rc, u64 delta,
        const u64* liftModQ, u64* out, void* stream)
    {
        if (!out || !liftModQ || !rc.mN || !rc.mRho) return false;
        constexpr u32 threads = 256;
        const u32 blocks = rc.mN / threads + (rc.mN % threads != 0);
        prepareConstantDeltaKernel<<<blocks, threads, 0, asStream(stream)>>>(
            toDevice(rc), delta, liftModQ, out);
        return check(cudaGetLastError(), "prepareConstantDelta");
    }

    bool launchLeafPairScaled(
        const RingConstView& rc,
        const u64* leftB,
        const u64* rightB,
        const u64* digits,
        const u32* leftIdx,
        const u32* rightIdx,
        const u32* leftLimb,
        const u32* rightLimb,
        u64* out,
        const u32* outIdx,
        u32 outCount,
        void* stream)
    {
        if (outCount == 0) return true;
        const DeviceRing rg = toDevice(rc);
        const u32 threads = 256;
        leafPairScaledKernel<<<grid2D(rc.mRho * rc.mN, outCount, threads), threads, 0, asStream(stream)>>>(
            rg, leftB, rightB, digits, leftIdx, rightIdx, leftLimb, rightLimb, out, outIdx,
            outCount);
        return check(cudaGetLastError(), "leafPairScaled");
    }

    bool launchRecursiveLeafDiagonal(
        const RingConstView& rc,
        const u64* nodes,
        const u32* nodeIdx,
        const u32* parentAndSide,
        const u64* leftB,
        const u64* rightB,
        u64* packed,
        u64* parent,
        u32 logicalCount,
        bool selfZeroRho4,
        void* stream)
    {
        if (logicalCount == 0) return true;
        if (!nodes || !nodeIdx || !parentAndSide || !leftB || !rightB ||
            !packed || !parent || rc.mRho <= 1u)
            return false;
        const u32 threads = 256;
        if (selfZeroRho4)
        {
            if (rc.mN != 8192u || rc.mRho != 4u) return false;
            recursiveLeafDiagonalRho4SelfZeroKernel<<<
                grid2D(rc.mN, logicalCount, threads), threads, 0, asStream(stream)>>>(
                toDevice(rc), nodes, nodeIdx, parentAndSide, leftB, rightB,
                packed, parent, logicalCount);
        }
        else
        {
            recursiveLeafDiagonalKernel<<<
                grid2D(rc.mN, logicalCount, threads), threads, 0, asStream(stream)>>>(
                toDevice(rc), nodes, nodeIdx, parentAndSide, leftB, rightB,
                packed, parent, logicalCount);
        }
        return check(cudaGetLastError(), "recursiveLeafDiagonal");
    }

    bool launchPrepareRawNttTables(const RingConstView& rc, const u64* primes,
        u64* scratch, u32* status, void* stream)
    {
        if (rc.mN < 2 || rc.mN > 131072 || (rc.mN & (rc.mN - 1u)) ||
            rc.mLogN == 0 || rc.mLogN > 17 || (1u << rc.mLogN) != rc.mN ||
            !rc.mRho || rc.mRho > kMaxRawSetupWords || rc.mMinModulus <= 2u * rc.mN ||
            rc.mMaxModulus >= (u64{1} << 60) || !rc.mMods || !rc.mRoots ||
            !rc.mInvRoots || !rc.mInvDegree || !rc.mScaledInvRoot ||
            !primes || !scratch || !status) return false;
        if (!check(cudaMemsetAsync(status, 0, sizeof(u32), asStream(stream)), "rawSetupStatus")) return false;
        rawSetupModuliKernel<<<1, 32, 0, asStream(stream)>>>(
            rc, primes, scratch, status, nullptr);
        if (!check(cudaGetLastError(), "rawSetupModuli")) return false;
        const dim3 grid((rc.mN + 255u) / 256u, rc.mRho);
        rawSetupMinimumRootsKernel<<<grid, 256, 0, asStream(stream)>>>(rc, scratch, status);
        if (!check(cudaGetLastError(), "rawSetupMinimumRoots")) return false;
        rawSetupNttScalarsKernel<<<1, 32, 0, asStream(stream)>>>(rc, scratch, status);
        if (!check(cudaGetLastError(), "rawSetupNttScalars")) return false;
        rawSetupNttTablesKernel<<<grid, 256, 0, asStream(stream)>>>(rc, scratch, status);
        return check(cudaGetLastError(), "rawSetupNttTables");
    }

    bool launchPrepareRawCrtConstants(const RingConstView& rc,
        const DenoiseConstView& dc, u64* crtLift, u64* invCrtLift,
        u64* sampleMaxMultiple, const u32* status, void* stream)
    {
        if (!rc.mRho || rc.mRho > kMaxRawSetupWords || !rc.mMods || !rc.mBaseProd ||
            !rc.mBaseProdHalf || !rc.mPuncturedProd || !rc.mInvPuncturedProd ||
            !rc.mGarnerInv || !dc.mQ || !crtLift || !invCrtLift ||
            !sampleMaxMultiple || !status) return false;
        if (rc.mRho > 1 && (!dc.mSrcLimb || !dc.mCrtInvPunctured ||
            !dc.mPuncturedProdModTarget || !dc.mCrtInvPuncturedShoup ||
            !dc.mScaledPuncturedShoup || !dc.mFracInvLo || !dc.mFracInvHi ||
            !dc.mInvCrtLiftShoup)) return false;
        rawSetupCrtKernel<<<1, 32, 0, asStream(stream)>>>(rc, dc, crtLift, invCrtLift, sampleMaxMultiple, status);
        return check(cudaGetLastError(), "rawSetupCrt");
    }

    bool launchPrepareRawSlotMaps(u32 n, u32* slotMap, u32* inverseSlotMap, void* stream)
    {
        if (n < 2 || n > 131072 || (n & (n - 1u)) || !slotMap || !inverseSlotMap) return false;
        u32 logN = 0;
        while ((1u << logN) < n) ++logN;
        rawSetupSlotMapsKernel<<<(n / 2u + 255u) / 256u, 256, 0, asStream(stream)>>>(
            n, logN, slotMap, inverseSlotMap, nullptr);
        return check(cudaGetLastError(), "rawSetupSlotMaps");
    }

    bool launchSelectSealCoeffModuli(u32 n, const int* bits, u32 rho,
        u64* orderedPrimes, u32* status, void* stream)
    {
        if (n < 1024u || n > 131072u || (n & (n - 1u)) ||
            !rho || rho > kMaxRawSetupWords || !bits || !orderedPrimes || !status) return false;
        if (!check(cudaMemsetAsync(status, 0, sizeof(u32), asStream(stream)),
            "rawSealCoeffStatus")) return false;
        rawSetupSelectSealCoeffKernel<<<1, 32, 0, asStream(stream)>>>(
            n, bits, rho, orderedPrimes, status);
        return check(cudaGetLastError(), "rawSealCoeffSelect");
    }

    bool launchSelectSealPlainModulus(u32 n, u32 requestedBits, u64 minimumQ,
        u64* selectedPrime, u32* selectedBits, u32* status, void* stream)
    {
        if (n < 1024u || n > 131072u || (n & (n - 1u)) ||
            !requestedBits || minimumQ <= 2u * n ||
            !selectedPrime || !selectedBits || !status) return false;
        if (!check(cudaMemsetAsync(status, 0, sizeof(u32), asStream(stream)),
            "rawSealPlainStatus")) return false;
        rawSetupSelectSealPlainKernel<<<1, 32, 0, asStream(stream)>>>(
            n, requestedBits, minimumQ, selectedPrime, selectedBits, status);
        return check(cudaGetLastError(), "rawSealPlainSelect");
    }

    bool launchPreparePlaintextLift(const RingConstView& rc, u64 plaintextPrime,
        u64* residues, u32* status, void* stream)
    {
        if (!rc.mRho || rc.mRho > kMaxRawSetupWords || !rc.mMods || !rc.mBaseProd ||
            plaintextPrime <= 2u * rc.mN || plaintextPrime >= rc.mMinModulus ||
            !residues || !status) return false;
        if (!check(cudaMemsetAsync(status, 0, sizeof(u32), asStream(stream)),
            "rawPlainLiftStatus")) return false;
        rawSetupPlaintextLiftKernel<<<1, 32, 0, asStream(stream)>>>(
            rc, plaintextPrime, residues, status);
        return check(cudaGetLastError(), "rawPlainLift");
    }

    bool launchNativeSealSetupBundle(const RingConstView& ring,
        const DenoiseConstView& denoise, const RingConstView& plain,
        const int* coefficientBits, u32 coefficientCount,
        u32 requestedPlaintextBits,
        u64* orderedQ, u64* selectedP, u32* selectedBits, u64* plaintextLift,
        u32* fiveStatuses, u64* ringScratch, u64* plainScratch,
        u64* crtLift, u64* inverseCrtLift, u64* sampleMaxMultiple,
        u32* slotMap, u32* inverseSlotMap, void* stream)
    {
        const u32 n = ring.mN;
        const u32 rho = ring.mRho;
        if (n < 1024u || n > 131072u || (n & (n - 1u)) ||
            !rho || rho > kMaxRawSetupWords ||
            coefficientCount != rho || !coefficientBits ||
            !requestedPlaintextBits ||
            plain.mN != n || plain.mRho != 1u ||
            ring.mLogN == 0 || ring.mLogN > 17u ||
            (1u << ring.mLogN) != n || plain.mLogN != ring.mLogN ||
            !ring.mMods || !ring.mRoots || !ring.mInvRoots ||
            !ring.mInvDegree || !ring.mScaledInvRoot ||
            !ring.mBaseProd || !ring.mBaseProdHalf || !ring.mPuncturedProd ||
            !ring.mInvPuncturedProd || !ring.mGarnerInv ||
            !denoise.mQ || !plain.mMods || !plain.mRoots ||
            !plain.mInvRoots || !plain.mInvDegree || !plain.mScaledInvRoot ||
            !orderedQ || !selectedP || !selectedBits || !plaintextLift ||
            !fiveStatuses || !ringScratch || !plainScratch ||
            !crtLift || !inverseCrtLift || !sampleMaxMultiple ||
            !slotMap || !inverseSlotMap || !stream)
            return false;
        if (rho > 1u && (!denoise.mSrcLimb || !denoise.mCrtInvPunctured ||
            !denoise.mPuncturedProdModTarget || !denoise.mCrtInvPuncturedShoup ||
            !denoise.mScaledPuncturedShoup || !denoise.mFracInvLo ||
            !denoise.mFracInvHi || !denoise.mInvCrtLiftShoup)) return false;
        RawSetupWidths widths{};
        for (u32 j = 0; j < rho; ++j)
        {
            if (coefficientBits[j] < 2 || coefficientBits[j] > 60) return false;
            widths.mBits[j] = coefficientBits[j];
        }
        const auto cudaStream = asStream(stream);
        if (!check(cudaMemsetAsync(fiveStatuses, 0, 5u * sizeof(u32), cudaStream),
            "nativeSealBundleStatus")) return false;
        rawSetupSelectSealCoeffValueKernel<<<1, 32, 0, cudaStream>>>(
            n, widths, rho, orderedQ, fiveStatuses);
        if (!check(cudaGetLastError(), "nativeSealBundleCoeffSelect")) return false;
        rawSetupModuliKernel<<<1, 32, 0, cudaStream>>>(
            ring, orderedQ, ringScratch, fiveStatuses + 1u, fiveStatuses);
        if (!check(cudaGetLastError(), "nativeSealBundleRingModuli")) return false;
        const dim3 ringGrid((n + 255u) / 256u, rho);
        rawSetupMinimumRootsKernel<<<ringGrid, 256, 0, cudaStream>>>(
            ring, ringScratch, fiveStatuses + 1u);
        if (!check(cudaGetLastError(), "nativeSealBundleRingRoots")) return false;
        rawSetupNttScalarsKernel<<<1, 32, 0, cudaStream>>>(
            ring, ringScratch, fiveStatuses + 1u);
        if (!check(cudaGetLastError(), "nativeSealBundleRingScalars")) return false;
        rawSetupNttTablesKernel<<<ringGrid, 256, 0, cudaStream>>>(
            ring, ringScratch, fiveStatuses + 1u);
        if (!check(cudaGetLastError(), "nativeSealBundleRingNtt")) return false;
        rawSetupCrtKernel<<<1, 32, 0, cudaStream>>>(
            ring, denoise, crtLift, inverseCrtLift, sampleMaxMultiple,
            fiveStatuses + 1u);
        if (!check(cudaGetLastError(), "nativeSealBundleRingCrt")) return false;
        rawSetupSelectSealPlainFromQKernel<<<1, 32, 0, cudaStream>>>(
            n, requestedPlaintextBits, orderedQ, rho,
            fiveStatuses, fiveStatuses + 1u,
            selectedP, selectedBits, fiveStatuses + 2u);
        if (!check(cudaGetLastError(), "nativeSealBundlePlainSelect")) return false;
        rawSetupModuliKernel<<<1, 32, 0, cudaStream>>>(
            plain, selectedP, plainScratch, fiveStatuses + 3u,
            fiveStatuses + 2u);
        if (!check(cudaGetLastError(), "nativeSealBundlePlainModuli")) return false;
        const dim3 plainGrid((n + 255u) / 256u, 1u);
        rawSetupMinimumRootsKernel<<<plainGrid, 256, 0, cudaStream>>>(
            plain, plainScratch, fiveStatuses + 3u);
        if (!check(cudaGetLastError(), "nativeSealBundlePlainRoots")) return false;
        rawSetupNttScalarsKernel<<<1, 32, 0, cudaStream>>>(
            plain, plainScratch, fiveStatuses + 3u);
        if (!check(cudaGetLastError(), "nativeSealBundlePlainScalars")) return false;
        rawSetupNttTablesKernel<<<plainGrid, 256, 0, cudaStream>>>(
            plain, plainScratch, fiveStatuses + 3u);
        if (!check(cudaGetLastError(), "nativeSealBundlePlainNtt")) return false;
        // The slot permutation depends only on N, but a failed upstream stage
        // should not perform extra setup or write an unpublished table.
        rawSetupSlotMapsKernel<<<(n / 2u + 255u) / 256u, 256, 0, cudaStream>>>(
            n, ring.mLogN, slotMap, inverseSlotMap, fiveStatuses + 3u);
        if (!check(cudaGetLastError(), "nativeSealBundleSlotMap")) return false;
        rawSetupPlaintextLiftFromDeviceKernel<<<1, 32, 0, cudaStream>>>(
            ring, orderedQ, selectedP, plaintextLift, fiveStatuses);
        return check(cudaGetLastError(), "nativeSealBundleLift");
    }

    bool launchPreparePow2Factors(const RingConstView& rc, u32 shiftBits, u64* factors, void* stream)
    {
        if (!rc.mRho || rc.mRho > kMaxRawSetupWords || !rc.mMods || !factors) return false;
        rawSetupPow2Kernel<<<1, 32, 0, asStream(stream)>>>(rc, shiftBits, factors);
        return check(cudaGetLastError(), "rawSetupPow2");
    }

    bool launchPrepareScaleRoundConstants(const RingConstView& rc, u64 p,
        const ScaleRoundConstView& out, void* stream)
    {
        if (!rc.mRho || rc.mRho > kMaxRawSetupWords || !rc.mMods || !rc.mInvPuncturedProd ||
            !p || p >= rc.mMinModulus || !out.mQ || !out.mCrtInvPunctured ||
            !out.mPShoup || !out.mFracLo || !out.mFracHi || !out.mFastLimbs) return false;
        rawSetupScaleRoundKernel<<<1, 32, 0, asStream(stream)>>>(rc, p, out);
        return check(cudaGetLastError(), "rawSetupScaleRound");
    }

    bool launchDenoiseComb(
        const RingConstView& rc,
        const DenoiseConstView& dc,
        const u64* in,
        u64* out,
        u32 outCount,
        void* stream)
    {
        if (outCount == 0) return true;
        const DeviceRing rg = toDevice(rc);
        DeviceDenoise dn{};
        dn.mQ = dc.mQ;
        dn.mMods = static_cast<const GpuModulus*>(dc.mMods);
        dn.mSrcLimb = dc.mSrcLimb;
        dn.mCrtInvPunctured = dc.mCrtInvPunctured;
        dn.mPuncturedProdModTarget = dc.mPuncturedProdModTarget;
        dn.mCrtInvPuncturedShoup =
            static_cast<const ShoupOperand*>(dc.mCrtInvPuncturedShoup);
        dn.mScaledPuncturedShoup =
            static_cast<const ShoupOperand*>(dc.mScaledPuncturedShoup);
        dn.mFracInvLo = dc.mFracInvLo;
        dn.mFracInvHi = dc.mFracInvHi;
        dn.mCrtLiftModTarget = dc.mCrtLiftModTarget;
        dn.mInvCrtLiftModTarget = dc.mInvCrtLiftModTarget;
        dn.mInvCrtLiftShoup = static_cast<const ShoupOperand*>(dc.mInvCrtLiftShoup);
        const u32 threads = 256;
        const bool fixedRho4 =
            rc.mRho == 4u && rc.mN == kDenoiseRho4N;
        const bool nearEqualModuli =
            rc.mMinModulus != 0u && rc.mMaxModulus >= rc.mMinModulus &&
            (rc.mMaxModulus - rc.mMinModulus) < rc.mMinModulus;
        if (log14H200Shape(rc) &&
            nearEqualModuli && rc.mMinModulus > 8u &&
            rc.mMaxModulus < (u64(1) << 62u) && outCount <= 8191u &&
            dn.mCrtInvPuncturedShoup && dn.mScaledPuncturedShoup && dn.mInvCrtLiftShoup)
        {
            launchNoGoldDenoiseShoup(dn, in, out, outCount, asStream(stream));
            return check(cudaGetLastError(), "denoiseNoGoldShoup");
        }
        const bool useShoup =
            fixedRho4 && nearEqualModuli &&
            dn.mCrtInvPuncturedShoup && dn.mScaledPuncturedShoup &&
            dn.mInvCrtLiftShoup;
        const bool hotGeometry =
            fixedRho4 && outCount <= 16383u;
        if (useShoup && hotGeometry)
        {
            denoiseCombRho4FixedKernel<true, true, false><<<
                dim3(32u, 4u * outCount, 1u), threads, 0, asStream(stream)>>>(
                dn, in, out, outCount, nullptr, nullptr, nullptr);
            return check(cudaGetLastError(), "denoiseCombRho4ShoupHot");
        }
        if (useShoup)
        {
            denoiseCombRho4FixedKernel<true, false, false><<<
                grid2D(kDenoiseRho4PerPoly, outCount, threads), threads, 0,
                asStream(stream)>>>(dn, in, out, outCount, nullptr, nullptr, nullptr);
            return check(cudaGetLastError(), "denoiseCombRho4Shoup");
        }
        if (hotGeometry)
        {
            denoiseCombRho4FixedKernel<false, true, false><<<
                dim3(32u, 4u * outCount, 1u), threads, 0, asStream(stream)>>>(
                dn, in, out, outCount, nullptr, nullptr, nullptr);
            return check(cudaGetLastError(), "denoiseCombRho4HotGeometry");
        }
        if (rc.mRho == 4u)
        {
            denoiseCombSpecializedKernel<false><<<
                grid2D(4u * rc.mN, outCount, threads), threads, 0, asStream(stream)>>>(
                rg, dn, in, out, outCount, nullptr, nullptr, nullptr);
            return check(cudaGetLastError(), "denoiseCombSpecialized4");
        }
        denoiseCombKernel<false><<<
            grid2D(rc.mRho * rc.mN, outCount, threads), threads, 0, asStream(stream)>>>(
            rg, dn, in, out, outCount, nullptr, nullptr, nullptr);
        return check(cudaGetLastError(), "denoiseComb");
    }

    bool launchDenoiseCombValidate(
        const RingConstView& rc,
        const DenoiseConstView& dc,
        const u64* in,
        u64* out,
        u32 outCount,
        const u64* marginLo,
        const u64* marginHi,
        u32* failFlag,
        void* stream)
    {
        if (outCount == 0) return true;
        if (!marginLo || !marginHi || !failFlag) return false;
        const DeviceRing rg = toDevice(rc);
        DeviceDenoise dn{};
        dn.mQ = dc.mQ;
        dn.mMods = static_cast<const GpuModulus*>(dc.mMods);
        dn.mSrcLimb = dc.mSrcLimb;
        dn.mCrtInvPunctured = dc.mCrtInvPunctured;
        dn.mPuncturedProdModTarget = dc.mPuncturedProdModTarget;
        dn.mCrtInvPuncturedShoup =
            static_cast<const ShoupOperand*>(dc.mCrtInvPuncturedShoup);
        dn.mScaledPuncturedShoup =
            static_cast<const ShoupOperand*>(dc.mScaledPuncturedShoup);
        dn.mFracInvLo = dc.mFracInvLo;
        dn.mFracInvHi = dc.mFracInvHi;
        dn.mCrtLiftModTarget = dc.mCrtLiftModTarget;
        dn.mInvCrtLiftModTarget = dc.mInvCrtLiftModTarget;
        dn.mInvCrtLiftShoup = static_cast<const ShoupOperand*>(dc.mInvCrtLiftShoup);
        const u32 threads = 256;
        const bool fixedRho4 =
            rc.mRho == 4u && rc.mN == kDenoiseRho4N;
        const bool nearEqualModuli =
            rc.mMinModulus != 0u && rc.mMaxModulus >= rc.mMinModulus &&
            (rc.mMaxModulus - rc.mMinModulus) < rc.mMinModulus;
        const bool useShoup =
            fixedRho4 && nearEqualModuli &&
            dn.mCrtInvPuncturedShoup && dn.mScaledPuncturedShoup &&
            dn.mInvCrtLiftShoup;
        const bool hotGeometry =
            fixedRho4 && outCount <= 16383u;
        if (useShoup && hotGeometry)
        {
            denoiseCombRho4FixedKernel<true, true, true><<<
                dim3(32u, 4u * outCount, 1u), threads, 0, asStream(stream)>>>(
                dn, in, out, outCount, marginLo, marginHi, failFlag);
            return check(cudaGetLastError(), "denoiseCombValidateRho4ShoupHot");
        }
        if (useShoup)
        {
            denoiseCombRho4FixedKernel<true, false, true><<<
                grid2D(kDenoiseRho4PerPoly, outCount, threads), threads, 0,
                asStream(stream)>>>(
                dn, in, out, outCount, marginLo, marginHi, failFlag);
            return check(cudaGetLastError(), "denoiseCombValidateRho4Shoup");
        }
        if (hotGeometry)
        {
            denoiseCombRho4FixedKernel<false, true, true><<<
                dim3(32u, 4u * outCount, 1u), threads, 0, asStream(stream)>>>(
                dn, in, out, outCount, marginLo, marginHi, failFlag);
            return check(cudaGetLastError(), "denoiseCombValidateRho4HotGeometry");
        }
        if (rc.mRho == 4u)
        {
            denoiseCombSpecializedKernel<true><<<
                grid2D(4u * rc.mN, outCount, threads), threads, 0, asStream(stream)>>>(
                rg, dn, in, out, outCount, marginLo, marginHi, failFlag);
            return check(cudaGetLastError(), "denoiseCombValidateSpecialized4");
        }
        denoiseCombKernel<true><<<
            grid2D(rc.mRho * rc.mN, outCount, threads), threads, 0, asStream(stream)>>>(
            rg, dn, in, out, outCount, marginLo, marginHi, failFlag);
        return check(cudaGetLastError(), "denoiseCombValidate");
    }

    bool launchValidateGoldenSeed(
        const RingConstView& rc,
        const DenoiseConstView& dc,
        const u64* tbk,
        u32 polyCount,
        u32 mu,
        const u64* marginLo,
        const u64* marginHi,
        u32* failFlag,
        void* stream)
    {
        if (polyCount == 0 || mu == 0) return true;
        const DeviceRing rg = toDevice(rc);
        DeviceDenoise dn{};
        dn.mQ = dc.mQ;
        dn.mMods = static_cast<const GpuModulus*>(dc.mMods);
        dn.mSrcLimb = dc.mSrcLimb;
        dn.mCrtInvPunctured = dc.mCrtInvPunctured;
        dn.mPuncturedProdModTarget = dc.mPuncturedProdModTarget;
        dn.mCrtInvPuncturedShoup =
            static_cast<const ShoupOperand*>(dc.mCrtInvPuncturedShoup);
        dn.mScaledPuncturedShoup =
            static_cast<const ShoupOperand*>(dc.mScaledPuncturedShoup);
        dn.mFracInvLo = dc.mFracInvLo;
        dn.mFracInvHi = dc.mFracInvHi;
        dn.mCrtLiftModTarget = dc.mCrtLiftModTarget;
        dn.mInvCrtLiftModTarget = dc.mInvCrtLiftModTarget;
        dn.mInvCrtLiftShoup = static_cast<const ShoupOperand*>(dc.mInvCrtLiftShoup);

        const u32 threads = 256;
        const bool rho4Cycle = rc.mRho == 4u && (mu % 4u) == 0u;
        if (rho4Cycle &&
            rc.mN == kDenoiseRho4N && polyCount <= 65535u && dc.mQ &&
            dc.mCrtInvPuncturedShoup && dc.mFracInvLo && dc.mFracInvHi)
        {
            DeviceGoldenValidateRho4 gv{};
            gv.mQ = dc.mQ;
            gv.mCrtInvPunctured =
                static_cast<const ShoupOperand*>(dc.mCrtInvPuncturedShoup);
            gv.mFracInvLo = dc.mFracInvLo;
            gv.mFracInvHi = dc.mFracInvHi;
            validateGoldenSeedRho4ShoupKernel<<<
                dim3(32u, polyCount, 1u), threads, 0, asStream(stream)>>>(
                gv, tbk, marginLo, marginHi, failFlag);
            return check(cudaGetLastError(), "validateGoldenSeedRho4Shoup");
        }
        if (rho4Cycle)
        {
            validateGoldenSeedSpecializedKernel<<<
                grid2D(rc.mN, polyCount, threads), threads, 0, asStream(stream)>>>(
                rg, dn, tbk, polyCount, marginLo, marginHi, failFlag);
            return check(cudaGetLastError(), "validateGoldenSeedSpecialized4");
        }
        validateGoldenSeedKernel<<<grid2D(rc.mN, polyCount, threads), threads, 0, asStream(stream)>>>(
            rg, dn, tbk, polyCount, mu, marginLo, marginHi, failFlag);
        return check(cudaGetLastError(), "validateGoldenSeed");
    }

    bool launchValidateLeafGoldenSeed(
        const RingConstView& rc, const LeafGoldenSeedLimb* constants, const u64* tbk,
        u32 logicalPolyCount, u64 marginLo, u64 marginHi, u32* failFlag, void* stream)
    {
        if (!rc.mN || !rc.mRho || !logicalPolyCount || !constants || !tbk || !failFlag) return false;
        const u32 threads = 256;
        const auto grid = grid2D(rc.mN, logicalPolyCount, threads);
        const Wide margin{marginLo, marginHi};
        if (rc.mRho == 4u)
            validateLeafGoldenSeedKernel<4u><<<grid, threads, 0, asStream(stream)>>>(
                rc.mN, rc.mRho, constants, tbk, logicalPolyCount, margin, failFlag);
        else if (rc.mRho == 8u)
            validateLeafGoldenSeedKernel<8u><<<grid, threads, 0, asStream(stream)>>>(
                rc.mN, rc.mRho, constants, tbk, logicalPolyCount, margin, failFlag);
        else
            validateLeafGoldenSeedKernel<0u><<<grid, threads, 0, asStream(stream)>>>(
                rc.mN, rc.mRho, constants, tbk, logicalPolyCount, margin, failFlag);
        return check(cudaGetLastError(), "validateLeafGoldenSeed");
    }

    bool launchAggregate(
        const RingConstView& rc, const u64* in, u32 tau, u64* out, u32 outCount, void* stream)
    {
        if (outCount == 0 || tau == 0) return true;
        const DeviceRing rg = toDevice(rc);
        const u32 threads = 256;
        aggregateKernel<<<grid2D(rc.mRho * rc.mN, outCount, threads), threads, 0, asStream(stream)>>>(
            rg, in, tau, out, outCount);
        return check(cudaGetLastError(), "aggregate");
    }

    bool launchComposeReducePlain(
        const RingConstView& ringRc,
        const RingConstView& plainRc,
        const u64* in,
        u32 inCount,
        u64* out,
        void* stream)
    {
        if (!ringRc.mN || ringRc.mN != plainRc.mN ||
            !ringRc.mRho || ringRc.mRho > kMaxRawSetupWords ||
            plainRc.mRho != 1u || !ringRc.mMods || !plainRc.mMods ||
            !ringRc.mBaseProd || !ringRc.mPuncturedProd ||
            !ringRc.mInvPuncturedProd ||
            plainRc.mMinModulus != plainRc.mMaxModulus ||
            plainRc.mMinModulus <= 2u * ringRc.mN ||
            plainRc.mMinModulus >= ringRc.mMinModulus ||
            !in || !out || in == out) return false;
        if (!inCount) return true;
        const DeviceRing ring = toDevice(ringRc);
        const auto* plainMods = static_cast<const GpuModulus*>(plainRc.mMods);
        constexpr u32 threads = 128u;
        const dim3 grid = grid2D(ringRc.mN, inCount, threads);
        const cudaStream_t st = asStream(stream);
#define LV_LAUNCH_COMPOSE_REDUCE_PLAIN(W) \
        case W: composeReducePlainKernel<W><<<grid, threads, 0u, st>>>( \
            ring, plainMods, in, inCount, out); break
        switch (ringRc.mRho)
        {
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(1u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(2u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(3u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(4u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(5u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(6u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(7u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(8u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(9u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(10u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(11u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(12u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(13u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(14u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(15u);
        LV_LAUNCH_COMPOSE_REDUCE_PLAIN(16u);
        default: return false;
        }
#undef LV_LAUNCH_COMPOSE_REDUCE_PLAIN
        return check(cudaGetLastError(), "composeReducePlain");
    }

    bool launchScaleAndRound(
        const RingConstView& rc,
        const u64* in,
        u32 inCount,
        u64 plainModulus,
        const u64* crtInvPunctured,
        const u64* qValues,
        const u64* pShoup,
        const u64* fracInvLo,
        const u64* fracInvHi,
        const ScaleRoundFastLimb* fastLimbs,
        u64* out,
        void* stream)
    {
        if (inCount == 0) return true;
        const DeviceRing rg = toDevice(rc);
        const u32 threads = 256;
        if (pShoup)
        {
            if (fastLimbs && rc.mN == 8192u &&
                rc.mRho == 4u && inCount <= 65535u)
            {
                const dim3 grid(8192u / threads, inCount);
                // The high-word-first path relies on the production RNS
                // bound as well as the fixed rho/N geometry above.
                if (rc.mMaxModulus < (u64(1) << 60))
                {
                    scaleAndRoundHotRho4HiCarryKernel<<<
                        grid, threads, 0, asStream(stream)>>>(
                        in, plainModulus, fastLimbs, out);
                }
                else
                {
                    scaleAndRoundHotRho4Kernel<<<
                        grid, threads, 0, asStream(stream)>>>(
                        in, plainModulus, fastLimbs, out);
                }

                return check(cudaGetLastError(), "scaleAndRoundHotRho4");
            }

            scaleAndRoundKernel<true><<<
                grid2D(rc.mN, inCount, threads), threads, 0, asStream(stream)>>>(
                rg, in, inCount, plainModulus, crtInvPunctured, qValues, pShoup,
                fracInvLo, fracInvHi, out);

        }
        else
        {
            scaleAndRoundKernel<false><<<
                grid2D(rc.mN, inCount, threads), threads, 0, asStream(stream)>>>(
                rg, in, inCount, plainModulus, crtInvPunctured, qValues, pShoup,
                fracInvLo, fracInvHi, out);
        }
        return check(cudaGetLastError(), "scaleAndRound");
    }

    bool canLaunchScaleNttForwardGather(
        const RingConstView& ringRc,
        const RingConstView& plainRc,
        const u64* in,
        u32 inCount,
        u64 plainModulus,
        const ScaleRoundFastLimb* fastLimbs,
        const u32* inverseSlotMap,
        u32 slotCount,
        u64* out,
        u64 outCount)
    {
        constexpr u32 kN = 8192u;
        constexpr u32 kMaxGridX = 0x7fffffffu;
        return in && fastLimbs && plainRc.mRoots && inverseSlotMap && out &&
            inCount != 0u && inCount <= kMaxGridX && outCount != 0u &&
            outCount <= static_cast<u64>(inCount) * kN &&
            ringRc.mN == kN && ringRc.mLogN == 13u && ringRc.mRho == 4u &&
            plainRc.mN == kN && plainRc.mLogN == 13u && plainRc.mRho == 1u &&
            slotCount == kN && plainModulus != 0u &&
            plainRc.mMinModulus == plainModulus &&
            plainRc.mMaxModulus == plainModulus &&
            plainModulus < ringRc.mMinModulus &&
            ringRc.mMaxModulus < (u64(1) << 63u);
    }

    bool launchScaleNttForwardGather(
        const RingConstView& ringRc,
        const RingConstView& plainRc,
        const u64* in,
        u32 inCount,
        u64 plainModulus,
        const ScaleRoundFastLimb* fastLimbs,
        const u32* inverseSlotMap,
        const u32* slotMap,
        u32 slotCount,
        u64* out,
        u64 outCount,
        void* stream)
    {
        return launchScaleNttForwardGather(
            ringRc, plainRc, in, inCount, plainModulus, fastLimbs,
            inverseSlotMap, slotMap, slotCount, out, outCount, stream,
            false);
    }

    bool launchScaleNttForwardGather(
        const RingConstView& ringRc,
        const RingConstView& plainRc,
        const u64* in,
        u32 inCount,
        u64 plainModulus,
        const ScaleRoundFastLimb* fastLimbs,
        const u32* inverseSlotMap,
        const u32* slotMap,
        u32 slotCount,
        u64* out,
        u64 outCount,
        void* stream,
        bool /*alphaIsTwo*/)
    {
        if (!canLaunchScaleNttForwardGather(
                ringRc, plainRc, in, inCount, plainModulus, fastLimbs,
                inverseSlotMap, slotCount, out, outCount))
        {
            return false;
        }

        ScaleNttForwardGather8192Args args{};
        args.mIn = in;
        args.mFastLimbs = fastLimbs;
        args.mRoots = static_cast<const ShoupOperand*>(plainRc.mRoots);
        args.mInverseSlotMap = inverseSlotMap;
        args.mOut = out;
        args.mOutCount = outCount;
        args.mPlainModulus = plainModulus;

        constexpr size_t shBytes = 8192u * sizeof(u64);
        const u32 threads = 1024u;
        const bool hiCarry =
            ringRc.mMaxModulus < (u64(1) << 60u);
        if (hiCarry && slotMap)
        {
            if (!check(
                    cudaFuncSetAttribute(
                        scaleNttForwardGather8192Rho4HiCarrySlotOwnedKernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(scaleNttGather8192HiCarrySlotOwned)"))
                return false;
            scaleNttForwardGather8192Rho4HiCarrySlotOwnedKernel<<<
                inCount, threads, shBytes, asStream(stream)>>>(
                args, slotMap);
        }
        else if (hiCarry)
        {
            if (!check(
                    cudaFuncSetAttribute(
                        scaleNttForwardGather8192Rho4HiCarryKernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(scaleNttGather8192HiCarry)"))
                return false;
            scaleNttForwardGather8192Rho4HiCarryKernel<<<
                inCount, threads, shBytes, asStream(stream)>>>(args);
        }
        else
        {
            if (!check(
                    cudaFuncSetAttribute(
                        scaleNttForwardGather8192Rho4Kernel,
                        cudaFuncAttributeMaxDynamicSharedMemorySize,
                        static_cast<int>(shBytes)),
                    "cudaFuncSetAttribute(scaleNttGather8192FastSimpleIndex)"))
                return false;
            scaleNttForwardGather8192Rho4Kernel<<<
                inCount, threads, shBytes, asStream(stream)>>>(args);
        }
        return check(cudaGetLastError(), "scaleNttForwardGather8192Rho4");
    }


    bool launchGatherSlots(
        const u64* plain,
        u32 n,
        const u32* slotMap,
        u32 slotCount,
        u32 chunkCount,
        u64* out,
        u64 outCount,
        void* stream)
    {
        if (chunkCount == 0 || slotCount == 0 || outCount == 0) return true;
        const u32 threads = 256;
        gatherSlotsKernel<<<grid2D(slotCount, chunkCount, threads), threads, 0, asStream(stream)>>>(
            plain, n, slotMap, slotCount, chunkCount, out, outCount);
        return check(cudaGetLastError(), "gatherSlots");
    }

    bool launchScatterSlots(
        const u64* labels,
        u64 labelCount,
        u64 padValue,
        const u32* slotMap,
        u32 slotCount,
        u32 chunkCount,
        u64* plain,
        u32 n,
        void* stream,
        bool garbledInput)
    {
        if (chunkCount == 0 || slotCount == 0) return true;
        const u32 threads = 256;
        scatterSlotsKernel<<<grid2D(slotCount, chunkCount, threads), threads, 0, asStream(stream)>>>(
            labels, labelCount, padValue, slotMap, slotCount, chunkCount, plain, n, garbledInput);
        return check(cudaGetLastError(), "scatterSlots");
    }

    bool launchRepeatGarbledInputs(const u64* labels, u64 count, u32 n,
        u32 chunks, u64* out, void* stream)
    {
        if (!labels || !out || !count || n < 3 || !chunks) return false;
        const u32 threads = 256;
        repeatGarbledInputsKernel<<<grid2D(n, chunks, threads), threads, 0, asStream(stream)>>>(
            labels, count, n, chunks, out);
        return check(cudaGetLastError(), "repeatGarbledInputs");
    }

    bool launchLiftPlainToRing(
        const RingConstView& rc,
        const u64* plain,
        u32 chunkCount,
        const u64* liftModQ,
        u64* out,
        void* stream)
    {
        if (chunkCount == 0) return true;
        const DeviceRing rg = toDevice(rc);
        const u32 threads = 256;
        liftPlainToRingKernel<<<grid2D(rc.mRho * rc.mN, chunkCount, threads), threads, 0, asStream(stream)>>>(
            rg, plain, chunkCount, liftModQ, out);
        return check(cudaGetLastError(), "liftPlainToRing");
    }


    bool launchAesCtrScalars(
        const u64* seed, u64* out, u64 count, u64 modulus, void* stream)
    {
        if (!seed || !out || !count || !modulus) return false;
        const u64 blocks = (count >> 1u) + (count & 1u);
        const u32 grid = static_cast<u32>(std::min<u64>((blocks + 255u) / 256u, 4096u));
        aesCtrScalarsKernel<<<grid, 256, 0, asStream(stream)>>>(seed, out, count, modulus);
        return check(cudaGetLastError(), "aesCtrScalars");
    }

    namespace
    {
        bool prepareAesPrngKeys(const u64* seeds, u32 count,
            unsigned char* keys, std::size_t capacity, void* stream)
        {
            if (!seeds || !keys || (reinterpret_cast<std::uintptr_t>(keys) & 15u) ||
                capacity / 176u < count) return false;
            const u32 grid = static_cast<u32>(std::min<u64>((static_cast<u64>(count) + 127u) / 128u, 65535u));
            aesPrngExpandKernel<<<grid, 128, 0, asStream(stream)>>>(seeds, keys, count);
            return check(cudaGetLastError(), "aesPrngExpand");
        }
    }

    bool launchAesPrngStream(const u64* seeds, u64* out, u32 words, u32 count,
        unsigned char* keys, std::size_t capacity, void* stream)
    {
        if (!count) return true;
        if (!out || !words || count > std::numeric_limits<std::size_t>::max() / sizeof(u64) / words ||
            !prepareAesPrngKeys(seeds, count, keys, capacity, stream)) return false;
        aesPrngStreamKernel<false><<<std::min(count, 65535u), 128, 0, asStream(stream)>>>(
            keys, out, words, count, DeviceRing{}, nullptr, nullptr, nullptr, 0);
        return check(cudaGetLastError(), "aesPrngStream");
    }

    bool launchSampleUniformPolyAes(const RingConstView& rc, const u64* seeds,
        const u64* maxMultiple, u64* out, const u32* outIdx, u32 count,
        unsigned char* keys, std::size_t capacity, u32* rejectEpochs,
        u32 rejectEpoch, void* stream)
    {
        if (!count) return true;
        const u64 words = static_cast<u64>(rc.mN) * rc.mRho;
        if (!out || !maxMultiple || !rejectEpochs || !rejectEpoch || !words ||
            !rc.mMods || rc.mLogN >= 32u || (u64{1} << rc.mLogN) != rc.mN ||
            words > std::numeric_limits<u32>::max() ||
            count > std::numeric_limits<std::size_t>::max() / sizeof(u64) / words ||
            !prepareAesPrngKeys(seeds, count, keys, capacity, stream)) return false;
        const auto grid = std::min(count, 65535u);
        const auto ring = toDevice(rc);
        aesPrngStreamKernel<true><<<grid, 128, 0, asStream(stream)>>>(
            keys, out, static_cast<u32>(words), count, ring, maxMultiple, outIdx, rejectEpochs, rejectEpoch);
        if (!check(cudaGetLastError(), "aesUniform")) return false;
        aesUniformRepairKernel<<<grid, 128, 0, asStream(stream)>>>(
            ring, keys, maxMultiple, out, outIdx, count, rejectEpochs, rejectEpoch);
        return check(cudaGetLastError(), "aesUniformRepair");
    }

    bool launchRootZetaRho4(
        const RingConstView& rc,
        const u64* taskSeeds,
        unsigned char* roundKeys,
        u32* firstReject,
        u64* out,
        u32 rangesPerPoly,
        bool forceFirstReject,
        void* stream)
    {
        if (!taskSeeds || !roundKeys || !firstReject || !out ||
            rc.mN != 8192u || rc.mLogN != 13u || rc.mRho != 4u || !rc.mMods ||
            rc.mMaxModulus >= (u64(1) << 63u) ||
            rangesPerPoly < 2u || rangesPerPoly > 32u)
        {
            return false;
        }

        const auto st = asStream(stream);
        constexpr u32 expandThreads = 128u;
        const u32 tasks = kRootZetaPolys * rangesPerPoly;
        const u32 rangeCoeffs = (8192u + rangesPerPoly - 1u) / rangesPerPoly;
        rootZetaExpandKeysKernel<<<1u, expandThreads, 0, st>>>(
            taskSeeds, roundKeys, firstReject, tasks, rangeCoeffs);
        if (!check(cudaGetLastError(), "rootZetaExpandKeys")) return false;

        const u32 sampleThreads = rc.mKernelOptions.mRootZetaSampleThreads;
        const dim3 sampleBlocks(
            (rangeCoeffs + sampleThreads - 1u) / sampleThreads, tasks);
        rootZetaSampleRho4Kernel<<<sampleBlocks, sampleThreads, 0, st>>>(
            static_cast<const GpuModulus*>(rc.mMods), roundKeys, firstReject,
            out, rangesPerPoly, rangeCoeffs, forceFirstReject);
        if (!check(cudaGetLastError(), "rootZetaSampleRho4")) return false;

        // The repair launch is intentionally unconditional: its lanes return
        // after one flag read in the overwhelmingly common no-rejection case,
        // avoiding a synchronizing flag copy to the host.
        rootZetaRepairRho4Kernel<<<(tasks + 31u) / 32u, 32u, 0, st>>>(
            static_cast<const GpuModulus*>(rc.mMods), roundKeys, firstReject,
            out, rangesPerPoly, rangeCoeffs, forceFirstReject);
        return check(cudaGetLastError(), "rootZetaRepairRho4");
    }

    bool launchPolySeeds(
        const LogVoleGpuKernelOptions& options, const u64* seeds,
        u32 seedCount,
        u32 perSeedCount,
        u64 domainTag,
        u32 polyModulusDegree,
        u64 modulusCount,
        u64* outSeeds,
        unsigned char* roundKeys,
        void* stream)
    {
        if (seedCount == 0 || perSeedCount == 0) return true;
        const u32 total = seedCount * perSeedCount;
        const u32 threads = options.mCt2PolySeedThreads;
        const u32 blocks = (total + threads - 1u) / threads;

        if (options.mCt2SplitAes)
        {
            if (!roundKeys) return false;
            ct2PolySeedExpandKernel<<<blocks, threads, 0, asStream(stream)>>>(
                seeds, perSeedCount, domainTag, polyModulusDegree,
                modulusCount, total, roundKeys);
            if (!check(
                    cudaGetLastError(),
                    "polySeedExpand"))
            {
                return false;
            }
            constexpr u32 encryptThreads = 128;
            const u32 encryptTotal = total * 4u;
            const u32 encryptBlocks = (encryptTotal + encryptThreads - 1u) / encryptThreads;
            if (options.mCt2AesSharedSbox && total >= 32u &&
                (total & 31u) == 0u)
            {
                ct2PolySeedEncryptSharedSboxKernel<<<
                    encryptBlocks, encryptThreads, 0, asStream(stream)>>>(
                    roundKeys, total, outSeeds);
                return check(
                    cudaGetLastError(), "polySeedEncryptSharedSbox");
            }
            ct2PolySeedEncryptKernel<<<encryptBlocks, encryptThreads, 0, asStream(stream)>>>(
                roundKeys, total, outSeeds);
            return check(cudaGetLastError(), "polySeedEncrypt");
        }

        ct2PolySeedKernel<<<blocks, threads, 0, asStream(stream)>>>(
            seeds, perSeedCount, domainTag, polyModulusDegree, modulusCount, total, outSeeds);
        return check(cudaGetLastError(), "polySeeds");
    }

    bool launchRootZetaRho8(
        const RingConstView& rc, const u64* taskSeeds,
        unsigned char* roundKeys, u32* firstReject, u64* out,
        u32 rangesPerPoly, bool forceFirstReject, void* stream)
    {
        if (!taskSeeds || !roundKeys || !firstReject || !out || !rc.mMods ||
            rc.mN != 16384u || rc.mLogN != 14u || rc.mRho != 8u ||
            rc.mMaxModulus >= (u64(1) << 63u) ||
            rangesPerPoly < 2u || rangesPerPoly > 32u)
            return false;
        const auto st = asStream(stream);
        const u32 tasks = 3u * rangesPerPoly;
        const u32 rangeCoeffs = (16384u + rangesPerPoly - 1u) / rangesPerPoly;
        rootZetaExpandKeysRho8Kernel<<<1u, 128u, 0, st>>>(
            taskSeeds, roundKeys, firstReject, tasks, rangeCoeffs);
        if (!check(cudaGetLastError(), "rootZetaExpandKeysRho8")) return false;
        constexpr u32 threads = 256u;
        const dim3 blocks((rangeCoeffs + threads - 1u) / threads, tasks);
        rootZetaSampleRho8Kernel<<<blocks, threads, 0, st>>>(
            static_cast<const GpuModulus*>(rc.mMods), roundKeys, firstReject,
            out, rangesPerPoly, rangeCoeffs, forceFirstReject);
        if (!check(cudaGetLastError(), "rootZetaSampleRho8")) return false;
        // Device-side no-op in the common case; never read a rejection flag on
        // the host or synchronize just to decide whether to repair.
        rootZetaRepairRho8Kernel<<<(tasks + 31u) / 32u, 32u, 0, st>>>(
            static_cast<const GpuModulus*>(rc.mMods), roundKeys, firstReject,
            out, rangesPerPoly, rangeCoeffs, forceFirstReject);
        return check(cudaGetLastError(), "rootZetaRepairRho8");
    }


    bool launchCt2Seeds(
        const LogVoleGpuKernelOptions& options, const u64* prefix,
        u64 instanceBase,
        u32 chunkCount,
        u32 mu,
        u64 domainTag,
        u32 polyModulusDegree,
        u64 modulusCount,
        u64* ct2Scratch,
        u64* outSeeds,
        unsigned char* roundKeyScratch,
        void* stream)
    {
        if (chunkCount == 0 || mu == 0) return true;
        cudaStream_t st = asStream(stream);

        {
            const u32 threads = 128;
            const u32 blocks = (chunkCount + threads - 1u) / threads;
            ct2InstanceSeedKernel<<<blocks, threads, 0, st>>>(
                prefix, instanceBase, chunkCount, ct2Scratch);
            if (!check(cudaGetLastError(), "ct2InstanceSeed")) return false;
        }
        return launchPolySeeds(
            options, ct2Scratch, chunkCount, mu, domainTag, polyModulusDegree, modulusCount, outSeeds,
            roundKeyScratch, stream);
    }

}
