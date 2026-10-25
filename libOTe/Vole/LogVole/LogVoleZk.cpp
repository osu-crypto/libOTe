#include "libOTe/Vole/LogVole/LogVoleZk.h"

#include "libOTe/config.h"

#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCpuZkArith.h"
#include "libOTe/Vole/LogVole/LogVoleCpuZk.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"

#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuZk.h"
#endif

#include "cryptoTools/Crypto/RandomOracle.h"

#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <stdexcept>
#include <tuple>
#include <vector>

namespace osuCrypto::LogVole
{
    namespace
    {
        u64 powMod(u64 base, u64 exp, const seal::Modulus& mod)
        {
            u64 result = 1 % mod.value();
            u64 acc = base % mod.value();
            while (exp)
            {
                if (exp & 1) result = mulMod(result, acc, mod);
                acc = mulMod(acc, acc, mod);
                exp >>= 1;
            }
            return result;
        }
    }

    u64 zkPowMod(u64 base, u64 exp, u64 modulus)
    {
        if (modulus < 2) return 0;
        return powMod(base, exp, seal::Modulus(modulus));
    }

    namespace
    {
        u64 subMod(u64 lhs, u64 rhs, const seal::Modulus& mod)
        {
            return seal::util::sub_uint_mod(lhs, rhs, mod);
        }

        // Enough chunks to keep every worker busy without making the per-chunk
        // modular exponentiation that seeds the challenge power matter.
        std::size_t chunkCount(u64 items, u32 threads)
        {
            const std::size_t want = std::max<std::size_t>(1, threads) * 4;
            return static_cast<std::size_t>(std::min<u64>(want, std::max<u64>(1, items)));
        }

        // A uniform-enough field element for a public challenge. The modular
        // reduction of a 64-bit draw is biased by about 2^-9 relative to uniform
        // on a 55-bit prime, which changes a soundness error of |gates|/p by a
        // factor the statement does not care about.
        u64 nextFieldElement(PRNG& prng, u64 modulus)
        {
            return prng.get<u64>() % modulus;
        }

        u64 nextNonZeroFieldElement(PRNG& prng, u64 modulus)
        {
            u64 v = 0;
            while (v == 0) v = nextFieldElement(prng, modulus);
            return v;
        }
    }

    u64 zkChallengeScalar(block seed, u64 modulus)
    {
        PRNG prng(seed);
        return nextNonZeroFieldElement(prng, modulus);
    }

    u64 zkVoleRequestSize(u64 voleCount)
    {
        if (voleCount > (u64{1} << 63))
            throw std::invalid_argument("LogVole ZK request exceeds the largest representable power of two");
        u64 p = 1;
        while (p < voleCount) p <<= 1;
        return p;
    }

    bool makeZkMulCircuitForBudget(u64 voleBudget, u64 depth, block seed, ZkMulCircuit& out)
    {
        if (voleBudget < 2 || depth == 0) return false;
        // voleCount = width * (depth + 1) + 1 has to fit, so take the largest
        // width that does and let the caller see the resulting gate count.
        const u64 width = (voleBudget - 1) / (depth + 1);
        if (width == 0) return false;
        return makeZkMulCircuit(width * depth, depth, seed, out);
    }

    bool makeZkMulCircuit(u64 gateCount, u64 depth, block seed, ZkMulCircuit& out)
    {
        if (gateCount == 0 || depth == 0) return false;
        if (gateCount % depth) return false;

        out = ZkMulCircuit{};
        out.mDepth = depth;
        out.mWidth = gateCount / depth;
        if (out.mWidth == 0) return false;
        if (out.wireCount() > std::numeric_limits<u32>::max()) return false;

        out.mOperands.resize(static_cast<std::size_t>(2 * gateCount));
        PRNG prng(seed);
        const seal::Modulus widthMod(std::max<u64>(2, out.mWidth));

        // Gate g sits in layer 1 + g / width and draws both operands from the
        // layer below, which is what makes the witness evaluation width-parallel.
        for (u64 layer = 0; layer < depth; ++layer)
        {
            const u64 base = layer * out.mWidth;   // first wire of the layer below
            for (u64 j = 0; j < out.mWidth; ++j)
            {
                const u64 g = layer * out.mWidth + j;
                const u64 left = prng.get<u64>(), right = prng.get<u64>();
                out.mOperands[static_cast<std::size_t>(2 * g)] =
                    static_cast<u32>(base + (out.mWidth == 1 ? 0 : seal::util::barrett_reduce_64(left, widthMod)));
                out.mOperands[static_cast<std::size_t>(2 * g + 1)] =
                    static_cast<u32>(base + (out.mWidth == 1 ? 0 : seal::util::barrett_reduce_64(right, widthMod)));
            }
        }
        return true;
    }

    bool zkMulWitness(
        const ZkMulCircuit& circuit, u64 modulus, PRNG& prng, AlignedUnVec<u64>& wires,
        u64 voleSize)
    {
        return zkMulWitness(circuit, modulus, prng, wires, voleSize, 1);
    }

    bool zkMulWitness(
        const ZkMulCircuit& circuit, u64 modulus, PRNG& prng, AlignedUnVec<u64>& wires,
        u64 voleSize, u32 threads)
    {
        if (modulus < 2 || circuit.gateCount() == 0) return false;
        if (circuit.mOperands.size() != 2 * circuit.gateCount()) return false;
        if (voleSize && voleSize < circuit.voleCount()) return false;

        const seal::Modulus mod(modulus);
        const u64 total = voleSize ? voleSize : circuit.voleCount();
        wires.resize(static_cast<std::size_t>(total));
        std::fill(wires.data() + circuit.voleCount(), wires.data() + total, u64(0));

        for (u64 i = 0; i < circuit.mWidth; ++i) wires[i] = nextFieldElement(prng, modulus);
        const auto chunks = std::min<u64>(circuit.mWidth, std::max<u64>(1, threads));
        for (u64 layer = 0; layer < circuit.mDepth; ++layer)
        {
            const u64 firstGate = layer*circuit.mWidth;
            const u64 firstOutput = circuit.outputWire(firstGate);
            bool independent = true;
            for (u64 g = firstGate; g < firstGate+circuit.mWidth; ++g)
            {
                const u32 ix = circuit.mOperands[2*g], iy = circuit.mOperands[2*g+1];
                // Sequential dependencies within a layer retain scalar order.
                // Inputs beyond the current output are not an evaluated DAG.
                if (ix >= circuit.outputWire(g) || iy >= circuit.outputWire(g)) return false;
                independent &= ix < firstOutput && iy < firstOutput;
            }
            if (!independent)
            {
                detail::withCpuZkArithmetic(mod, [&](const auto& arithmetic) {
                    for (u64 g = firstGate; g < firstGate+circuit.mWidth; ++g)
                        wires[circuit.outputWire(g)] = arithmetic.multiply(
                            wires[circuit.mOperands[2*g]], wires[circuit.mOperands[2*g+1]]);
                });
                continue;
            }
            if (!detail::runParallelTasks(chunks, threads, [&](std::size_t chunk) {
                const u64 begin = chunk*circuit.mWidth/chunks, end = (chunk+1)*circuit.mWidth/chunks;
                const auto* operands = circuit.mOperands.data()+2*(firstGate+begin);
                auto* output = wires.data()+firstOutput+begin;
                if (!detail::cpuZkWitnessRange(operands, wires.data(), output, end-begin, mod))
                    detail::withCpuZkArithmetic(mod, [&](const auto& arithmetic) {
                        for (u64 g = begin; g < end; ++g)
                            wires[firstOutput+g] = arithmetic.multiply(
                                wires[circuit.mOperands[2*(firstGate+g)]],
                                wires[circuit.mOperands[2*(firstGate+g)+1]]);
                    });
                return true;
            })) return false;
        }
        wires[static_cast<std::size_t>(circuit.maskIndex())] = nextFieldElement(prng, modulus);
        return true;
    }

    bool zkMulProverResponse(
        const ZkMulCircuit& circuit,
        std::span<const u64> wires,
        std::span<const u64> macs,
        u64 chi,
        u64 modulus,
        u32 threads,
        ZkProof& out)
    {
        const u64 gates = circuit.gateCount();
        if (gates == 0 || modulus < 2) return false;
        if (wires.size() < circuit.voleCount() || macs.size() < circuit.voleCount()) return false;
        if (circuit.mOperands.size() != 2 * gates) return false;

        const seal::Modulus mod(modulus);
        const u64 firstOut = circuit.mWidth;
        const u32* ops = circuit.mOperands.data();

        // Workers traverse circuit layers in the same order to encourage
        // shared-cache reuse of random label/witness reads. There is no layer
        // barrier. Fixed ranges previously outperformed finer dynamic blocks
        // across the two settings.
        const std::size_t chunks = static_cast<std::size_t>(
            std::min<u64>(circuit.mWidth, std::max<u64>(1, threads)));
        seal::util::MultiplyUIntModOperand chiOperand;
        chiOperand.set(chi % modulus, mod);
        std::vector<std::array<u64, 2>> partial(chunks, { 0, 0 });

        detail::withCpuZkArithmetic(mod, [&](const auto& arithmetic) {
            detail::runParallelTasks(chunks, threads, [&](std::size_t c) {
                u64 u = 0;
                u64 v = 0;
                for (u64 layer = 0; layer < circuit.mDepth; ++layer)
                {
                    const u64 begin = layer * circuit.mWidth + c * circuit.mWidth / chunks;
                    const u64 end = layer * circuit.mWidth + (c + 1) * circuit.mWidth / chunks;
                    u64 pw = powMod(chi, begin + 1, mod);
                    std::array<u64, 2> sums;
                    if (detail::cpuZkProverRange(ops + 2 * begin, wires.data(), macs.data(),
                        macs.data() + firstOut + begin, end - begin, pw, chi, mod, sums))
                    {
                        u = addMod(u, sums[0], mod);
                        v = addMod(v, sums[1], mod);
                        continue;
                    }
                    for (u64 g = begin; g < end; ++g)
                    {
                        const u32 ix = ops[2 * g];
                        const u32 iy = ops[2 * g + 1];
                        const u64 mx = macs[ix];
                        const u64 my = macs[iy];
                        const u64 mz = macs[static_cast<std::size_t>(firstOut + g)];

                        const u64 a0 = arithmetic.multiply(mx, my);
                        const u64 t = addMod(
                            arithmetic.multiply(wires[ix], my), arithmetic.multiply(wires[iy], mx), mod);
                        const u64 a1 = subMod(mz, t, mod);

                        u = arithmetic.multiplyAdd(pw, a0, u);
                        v = arithmetic.multiplyAdd(pw, a1, v);
                        pw = seal::util::multiply_uint_mod(pw, chiOperand, mod);
                    }
                }
                partial[c] = { u, v };
                return true;
            });
        });

        u64 u = 0;
        u64 v = 0;
        for (const auto& p : partial)
        {
            u = addMod(u, p[0], mod);
            v = addMod(v, p[1], mod);
        }

        const auto mask = static_cast<std::size_t>(circuit.maskIndex());
        out.mU = addMod(u, macs[mask], mod);
        out.mV = subMod(v, wires[mask] % modulus, mod);
        return true;
    }

    bool zkMulVerifierValue(
        const ZkMulCircuit& circuit,
        std::span<const u64> keys,
        u64 chi,
        u64 delta,
        u64 modulus,
        u32 threads,
        u64& out)
    {
        const u64 gates = circuit.gateCount();
        if (gates == 0 || modulus < 2) return false;
        if (keys.size() < circuit.voleCount()) return false;
        if (circuit.mOperands.size() != 2 * gates) return false;

        const seal::Modulus mod(modulus);
        const u64 firstOut = circuit.mWidth;
        const u32* ops = circuit.mOperands.data();

        const std::size_t chunks = chunkCount(circuit.mWidth, threads);
        const std::size_t tasks = chunks * circuit.mDepth;
        seal::util::MultiplyUIntModOperand chiOperand;
        chiOperand.set(chi % modulus, mod);
        std::vector<u64> partial(tasks, 0);

        detail::withCpuZkArithmetic(mod, [&](const auto& arithmetic) {
            detail::runParallelTasks(tasks, threads, [&](std::size_t task) {
                u64 acc = 0;
                const u64 layer = task / chunks, c = task % chunks;
                {
                    const u64 begin = layer * circuit.mWidth + c * circuit.mWidth / chunks;
                    const u64 end = layer * circuit.mWidth + (c + 1) * circuit.mWidth / chunks;
                    u64 pw = powMod(chi, begin + 1, mod);
                    if (detail::cpuZkVerifierRange(ops + 2 * begin, keys.data(),
                        keys.data() + firstOut + begin, end - begin, pw, chi, delta, mod, acc))
                    {
                        partial[task] = acc;
                        return true;
                    }
                    for (u64 g = begin; g < end; ++g)
                    {
                        const u32 ix = ops[2 * g];
                        const u32 iy = ops[2 * g + 1];
                        const u64 b = arithmetic.multiplyAdd(
                            keys[static_cast<std::size_t>(firstOut + g)], delta,
                            arithmetic.multiply(keys[ix], keys[iy]));
                        acc = arithmetic.multiplyAdd(pw, b, acc);
                        pw = seal::util::multiply_uint_mod(pw, chiOperand, mod);
                    }
                }
                partial[task] = acc;
                return true;
            }, true);
        });

        u64 acc = 0;
        for (u64 p : partial) acc = addMod(acc, p, mod);
        out = addMod(acc, keys[static_cast<std::size_t>(circuit.maskIndex())], mod);
        return true;
    }

    // ---- matrix multiplication -------------------------------------------

    bool validateZkMatMulStatement(const ZkMatMulStatement& st)
    {
        const u64 maxWords = std::numeric_limits<std::size_t>::max() / sizeof(u64);
        const u64 reps = st.repetitions();
        return st.mDim != 0 && st.mDim <= maxWords / st.mDim &&
            reps <= maxWords && st.entries() <= (maxWords - reps) / 2u &&
            st.entries() <= maxWords / reps;
    }

    namespace
    {
        bool validMatMulChallenge(
            const ZkMatMulStatement& st, const ZkMatMulChallenge& ch, u64 modulus)
        {
            return validateZkMatMulStatement(st) && modulus >= 2 &&
                ch.mCoefficients.size() == st.entries() * st.repetitions() &&
                std::all_of(ch.mCoefficients.begin(), ch.mCoefficients.end(),
                    [modulus](u64 value) { return value < modulus; });
        }

        bool validMatMulPublicProduct(
            const ZkMatMulStatement& st, std::span<const u64> product, u64 modulus)
        {
            return validateZkMatMulStatement(st) && modulus >= 2 &&
                product.size() == st.entries() &&
                std::all_of(product.begin(), product.end(),
                    [modulus](u64 value) { return value < modulus; });
        }
        // Protocol inputs are canonical; normalize low-level caller inputs
        // once before using bounded raw-product accumulation.
        const u64* canonicalMatMulInput(
            const u64* source, std::size_t count, u64 modulus, AlignedUnVec<u64>& owned)
        {
            if (std::all_of(source, source + count, [modulus](u64 x) { return x < modulus; }))
                return source;
            owned.resize(count);
            std::transform(source, source + count, owned.begin(),
                [modulus](u64 x) { return x < modulus ? x : x % modulus; });
            return owned.data();
        }

        void transposeMatMulInput(
            const u64* source, std::size_t n, u64 modulus, AlignedUnVec<u64>& transposed)
        {
            transposed.resize(n * n);
            constexpr std::size_t tile = 32;
            for (std::size_t i0 = 0; i0 < n; i0 += tile)
                for (std::size_t j0 = 0; j0 < n; j0 += tile)
                    for (std::size_t i = i0; i < std::min(n, i0 + tile); ++i)
                        for (std::size_t j = j0; j < std::min(n, j0 + tile); ++j)
                        {
                            const u64 x = source[i * n + j];
                            transposed[j * n + i] = x < modulus ? x : x % modulus;
                        }
        }

        template<bool Dual>
        std::array<u64, 2> batchMatMulTerms(
            const u64* first, const u64* second, const u64* coefficients,
            std::size_t begin, std::size_t end, const seal::Modulus& mod)
        {
            std::array<u64, 2> result{0, 0};
#if defined(__SIZEOF_INT128__)
            // Each canonical product is <2^(2*bits). The bounded chunk leaves
            // two spare accumulator bits, for every supported SEAL modulus.
            const unsigned shift = std::min<unsigned>(20, 126 - 2 * mod.bit_count());
            const std::size_t block = std::size_t{1} << shift;
            for (std::size_t start = begin; start < end;)
            {
                const auto stop = start + std::min(block, end - start);
                __uint128_t a = 0, b = 0;
                for (std::size_t i = start; i < stop; ++i)
                {
                    a += static_cast<__uint128_t>(coefficients[i]) * first[i];
                    if constexpr (Dual) b += static_cast<__uint128_t>(coefficients[i]) * second[i];
                }
                result[0] = addMod(result[0], static_cast<u64>(a % mod.value()), mod);
                if constexpr (Dual)
                    result[1] = addMod(result[1], static_cast<u64>(b % mod.value()), mod);
                start = stop;
            }
#else
            for (std::size_t i = begin; i < end; ++i)
            {
                result[0] = mulAddMod(coefficients[i], first[i], result[0], mod);
                if constexpr (Dual) result[1] = mulAddMod(coefficients[i], second[i], result[1], mod);
            }
#endif
            return result;
        }
    }

    bool zkMatMulWitnessInputs(
        const ZkMatMulStatement& st, u64 modulus, PRNG& prng, AlignedUnVec<u64>& wires,
        u64 voleSize)
    {
        if (!validateZkMatMulStatement(st) || modulus < 2) return false;
        if (voleSize && voleSize < st.voleCount()) return false;
        const u64 total = voleSize ? voleSize : st.voleCount();
        if (total > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return false;
        wires.resize(static_cast<std::size_t>(total));
        for (u64 i = 0; i < 2 * st.entries(); ++i) wires[i] = nextFieldElement(prng, modulus);
        for (u32 rep = 0; rep < st.repetitions(); ++rep)
            wires[static_cast<std::size_t>(st.maskIndex(rep))] = nextFieldElement(prng, modulus);
        std::fill(wires.data() + st.voleCount(), wires.data() + total, u64(0));
        return true;
    }

    bool zkMatMulFillProduct(
        const ZkMatMulStatement& st, u64 modulus, u32 threads,
        std::span<const u64> wires, AlignedUnVec<u64>& publicProduct)
    {
        if (!validateZkMatMulStatement(st) || modulus < 2 || wires.size() < st.voleCount()) return false;
        const seal::Modulus mod(modulus);
        const u64 n = st.mDim;
        AlignedUnVec<u64> product(st.entries());
        const u64* a = wires.data() + st.offsetA();
        const u64* b = wires.data() + st.offsetB();
        const bool ok = detail::runParallelTasks(static_cast<std::size_t>(n), threads, [&](std::size_t row) {
            u64* out = product.data() + row * n;
            std::fill(out, out + n, u64(0));
            for (u64 k = 0; k < n; ++k)
            {
                const u64 av = a[row * n + k];
                if (!av) continue;
                const u64* brow = b + k * n;
                for (u64 j = 0; j < n; ++j) out[j] = mulAddMod(av, brow[j], out[j], mod);
            }
            return true;
        });
        if (ok) publicProduct = std::move(product);
        return ok;
    }

    bool zkMatMulWitness(
        const ZkMatMulStatement& st, u64 modulus, u32 threads, PRNG& prng,
        AlignedUnVec<u64>& wires, AlignedUnVec<u64>& publicProduct, u64 voleSize)
    {
        return zkMatMulWitnessInputs(st, modulus, prng, wires, voleSize) &&
               zkMatMulFillProduct(st, modulus, threads, wires, publicProduct);
    }

    void zkMatMulChallenge(
        const ZkMatMulStatement& st, block seed, u64 modulus, ZkMatMulChallenge& out)
    {
        if (!validateZkMatMulStatement(st) || modulus < 2)
            throw std::invalid_argument("LogVole ZK matmul challenge parameters are invalid");
        PRNG prng(seed);
        const u64 threshold = (u64{0} - modulus) % modulus;
        ZkMatMulChallenge next;
        next.mCoefficients.resize(static_cast<std::size_t>(st.entries() * st.repetitions()));
        for (auto& coefficient : next.mCoefficients)
        {
            u64 sample;
            do { sample = prng.get<u64>(); } while (sample < threshold);
            coefficient = sample % modulus;
        }
        out = std::move(next);
    }

    bool zkMatMulProverResponse(
        const ZkMatMulStatement& st,
        std::span<const u64> wires,
        std::span<const u64> macs,
        const ZkMatMulChallenge& ch,
        u64 modulus,
        u32 threads,
        std::vector<ZkProof>& out)
    {
        if (!validMatMulChallenge(st, ch, modulus) ||
            wires.size() < st.voleCount() || macs.size() < st.voleCount()) return false;
        const seal::Modulus mod(modulus);
        const auto n = static_cast<std::size_t>(st.mDim), entries = static_cast<std::size_t>(st.entries());
        const auto chunks = std::min<std::size_t>(n, std::max<u32>(1, threads));
        AlignedUnVec<u64> ownedA, ownedMa, bt, mbt, a0(entries), cross(entries);
        const u64* a = canonicalMatMulInput(wires.data(), entries, modulus, ownedA);
        const u64* ma = canonicalMatMulInput(macs.data(), entries, modulus, ownedMa);
        transposeMatMulInput(wires.data() + st.offsetB(), n, modulus, bt);
        transposeMatMulInput(macs.data() + st.offsetB(), n, modulus, mbt);
        const bool ok = detail::runParallelTasks(chunks, threads, [&](std::size_t chunk) {
            const auto begin = chunk * n / chunks, end = (chunk + 1) * n / chunks;
            if (detail::cpuZkMatMulProverTerms(a, ma, bt.data(), mbt.data(), a0.data(), cross.data(),
                    n, begin, end, mod)) return true;
            detail::withCpuZkArithmetic(mod, [&](const auto& arithmetic) {
                for (std::size_t i = begin; i < end; ++i)
                    for (std::size_t j = 0; j < n; ++j)
                    {
                        u64 sum = 0, mixed = 0;
                        for (std::size_t k = 0; k < n; ++k)
                        {
                            sum = arithmetic.multiplyAdd(ma[i * n + k], mbt[j * n + k], sum);
                            mixed = arithmetic.multiplyAdd(a[i * n + k], mbt[j * n + k], mixed);
                            mixed = arithmetic.multiplyAdd(bt[j * n + k], ma[i * n + k], mixed);
                        }
                        a0[i * n + j] = sum;
                        cross[i * n + j] = mixed;
                    }
            });
            return true;
        });
        if (!ok) return false;

        // The n^2 unweighted inner products are identical for every repetition.
        // Reuse them; only the independent coefficients and masks change.
        std::vector<ZkProof> proofs(st.repetitions());
        for (u32 rep = 0; rep < st.repetitions(); ++rep)
        {
            std::vector<std::array<u64, 2>> partial(chunks);
            if (!detail::runParallelTasks(chunks, threads, [&](std::size_t chunk) {
                partial[chunk] = batchMatMulTerms<true>(a0.data(), cross.data(),
                    ch.mCoefficients.data() + rep * entries, chunk * entries / chunks,
                    (chunk + 1) * entries / chunks, mod);
                return true;
            })) return false;
            u64 u = 0, mixed = 0;
            for (const auto& sums : partial)
            {
                u = addMod(u, sums[0], mod);
                mixed = addMod(mixed, sums[1], mod);
            }
            proofs[rep].mU = addMod(u, macs[st.maskIndex(rep)] % modulus, mod);
            proofs[rep].mV = subMod(subMod(0, mixed, mod), wires[st.maskIndex(rep)] % modulus, mod);
        }
        out = std::move(proofs);
        return true;
    }

    bool zkMatMulProverResponse(
        const ZkMatMulStatement& st, std::span<const u64> wires, std::span<const u64> macs,
        const ZkMatMulChallenge& ch, u64 modulus, u32 threads, ZkProof& out)
    {
        if (st.repetitions() != 1) return false;
        std::vector<ZkProof> proofs;
        if (!zkMatMulProverResponse(st, wires, macs, ch, modulus, threads, proofs)) return false;
        out = proofs.front();
        return true;
    }

    bool zkMatMulVerifierValue(
        const ZkMatMulStatement& st,
        std::span<const u64> keys,
        std::span<const u64> publicProduct,
        const ZkMatMulChallenge& ch,
        u64 delta,
        u64 modulus,
        u32 threads,
        std::vector<u64>& out)
    {
        if (!validMatMulChallenge(st, ch, modulus) ||
            !validMatMulPublicProduct(st, publicProduct, modulus) || keys.size() < st.voleCount()) return false;
        const seal::Modulus mod(modulus);
        const auto n = static_cast<std::size_t>(st.mDim), entries = static_cast<std::size_t>(st.entries());
        const auto chunks = std::min<std::size_t>(n, std::max<u32>(1, threads));
        const u64 deltaSquared = mulMod(delta % modulus, delta % modulus, mod);
        AlignedUnVec<u64> ownedA, bt, products(entries);
        const u64* a = canonicalMatMulInput(keys.data(), entries, modulus, ownedA);
        transposeMatMulInput(keys.data() + st.offsetB(), n, modulus, bt);
        if (!detail::runParallelTasks(chunks, threads, [&](std::size_t chunk) {
            const auto begin = chunk * n / chunks, end = (chunk + 1) * n / chunks;
            const bool fast = detail::cpuZkMatMulVerifierTerms(a, bt.data(), products.data(), n, begin, end, mod);
            detail::withCpuZkArithmetic(mod, [&](const auto& arithmetic) {
                for (std::size_t i = begin; i < end; ++i)
                    for (std::size_t j = 0; j < n; ++j)
                    {
                        if (!fast)
                        {
                            u64 sum = 0;
                            for (std::size_t k = 0; k < n; ++k)
                                sum = arithmetic.multiplyAdd(a[i * n + k], bt[j * n + k], sum);
                            products[i * n + j] = sum;
                        }
                        products[i * n + j] = subMod(products[i * n + j],
                            arithmetic.multiply(publicProduct[i * n + j], deltaSquared), mod);
                    }
            });
            return true;
        })) return false;
        std::vector<u64> values(st.repetitions());
        for (u32 rep = 0; rep < st.repetitions(); ++rep)
        {
            std::vector<std::array<u64, 2>> partial(chunks);
            if (!detail::runParallelTasks(chunks, threads, [&](std::size_t chunk) {
                partial[chunk] = batchMatMulTerms<false>(products.data(), nullptr,
                    ch.mCoefficients.data() + rep * entries, chunk * entries / chunks,
                    (chunk + 1) * entries / chunks, mod);
                return true;
            })) return false;
            u64 b = 0;
            for (const auto& sums : partial) b = addMod(b, sums[0], mod);
            values[rep] = addMod(b, keys[st.maskIndex(rep)] % modulus, mod);
        }
        out = std::move(values);
        return true;
    }

    bool zkMatMulVerifierValue(
        const ZkMatMulStatement& st, std::span<const u64> keys,
        std::span<const u64> publicProduct, const ZkMatMulChallenge& ch, u64 delta,
        u64 modulus, u32 threads, u64& out)
    {
        if (st.repetitions() != 1) return false;
        std::vector<u64> values;
        if (!zkMatMulVerifierValue(st, keys, publicProduct, ch, delta, modulus, threads, values)) return false;
        out = values.front();
        return true;
    }

    bool zkMatMulAccept(std::span<const ZkProof> proofs, std::span<const u64> values,
        u64 delta, u64 modulus)
    {
        if (proofs.empty() || proofs.size() != values.size()) return false;
        bool accepted = true;
        for (std::size_t rep = 0; rep < proofs.size(); ++rep)
            accepted &= zkAccept(proofs[rep], values[rep], delta, modulus);
        return accepted;
    }

    bool zkAccept(const ZkProof& proof, u64 verifierValue, u64 delta, u64 modulus)
    {
        if (modulus < 2) return false;
        const seal::Modulus mod(modulus);
        return verifierValue == mulAddMod(proof.mV, delta, proof.mU % modulus, mod);
    }
}

// ---- device paths --------------------------------------------------------

#if defined(ENABLE_LOGVOLE_CUDA)
namespace osuCrypto::LogVole::gpu
{
    namespace
    {
        HostModulus toHostModulus(u64 modulus)
        {
            const seal::Modulus mod(modulus);
            const auto* ratio = mod.const_ratio().data();
            return HostModulus{ modulus, ratio[0], ratio[1] };
        }

        bool multiplicationModulus(u64 modulus, HostModulus& out)
        {
            if (modulus < 2 || modulus >= (u64{1} << 61u)) return false;
            const char* setting = std::getenv("LV_GPU_ZK_DEVICE_CONSTANTS");
            if (!setting || setting[0] != '0') return prepareZkModulusDevice(modulus, out);
            HostStep rollback("zk: host modulus constants rollback");
            out = toHostModulus(modulus);
            return true;
        }

        // Small owned device buffer. The ZK checks allocate a handful of these
        // once per statement and reuse them for every proof, which matters because
        // the caching allocator's cheapest path is still a lookup and these are
        // on the critical path of a sub-millisecond check.
        struct DeviceWords
        {
            u64* mData = nullptr;
            std::size_t mCount = 0;

            bool resize(std::size_t count)
            {
                if (mCount >= count) return true;
                release();
                mData = static_cast<u64*>(gpuMalloc(count * sizeof(u64)));
                if (!mData) return false;
                mCount = count;
                return true;
            }

            void release()
            {
                if (mData) gpuFree(mData);
                mData = nullptr;
                mCount = 0;
            }

            ~DeviceWords() { release(); }
        };

        void* orderAgainst(const DeviceScalars& s)
        {
            void* mine = threadStream().raw();
            if (auto* ps = s.producerStream(); ps && ps != mine) gpuStreamSync(ps);
            return mine;
        }

        // The device check has no CPU fallback once the output is on the GPU, so a
        // failure here is fatal to the proof. Report why rather than unwinding with
        // a bare "could not run its device check".
        bool zkFail(const char* where)
        {
            const char* msg = nullptr;
            if (!gpuLastErrorOk(&msg) && msg)
            {
                std::fprintf(stderr, "[lvzk] %s failed: %s\n", where, msg);
            }
            else
            {
                std::fprintf(stderr, "[lvzk] %s failed\n", where);
            }
            return false;
        }
    }

    bool prepareZkModulusDevice(u64 modulus, HostModulus& out)
    {
        if (!enabled() || modulus < 2 || modulus >= (u64{1} << 61u)) return false;
        const int device = currentDeviceOrdinal();
        // Backend streams and allocation caches support the single visible
        // device at ordinal zero, matching GpuRing::getRaw's policy.
        if (device != 0) return false;
        using Key = std::tuple<int, ProtocolCacheRole, u64>;
        static std::map<Key, HostModulus> cache;
        static std::mutex cacheMutex;
        try
        {
            std::lock_guard<std::mutex> lock(cacheMutex);
            const Key key{device, currentProtocolCacheScope().mRole, modulus};
            if (const auto found = cache.find(key); found != cache.end())
            {
                out = found->second;
                return true;
            }
            HostStep preparation("gpu: zk modulus constants");
            auto& stream = threadStream();
            DeviceWords storage;
            HostModulus next;
            StreamDrain drain{stream};
            static_assert(sizeof(HostModulus) == 3 * sizeof(u64));
            if (!storage.resize(3) ||
                !launchZkPrepareModulus(modulus, reinterpret_cast<HostModulus*>(storage.mData), stream.raw()) ||
                !gpuMemcpyD2H(&next, storage.mData, sizeof(next), stream.raw()) || !stream.sync()) return false;
            if (next.mValue != modulus) return false;
            cache.emplace(key, next);
            out = next;
            return true;
        }
        catch (const std::exception&) { return false; }
    }

    bool zkAcceptDevice(const ZkProof& proof, u64 verifierValue, u64 delta,
        u64 modulus, bool& accepted)
    {
        if (!enabled()) return false;
        HostModulus mod;
        if (!prepareZkModulusDevice(modulus, mod)) return false;
        HostStep acceptance("gpu: zk proof acceptance");
        auto& stream = threadStream();
        DeviceWords storage;
        u64 result = 0;
        StreamDrain drain{stream};
        if (!storage.resize(1) ||
            !launchZkAccept(proof.mU, proof.mV, verifierValue, delta, mod, storage.mData, stream.raw()) ||
            !gpuMemcpyD2H(&result, storage.mData, sizeof(result), stream.raw()) || !stream.sync()) return false;
        accepted = result != 0;
        return true;
    }

    // Immutable wiring shared by circuit copies within one party. Separate
    // parties generate their own allocation; detachment also protects callers
    // that hand the same circuit object to both protocol wrappers.
    struct ZkOperandsDevice
    {
        u32* mData = nullptr;
        std::size_t mCount = 0;

        ~ZkOperandsDevice()
        {
            if (mData) gpuFree(mData);
        }

        bool upload(std::span<const u32> host)
        {
            auto& stream = threadStream();
            mData = static_cast<u32*>(gpuMalloc(host.size() * sizeof(u32)));
            if (!mData) return false;
            mCount = host.size();
            // Public preprocessing: the wiring does not change between proofs, so
            // this upload happens once and never on a proof's critical path.
            return gpuMemcpyH2D(
                       mData, host.data(), host.size() * sizeof(u32), stream.raw()) &&
                   stream.sync();
        }
    };

    // Device state for one multiplication-gate statement: the public wiring plus
    // the partial-sum scratch.
    struct ZkMulDeviceState
    {
        std::shared_ptr<ZkOperandsDevice> mOperandsOwned;
        const u32* mOperands = nullptr;
        DeviceWords mScratch;
        DeviceWords mOut;

        bool prepare(const ZkMulCircuit& circuit)
        {
            const std::size_t needed = static_cast<std::size_t>(2 * circuit.gateCount());
            if (!circuit.mOperandsDevice && circuit.mOperands.size() != needed) return false;

            // Establish this thread's stream *before* allocating. gpuMalloc tags the
            // block it hands out with the caller's current stream and, when it
            // recycles a block another stream last used, makes that stream wait on
            // an event from the previous owner. Allocating with whatever stream the
            // VOLE happened to leave current puts that wait on the wrong stream, and
            // then the check reads a buffer the previous owner is still writing:
            // wrong U and V on the first proof of a process, or an illegal access.
            (void)threadStream();
            if (!mScratch.resize(kZkScratchWords) || !mOut.resize(2)) return false;
            if (mOperands) return true;

            // Prefer the copy the circuit already carries; only upload one of our
            // own when the caller did not hand one over.
            if (circuit.mOperandsDevice)
            {
                mOperandsOwned =
                    std::static_pointer_cast<ZkOperandsDevice>(circuit.mOperandsDevice);
            }
            else
            {
                mOperandsOwned = std::make_shared<ZkOperandsDevice>();
                if (!mOperandsOwned->upload(
                        std::span<const u32>(circuit.mOperands.data(), needed)))
                {
                    mOperandsOwned.reset();
                    return false;
                }
            }
            if (mOperandsOwned->mCount != needed) return false;
            mOperands = mOperandsOwned->mData;
            return true;
        }
    };


    // Dense independent coefficients and per-entry inner-product partials.
    struct ZkMatMulDeviceState
    {
        DeviceWords mCoefficients;
        DeviceWords mScratch;
        DeviceWords mProduct;
        DeviceWords mOut;
        u64 mDim = 0;
        u32 mReps = 0;

        bool prepare(const ZkMatMulStatement& st)
        {
            if (!validateZkMatMulStatement(st) || st.mDim > std::numeric_limits<u32>::max()) return false;
            const auto entries = static_cast<std::size_t>(st.entries());
            (void)threadStream();
            if (!mCoefficients.resize(entries * st.repetitions()) ||
                !mScratch.resize(2u * entries) || !mProduct.resize(entries) || !mOut.resize(2)) return false;
            mDim = st.mDim;
            mReps = st.repetitions();
            return true;
        }
    };

    // Waits for the stream that produced a device-resident VOLE output. Exposed so
    // that the protocol wrappers can attribute the wait to the VOLE rather than to
    // the check that happens to read the output first.
    void zkDrainProducer(const std::shared_ptr<void>& scalars)
    {
        if (!scalars || !enabled()) return;
        auto s = std::static_pointer_cast<DeviceScalars>(scalars);
        orderAgainst(*s);
        // Once the producing stream has been waited on there is nothing left to
        // order against, and the handle is a liability: the producer is a protocol
        // party running on its own host thread, threadStream() is thread_local, and
        // when that thread exits the stream is destroyed. A later reader - the
        // benchmark fetching the output to check it, say - would then hand a dead
        // handle to cudaStreamSynchronize, which crashed the process.
        s->setProducerStream(nullptr);
    }

    // Drains the calling thread's own stream as well. The check is queued there,
    // and the protocol leaves work on it that has nothing to do with the check;
    // without this the check's timing is really "whatever was still in flight plus
    // the check".
    void zkDrainSelf()
    {
        if (!enabled()) return;
        threadStream().sync();
    }

    std::shared_ptr<ZkMulDeviceState> makeZkMulDeviceState(const ZkMulCircuit& circuit)
    {
        if (!enabled()) return nullptr;
        auto st = std::make_shared<ZkMulDeviceState>();
        if (!st->prepare(circuit))
        {
            zkFail("mul device state build");
            return nullptr;
        }
        return st;
    }

    std::shared_ptr<ZkMatMulDeviceState> makeZkMatMulDeviceState(const ZkMatMulStatement& st)
    {
        if (!enabled()) return nullptr;
        auto out = std::make_shared<ZkMatMulDeviceState>();
        if (!out->prepare(st)) return nullptr;
        return out;
    }

    bool zkMulProverResponseDevice(
        const ZkMulCircuit& circuit,
        const DeviceScalars& wires,
        const DeviceScalars& macs,
        u64 chi,
        u64 modulus,
        ZkMulDeviceState& state,
        ZkProof& out)
    {
        if (!enabled() || !state.mOperands) return zkFail("mul prover state");
        if (wires.count() < circuit.voleCount() || macs.count() < circuit.voleCount())
        {
            return zkFail("mul prover operand size");
        }

        orderAgainst(wires);
        void* raw = orderAgainst(macs);
        auto& stream = threadStream();
        HostModulus mod;
        if (!multiplicationModulus(modulus, mod)) return zkFail("mul prover modulus");
        HostStep deviceCheck("gpu: zk multiplication prover");
        if (!launchZkMulProver(
                wires.data(), macs.data(), state.mOperands, circuit.gateCount(), circuit.mWidth,
                circuit.maskIndex(), chi, mod, state.mScratch.mData,
                state.mOut.mData, raw))
        {
            return zkFail("mul prover launch");
        }

        u64 host[2] = { 0, 0 };
        if (!gpuMemcpyD2H(host, state.mOut.mData, sizeof(host), raw) || !stream.sync())
        {
            return zkFail("mul prover readback");
        }
        out.mU = host[0];
        out.mV = host[1];
        return true;
    }

    bool zkMulVerifierValueDevice(
        const ZkMulCircuit& circuit,
        const DeviceScalars& keys,
        u64 chi,
        u64 delta,
        u64 modulus,
        ZkMulDeviceState& state,
        u64& out)
    {
        if (!enabled() || !state.mOperands) return zkFail("mul verifier state");
        if (keys.count() < circuit.voleCount()) return zkFail("mul verifier operand size");

        void* raw = orderAgainst(keys);
        auto& stream = threadStream();
        HostModulus mod;
        if (!multiplicationModulus(modulus, mod)) return zkFail("mul verifier modulus");
        HostStep deviceCheck("gpu: zk multiplication verifier");
        if (!launchZkMulVerifier(
                keys.data(), state.mOperands, circuit.gateCount(), circuit.mWidth,
                circuit.maskIndex(), chi, delta, mod, state.mScratch.mData,
                state.mOut.mData, raw))
        {
            return zkFail("mul verifier launch");
        }

        u64 host = 0;
        if (!gpuMemcpyD2H(&host, state.mOut.mData, sizeof(host), raw) || !stream.sync())
        {
            return zkFail("mul verifier readback");
        }
        out = host;
        return true;
    }

    bool zkMatMulProverResponseDevice(
        const ZkMatMulStatement& st,
        const DeviceScalars& wires,
        const DeviceScalars& macs,
        const ZkMatMulChallenge& ch,
        u64 modulus,
        ZkMatMulDeviceState& state,
        std::vector<ZkProof>& out)
    {
        if (!enabled() || !validMatMulChallenge(st, ch, modulus) || modulus >= (u64{1} << 61) ||
            st.mDim > std::numeric_limits<u32>::max() ||
            state.mDim != st.mDim || state.mReps != st.repetitions() ||
            wires.count() < st.voleCount() || macs.count() < st.voleCount()) return false;
        orderAgainst(wires);
        void* raw = orderAgainst(macs);
        std::array<u64, 2> host{};
        auto& stream = threadStream();
        // H2D copies borrow the caller's challenge/product until the stream
        // drains, including when a later copy or launch fails.
        StreamDrain drain{stream};
        const HostModulus mod = toHostModulus(modulus);
        if (!gpuMemcpyH2D(state.mCoefficients.mData, ch.mCoefficients.data(),
                ch.mCoefficients.size() * sizeof(u64), raw)) return false;
        std::vector<ZkProof> proofs(st.repetitions());
        for (u32 rep = 0; rep < st.repetitions(); ++rep)
        {
            if (!launchZkMatMulProver(wires.data(), macs.data(),
                    state.mCoefficients.mData + rep * st.entries(), static_cast<u32>(st.mDim),
                    st.maskIndex(rep), mod, state.mScratch.mData, state.mOut.mData, raw)) return false;
            if (!gpuMemcpyD2H(host.data(), state.mOut.mData, sizeof(host), raw) || !stream.sync()) return false;
            proofs[rep] = {host[0], host[1]};
        }
        out = std::move(proofs);
        return true;
    }

    bool zkMatMulVerifierValueDevice(
        const ZkMatMulStatement& st,
        const DeviceScalars& keys,
        std::span<const u64> publicProduct,
        const ZkMatMulChallenge& ch,
        u64 delta,
        u64 modulus,
        ZkMatMulDeviceState& state,
        std::vector<u64>& out)
    {
        if (!enabled() || !validMatMulChallenge(st, ch, modulus) ||
            !validMatMulPublicProduct(st, publicProduct, modulus) || modulus >= (u64{1} << 61) ||
            st.mDim > std::numeric_limits<u32>::max() ||
            state.mDim != st.mDim || state.mReps != st.repetitions() || keys.count() < st.voleCount()) return false;
        void* raw = orderAgainst(keys);
        std::vector<u64> values(st.repetitions());
        auto& stream = threadStream();
        // H2D copies borrow the caller's challenge/product until the stream
        // drains, including when a later copy or launch fails.
        StreamDrain drain{stream};
        const HostModulus mod = toHostModulus(modulus);
        // Public C is re-uploaded on every call, including same-shape statements.
        if (!gpuMemcpyH2D(state.mCoefficients.mData, ch.mCoefficients.data(),
                ch.mCoefficients.size() * sizeof(u64), raw) ||
            !gpuMemcpyH2D(state.mProduct.mData, publicProduct.data(), publicProduct.size() * sizeof(u64), raw)) return false;
        for (u32 rep = 0; rep < st.repetitions(); ++rep)
        {
            if (!launchZkMatMulVerifier(keys.data(), state.mProduct.mData,
                    state.mCoefficients.mData + rep * st.entries(), static_cast<u32>(st.mDim),
                    st.maskIndex(rep), delta % modulus, mod, state.mScratch.mData, state.mOut.mData, raw) ||
                !gpuMemcpyD2H(&values[rep], state.mOut.mData, sizeof(u64), raw) || !stream.sync()) return false;
        }
        out = std::move(values);
        return true;
    }

    bool zkMulUploadOperands(ZkMulCircuit& circuit)
    {
        if (!enabled() || circuit.gateCount() == 0) return false;
        const std::size_t needed = static_cast<std::size_t>(2 * circuit.gateCount());
        if (circuit.mOperandsDevice)
            return std::static_pointer_cast<ZkOperandsDevice>(circuit.mOperandsDevice)->mCount == needed;
        if (circuit.mOperands.size() != needed) return false;

        auto owned = std::make_shared<ZkOperandsDevice>();
        if (!owned->upload(std::span<const u32>(circuit.mOperands.data(), needed))) return false;
        circuit.mOperandsDevice = std::move(owned);
        return true;
    }

    static bool zkMulDeviceOperandsValid(const ZkMulCircuit& circuit)
    {
        if (!circuit.mOperandsDevice || !circuit.mWidth ||
            !circuit.mDepth || circuit.mDepth == std::numeric_limits<u64>::max() ||
            circuit.mWidth > std::numeric_limits<u32>::max() / (circuit.mDepth + 1))
            return false;
        const u64 words = 2 * circuit.gateCount();
        if (words > std::numeric_limits<std::size_t>::max() / sizeof(u32)) return false;
        const auto source = std::static_pointer_cast<ZkOperandsDevice>(circuit.mOperandsDevice);
        return source->mData && source->mCount == static_cast<std::size_t>(words);
    }

    bool zkMulDetachOperands(ZkMulCircuit& circuit)
    {
        if (!enabled() || !zkMulDeviceOperandsValid(circuit)) return false;
        const auto count = static_cast<std::size_t>(2 * circuit.gateCount());
        const auto source = std::static_pointer_cast<ZkOperandsDevice>(circuit.mOperandsDevice);

        HostStep preparationStep("gpu: zk detach circuit operands");
        auto& stream = threadStream();
        auto owned = std::make_shared<ZkOperandsDevice>();
        StreamDrain drain{stream};
        owned->mData = static_cast<u32*>(gpuMalloc(count * sizeof(u32)));
        if (!owned->mData) return false;
        owned->mCount = count;
        // Upload and seeded generation both complete before publishing their
        // immutable handle, so no foreign producer stream is needed here.
        if (!gpuMemcpyD2D(owned->mData, source->mData, count * sizeof(u32), stream.raw()) ||
            !stream.sync()) return false;
        circuit.mOperandsDevice = std::move(owned);
        return true;
    }

    bool makeZkMulCircuitForBudgetDevice(
        u64 voleBudget, u64 depth, block seed, ZkMulCircuit& out)
    {
        if (!enabled() || voleBudget < 2 || !depth || depth == std::numeric_limits<u64>::max())
            return false;
        const u64 width = (voleBudget - 1) / (depth + 1);
        if (!width || width > std::numeric_limits<u32>::max() / (depth + 1)) return false;
        HostStep preparationStep("gpu: zk prepare circuit");
        const u64 count = 2 * width * depth;
        auto residues = sampleScalarsFromSeed(seed, count, width);
        if (!residues) return false;
        auto& stream = threadStream();
        auto operands = std::make_shared<ZkOperandsDevice>();
        StreamDrain drain{stream};
        operands->mData = static_cast<u32*>(gpuMalloc(static_cast<std::size_t>(count) * sizeof(u32)));
        if (!operands->mData) return false;
        operands->mCount = static_cast<std::size_t>(count);
        if (!launchZkPackOperands(residues->data(), operands->mData, count, width, stream.raw()) ||
            !stream.sync()) return false;
        ZkMulCircuit next;
        next.mWidth = width;
        next.mDepth = depth;
        next.mOperandsDevice = std::move(operands);
        out = std::move(next);
        return true;
    }

    bool zkMulMaterializeOperands(ZkMulCircuit& circuit)
    {
        const auto count = static_cast<std::size_t>(2 * circuit.gateCount());
        if (!count) return false;
        if (circuit.mOperands.size() == count) return true;
        // Explicit materialization releases a device-only circuit to a CPU
        // consumer, including after GPU execution has been disabled. Its
        // existing allocation already establishes the CUDA ownership here.
        if (!circuit.mOperandsDevice) return false;
        const auto owned = std::static_pointer_cast<ZkOperandsDevice>(circuit.mOperandsDevice);
        if (owned->mCount != count) return false;
        AlignedUnVec<u32> next;
        next.resize(count);
        auto& stream = threadStream();
        StreamDrain drain{stream};
        if (!gpuMemcpyD2H(next.data(), owned->mData, count * sizeof(u32), stream.raw()) ||
            !stream.sync()) return false;
        circuit.mOperands = std::move(next);
        return true;
    }

    static DeviceScalarsPtr zkMulWitnessDeviceImpl(
        const ZkMulCircuit& circuit, u64 modulus, std::span<const u64> inputs, u64 voleSize,
        const DeviceScalarsPtr& deviceInputs)
    {
        if (!enabled() || circuit.gateCount() == 0 || modulus < 2) return nullptr;
        const u64 total = std::max(voleSize, circuit.voleCount());
        if ((deviceInputs ? deviceInputs->count() : inputs.size()) < circuit.mWidth + 1)
            return nullptr;
        const std::size_t operandWords = static_cast<std::size_t>(2 * circuit.gateCount());
        if (!circuit.mOperandsDevice && circuit.mOperands.size() != operandWords) return nullptr;

        auto& stream = threadStream();
        auto wires = std::make_shared<DeviceScalars>();
        std::shared_ptr<ZkOperandsDevice> temp;
        StreamDrain drain{stream};
        if (!wires->resize(static_cast<std::size_t>(total))) return nullptr;

        // Only the layer-0 values and the mask cross the bus; the rest of the
        // witness is produced in place. Everything past the committed range is the
        // request padding and stays zero.
        const std::size_t inputBytes = static_cast<std::size_t>(circuit.mWidth) * sizeof(u64);
        if (!gpuMemsetZero(wires->data(), static_cast<std::size_t>(total) * sizeof(u64), stream.raw()))
            return nullptr;
        const bool copied = deviceInputs
            ? gpuMemcpyD2D(wires->data(), deviceInputs->data(), inputBytes, stream.raw()) &&
              gpuMemcpyD2D(wires->data() + circuit.maskIndex(), deviceInputs->data() + circuit.mWidth,
                           sizeof(u64), stream.raw())
            : gpuMemcpyH2D(wires->data(), inputs.data(), inputBytes, stream.raw()) &&
              gpuMemcpyH2D(wires->data() + circuit.maskIndex(), inputs.data() + circuit.mWidth,
                           sizeof(u64), stream.raw());
        if (!copied)
        {
            return nullptr;
        }

        // Reuse the circuit's device wiring when it has one, so that evaluating the
        // witness does not need a second 8-bytes-per-gate buffer of its own.
        const u32* operands = nullptr;
        if (circuit.mOperandsDevice)
        {
            temp = std::static_pointer_cast<ZkOperandsDevice>(circuit.mOperandsDevice);
        }
        else
        {
            temp = std::make_shared<ZkOperandsDevice>();
            if (!temp->upload(std::span<const u32>(circuit.mOperands.data(), operandWords)))
            {
                return nullptr;
            }
        }
        if (temp->mCount != operandWords) return nullptr;
        operands = temp->mData;
        bool ok = true;

        HostModulus mod;
        if (!multiplicationModulus(modulus, mod)) return nullptr;
        for (u64 layer = 0; layer < circuit.mDepth && ok; ++layer)
        {
            ok = launchZkMulEvalLayer(
                wires->data(), operands, layer * circuit.mWidth, circuit.mWidth, circuit.mWidth,
                mod, stream.raw());
        }
        ok = ok && stream.sync();
        if (!ok) return nullptr;

        wires->setProducerStream(nullptr);
        return wires;
    }

    DeviceScalarsPtr zkMulWitnessDevice(
        const ZkMulCircuit& circuit, u64 modulus, std::span<const u64> inputs, u64 voleSize)
    {
        return zkMulWitnessDeviceImpl(circuit, modulus, inputs, voleSize, nullptr);
    }

    DeviceScalarsPtr zkMulWitnessDevice(
        const ZkMulCircuit& circuit, u64 modulus, block seed, u64 voleSize)
    {
        if (!enabled() || modulus < 2 || !circuit.mWidth || !circuit.mDepth) return nullptr;
        HostStep preparationStep("gpu: zk prepare witness inputs");
        auto inputs = sampleScalarsFromSeed(seed, circuit.mWidth + 1, modulus);
        if (!inputs) return nullptr;
        return zkMulWitnessDeviceImpl(circuit, modulus, {}, voleSize, inputs);
    }

    DeviceScalarsPtr zkMatMulWitnessInputsDevice(
        const ZkMatMulStatement& st, u64 modulus, block seed, u64 voleSize)
    {
        if (!enabled() || !validateZkMatMulStatement(st) || modulus < 2) return nullptr;
        const u64 entries = st.mDim * st.mDim;
        const u64 maxWords = std::numeric_limits<std::size_t>::max() / sizeof(u64);
        const u64 masks = st.repetitions();
        const u64 committed = st.voleCount();
        const u64 total = voleSize ? voleSize : committed;
        if (total < committed || total > maxWords) return nullptr;
        HostStep preparationStep("gpu: zk matmul prepare inputs");
        // The scalar stream has no C entries: the masks are the very next
        // sample after A and B, as in zkMatMulWitnessInputs.
        auto sampled = sampleScalarsFromSeed(seed, 2u * entries + masks, modulus);
        if (!sampled) return nullptr;
        auto& stream = threadStream();
        auto wires = std::make_shared<DeviceScalars>();
        StreamDrain drain{stream};
        if (!wires->resize(static_cast<std::size_t>(total)) ||
            !gpuMemcpyD2D(wires->data(), sampled->data(), 2u * entries * sizeof(u64), stream.raw()) ||
            !gpuMemsetZero(wires->data() + 2u * entries,
                (total - 2u * entries) * sizeof(u64), stream.raw()) ||
            !gpuMemcpyD2D(wires->data() + 2u * entries, sampled->data() + 2u * entries,
                masks * sizeof(u64), stream.raw()) || !stream.sync()) return nullptr;
        wires->setProducerStream(nullptr);
        return wires;
    }

    bool zkMatMulFillProductDevice(
        const DeviceScalars& wires, const ZkMatMulStatement& st, u64 modulus,
        DeviceScalars& publicProduct)
    {
        if (!enabled() || !validateZkMatMulStatement(st) || modulus < 2 || modulus >= (u64{1} << 61) ||
            st.mDim > std::numeric_limits<u32>::max() || &wires == &publicProduct ||
            wires.count() < st.voleCount()) return false;
        void* raw = orderAgainst(wires);
        (void)orderAgainst(publicProduct);
        auto& stream = threadStream();
        if (!publicProduct.resize(static_cast<std::size_t>(st.entries()))) return false;
        const bool ok = launchZkMatMulGemm(
            wires.data() + st.offsetA(), wires.data() + st.offsetB(), publicProduct.data(),
            static_cast<u32>(st.mDim), toHostModulus(modulus), raw) && stream.sync();
        publicProduct.setProducerStream(nullptr);
        return ok;
    }

}
#endif

// ---- protocol wrappers ---------------------------------------------------

namespace osuCrypto
{
    namespace
    {
        using namespace LogVole;

        double msSinceCheck(std::chrono::steady_clock::time_point t)
        {
            return std::chrono::duration<double, std::milli>(
                       std::chrono::steady_clock::now() - t)
                .count();
        }

        task<> sendBlock(Socket& sock, block value)
        {
            std::array<u8, 16> payload{};
            std::memcpy(payload.data(), value.data(), payload.size());
            co_await sock.send(coproto::copy(payload));
        }

        task<block> recvBlock(Socket& sock)
        {
            std::array<u8, 16> payload{};
            co_await sock.recv(payload);
            block value;
            std::memcpy(value.data(), payload.data(), payload.size());
            co_return value;
        }

        task<> sendProof(Socket& sock, const ZkProof& proof)
        {
            std::array<u64, 2> payload{ proof.mU, proof.mV };
            co_await sock.send(coproto::copy(payload));
        }

        task<ZkProof> recvProof(Socket& sock)
        {
            std::array<u64, 2> payload{};
            co_await sock.recv(payload);
            co_return ZkProof{ payload[0], payload[1] };
        }

        task<> sendMatMulProofs(Socket& sock, std::span<const ZkProof> proofs)
        {
            AlignedUnVec<u64> payload(2u * proofs.size());
            for (std::size_t rep = 0; rep < proofs.size(); ++rep)
            {
                payload[2u * rep] = proofs[rep].mU;
                payload[2u * rep + 1u] = proofs[rep].mV;
            }
            co_await sock.send(std::move(payload));
        }

        task<std::vector<ZkProof>> recvMatMulProofs(Socket& sock, u32 repetitions)
        {
            // The configured statement fixes the exact receive size; the peer
            // supplies no allocation length or repetition count on the wire.
            AlignedUnVec<u64> payload(2u * static_cast<std::size_t>(repetitions));
            co_await sock.recv(payload);
            std::vector<ZkProof> proofs(repetitions);
            for (u32 rep = 0; rep < repetitions; ++rep)
                proofs[rep] = {payload[2u * rep], payload[2u * rep + 1u]};
            co_return proofs;
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        std::shared_ptr<LogVole::gpu::DeviceScalars> asScalars(const std::shared_ptr<void>& p)
        {
            return std::static_pointer_cast<LogVole::gpu::DeviceScalars>(p);
        }
#endif

        // The authenticated mask is a chosen input, so fresh VOLE shares alone
        // do not refresh it. Replace it before committing every proof instance.
        void refreshProofMask(std::span<u64> wires, u64 maskIndex, u64 request,
            u64 modulus, PRNG& prng, const std::shared_ptr<void>& deviceWires)
        {
            if (modulus < 2 || maskIndex >= request ||
                (!wires.empty() && wires.size() != request) ||
                (wires.empty() && !deviceWires))
                throw std::runtime_error("LogVole ZK mask slot is invalid");
#if defined(ENABLE_LOGVOLE_CUDA)
            auto device = deviceWires ? asScalars(deviceWires) : nullptr;
            if (device && (!gpu::enabled() || !device->data() || device->count() != request))
                throw std::runtime_error("LogVole ZK mask device witness is invalid");
#else
            if (deviceWires)
                throw std::runtime_error("LogVole ZK device witness requires CUDA support");
#endif
            // Rejection sampling gives an exactly uniform field element.
            const u64 threshold = (u64{0} - modulus) % modulus;
            u64 sample;
            do { sample = prng.get<u64>(); } while (sample < threshold);
            const u64 mask = sample % modulus;
#if defined(ENABLE_LOGVOLE_CUDA)
            if (device)
            {
                auto& stream = gpu::threadStream();
                const auto producer = device->producerStream();
                if ((producer && producer != stream.raw() && !gpu::gpuStreamSync(producer)) ||
                    !gpu::launchZkSetMask(device->data() + maskIndex, mask, stream.raw()))
                    throw std::runtime_error("LogVole ZK could not refresh the device mask");
                device->setProducerStream(stream.raw());
            }
#endif
            if (!wires.empty()) wires[maskIndex] = mask;
        }
    }

    // ---- multiplication gates -------------------------------------------

    void ZkMulProver::configure(
        LogVole::ZkMulCircuit circuit, u32 plaintextModulusBits, u32 numThreads,
        LogVole::CivoleSetting setting, u64 voleRequest)
    {
        mCircuit = std::move(circuit);
        mVoleRequest = std::max(voleRequest, mCircuit.voleCount());
        mVole.configure(mVoleRequest, plaintextModulusBits, numThreads, setting);
        mMacs.resize(0);
        mDeviceState.reset();
    }

    task<> ZkMulProver::offline(Socket& sock)
    {
        co_await mVole.offline(sock);
    }

    task<> ZkMulProver::prove(std::span<u64> wires, PRNG& prng, Socket& sock)
    {
        const bool device = mUseDevice && mWiresDevice != nullptr;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (mDeviceOnlyHostSpans &&
            (!device || !mVoleDeviceInput || !gpu::enabled() ||
             !wires.empty() || asScalars(mWiresDevice)->count() != mVoleRequest))
        {
            throw std::runtime_error("LogVole ZK device-only witness handle does not match the request");
        }
#else
        if (mDeviceOnlyHostSpans)
            throw std::runtime_error("LogVole ZK device-only witness requires CUDA support");
#endif
        if (wires.size() != mVoleRequest &&
            !(mDeviceOnlyHostSpans && wires.empty()))
        {
            throw std::runtime_error("LogVole ZK prover witness size does not match the request");
        }

        refreshProofMask(wires, mCircuit.maskIndex(), mVoleRequest, mVole.modulus(),
            prng, device ? mWiresDevice : std::shared_ptr<void>{});

        mVole.mKeepOutputOnDevice = device;
        mVole.mInputDevice =
            (device && mVoleDeviceInput) ? mWiresDevice : std::shared_ptr<void>{};

        // An empty output span is valid only when the VOLE must publish a
        // device token. Keep the ordinary host/fallback allocation otherwise.
        if (mDeviceOnlyHostSpans) mMacs.clear();
        else mMacs.resize(static_cast<std::size_t>(mVoleRequest));
        {
            LogVole::HostStep phase("zk prover: label generation");
            co_await mVole.receive(wires, std::span<u64>(mMacs.data(), mMacs.size()), prng, sock);
        }

        // The challenge has to arrive after the VOLE has bound the witness, so
        // this is one extra round and it cannot be moved earlier.
        LogVole::HostStep challengePhase("zk prover: wait for challenge");
        const block seed = co_await recvBlock(sock);
        challengePhase.stop();
        mLastSeed = seed;
        mLastChallenge = zkChallengeScalar(seed, mVole.modulus());

        mDrainMs = 0;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (device)
        {
            const auto tDrain = std::chrono::steady_clock::now();
            LogVole::gpu::zkDrainProducer(mVole.outputDevice());
            LogVole::gpu::zkDrainProducer(mWiresDevice);
            LogVole::gpu::zkDrainSelf();
            mDrainMs = msSinceCheck(tDrain);
        }
#endif
        const auto tCheck = std::chrono::steady_clock::now();
        LogVole::HostStep responsePhase("zk prover: gate response");
        bool ok = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        // The VOLE may decline to leave its output on the device for a shape it
        // does not handle, in which case it wrote host MACs instead and the host
        // check is the correct path.
        const bool deviceOut = device && mVole.outputDevice() != nullptr;
        if (deviceOut)
        {
            if (!mDeviceState)
            {
                mDeviceState = LogVole::gpu::makeZkMulDeviceState(mCircuit);
            }
            if (mDeviceState)
            {
                auto st = std::static_pointer_cast<LogVole::gpu::ZkMulDeviceState>(mDeviceState);
                ok = LogVole::gpu::zkMulProverResponseDevice(
                    mCircuit, *asScalars(mWiresDevice), *asScalars(mVole.outputDevice()),
                    mLastChallenge, mVole.modulus(), *st, mLastProof);
            }
        }
        mCheckOnDevice = ok;
#endif
        if (!ok)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            // With the output device resident there is nothing on the host to fall
            // back to, so a failed device check is fatal rather than silent.
            if (deviceOut)
            {
                throw std::runtime_error("LogVole ZK could not run its device check");
            }
            if (mCircuit.mOperands.empty() && mCircuit.mOperandsDevice &&
                !LogVole::gpu::zkMulMaterializeOperands(mCircuit))
                throw std::runtime_error("LogVole ZK prover could not materialize circuit operands for its host check");
#endif
            ok = zkMulProverResponse(
                mCircuit, wires, std::span<const u64>(mMacs.data(), mMacs.size()), mLastChallenge,
                mVole.modulus(), mVole.mNumThreads, mLastProof);
        }
        if (!ok) throw std::runtime_error("LogVole ZK prover could not build its response");
        mCheckMs = msSinceCheck(tCheck);
        responsePhase.stop();

        LogVole::HostStep exchangePhase("zk prover: send proof");
        co_await sendProof(sock, mLastProof);
        mVole.mKeepOutputOnDevice = false;
        mVole.mInputDevice.reset();
    }

    void ZkMulVerifier::configure(
        LogVole::ZkMulCircuit circuit, u32 plaintextModulusBits, u32 numThreads,
        LogVole::CivoleSetting setting, u64 voleRequest)
    {
        LogVole::ScopedProtocolCacheScope cacheScope(
            LogVole::ProtocolCacheRole::Sender,
            LogVole::currentProtocolCacheScope().mRunId);
#if defined(ENABLE_LOGVOLE_CUDA)
        if (mUseDevice && LogVole::gpu::enabled() && circuit.mOperandsDevice &&
            circuit.mOperands.empty())
        {
            // A moved, unique allocation transfers ownership directly. Shared
            // input handles must detach before becoming verifier state.
            if (!LogVole::gpu::zkMulDeviceOperandsValid(circuit) ||
                (circuit.mOperandsDevice.use_count() != 1 &&
                 !LogVole::gpu::zkMulDetachOperands(circuit)))
                throw std::runtime_error("LogVole ZK verifier could not detach circuit operands");
        }
        else
        {
            // A supplied host vector remains authoritative: it may have been
            // independently edited after its old device snapshot was created.
            if (circuit.mOperands.empty() && circuit.mOperandsDevice &&
                !LogVole::gpu::zkMulMaterializeOperands(circuit))
                throw std::runtime_error("LogVole ZK verifier could not materialize circuit operands");
            circuit.mOperandsDevice.reset();
        }
#endif
        mCircuit = std::move(circuit);
        mVoleRequest = std::max(voleRequest, mCircuit.voleCount());
        mVole.configure(mVoleRequest, plaintextModulusBits, numThreads, setting);
        mKeys.resize(0);
        mDeviceState.reset();
    }

    task<> ZkMulVerifier::offline(u64 delta, PRNG& prng, Socket& sock)
    {
        co_await mVole.offline(delta, prng, sock);
    }

    task<> ZkMulVerifier::verify(PRNG& prng, Socket& sock)
    {
        mAccepted = false;
        mAcceptOnDevice = false;
        const bool device = mUseDevice;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (mDeviceOnlyHostSpans && (!device || !gpu::enabled()))
            throw std::runtime_error("LogVole ZK device-only keys require the GPU backend");
#else
        if (mDeviceOnlyHostSpans)
            throw std::runtime_error("LogVole ZK device-only keys require CUDA support");
#endif
        mVole.mKeepOutputOnDevice = device;

        if (mDeviceOnlyHostSpans) mKeys.clear();
        else mKeys.resize(static_cast<std::size_t>(mVoleRequest));
        {
            LogVole::HostStep phase("zk verifier: label generation");
            co_await mVole.send(std::span<u64>(mKeys.data(), mKeys.size()), prng, sock);
        }

        LogVole::HostStep challengePhase("zk verifier: send challenge");
        const block seed = prng.get<block>();
        mLastSeed = seed;
        co_await sendBlock(sock, seed);
        mLastChallenge = zkChallengeScalar(seed, mVole.modulus());
        challengePhase.stop();

        mDrainMs = 0;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (device)
        {
            const auto tDrain = std::chrono::steady_clock::now();
            LogVole::gpu::zkDrainProducer(mVole.outputDevice());
            LogVole::gpu::zkDrainSelf();
            mDrainMs = msSinceCheck(tDrain);
        }
#endif
        const auto tCheck = std::chrono::steady_clock::now();
        LogVole::HostStep checkPhase("zk verifier: gate check");
        u64 value = 0;
        bool ok = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool deviceOut = device && mVole.outputDevice() != nullptr;
        if (deviceOut)
        {
            if (!mDeviceState)
            {
                mDeviceState = LogVole::gpu::makeZkMulDeviceState(mCircuit);
            }
            if (mDeviceState)
            {
                auto st = std::static_pointer_cast<LogVole::gpu::ZkMulDeviceState>(mDeviceState);
                ok = LogVole::gpu::zkMulVerifierValueDevice(
                    mCircuit, *asScalars(mVole.outputDevice()), mLastChallenge, mVole.mDelta,
                    mVole.modulus(), *st, value);
            }
        }
        mCheckOnDevice = ok;
#endif
        if (!ok)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            // With the output device resident there is nothing on the host to fall
            // back to, so a failed device check is fatal rather than silent.
            if (deviceOut)
            {
                throw std::runtime_error("LogVole ZK could not run its device check");
            }
            if (mCircuit.mOperands.empty() && mCircuit.mOperandsDevice &&
                !LogVole::gpu::zkMulMaterializeOperands(mCircuit))
                throw std::runtime_error("LogVole ZK verifier could not materialize circuit operands for its host check");
#endif
            ok = zkMulVerifierValue(
                mCircuit, std::span<const u64>(mKeys.data(), mKeys.size()), mLastChallenge,
                mVole.mDelta, mVole.modulus(), mVole.mNumThreads, value);
        }
        if (!ok) throw std::runtime_error("LogVole ZK verifier could not evaluate the check");
        mCheckMs = msSinceCheck(tCheck);
        checkPhase.stop();

        LogVole::HostStep exchangePhase("zk verifier: wait for proof and accept");
        const ZkProof proof = co_await recvProof(sock);
        mLastValue = value;
#if defined(ENABLE_LOGVOLE_CUDA)
        const char* deviceAcceptance = std::getenv("LV_GPU_ZK_ACCEPT_DEVICE");
        if (mCheckOnDevice && (!deviceAcceptance || deviceAcceptance[0] != '0'))
        {
            if (!LogVole::gpu::zkAcceptDevice(proof, value, mVole.mDelta, mVole.modulus(), mAccepted))
                throw std::runtime_error("LogVole ZK could not execute acceptance on the device");
            mAcceptOnDevice = true;
        }
        else
#endif
        {
            LogVole::HostStep rollback("zk: host proof acceptance");
            mAccepted = zkAccept(proof, value, mVole.mDelta, mVole.modulus());
        }
        mVole.mKeepOutputOnDevice = false;
    }

    // ---- matrix multiplication ------------------------------------------

    void ZkMatMulProver::configure(
        LogVole::ZkMatMulStatement statement, u32 plaintextModulusBits, u32 numThreads,
        LogVole::CivoleSetting setting, u64 voleRequest)
    {
        if (!validateZkMatMulStatement(statement))
            throw std::invalid_argument("LogVole ZK matmul statement is invalid");
        mStatement = statement;
        mVoleRequest = std::max(voleRequest, mStatement.voleCount());
        mVole.configure(mVoleRequest, plaintextModulusBits, numThreads, setting);
        mMacs.resize(0);
        mDeviceState.reset();
        mLastProofs.clear();
        mLastProof = {};
    }

    task<> ZkMatMulProver::offline(Socket& sock)
    {
        co_await mVole.offline(sock);
    }

    task<> ZkMatMulProver::prove(std::span<u64> wires, PRNG& prng, Socket& sock)
    {
        if (wires.size() != mVoleRequest)
        {
            throw std::runtime_error("LogVole ZK matmul witness size does not match the request");
        }

        const bool device = mUseDevice && mWiresDevice != nullptr;
        for (u32 rep = 0; rep < mStatement.repetitions(); ++rep)
            refreshProofMask(wires, mStatement.maskIndex(rep), mVoleRequest, mVole.modulus(),
                prng, device ? mWiresDevice : std::shared_ptr<void>{});
        mVole.mKeepOutputOnDevice = device;
        mVole.mInputDevice =
            (device && mVoleDeviceInput) ? mWiresDevice : std::shared_ptr<void>{};

        mMacs.resize(static_cast<std::size_t>(mVoleRequest));
        co_await mVole.receive(wires, std::span<u64>(mMacs.data(), mMacs.size()), prng, sock);

        const block seed = co_await recvBlock(sock);
        mLastSeed = seed;

        mDrainMs = 0;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (device)
        {
            const auto tDrain = std::chrono::steady_clock::now();
            LogVole::gpu::zkDrainProducer(mVole.outputDevice());
            LogVole::gpu::zkDrainProducer(mWiresDevice);
            LogVole::gpu::zkDrainSelf();
            mDrainMs = msSinceCheck(tDrain);
        }
#endif
        const auto tCheck = std::chrono::steady_clock::now();
        LogVole::ZkMatMulChallenge ch{};
        zkMatMulChallenge(mStatement, seed, mVole.modulus(), ch);

        bool ok = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool deviceOut = device && mVole.outputDevice() != nullptr;
        if (deviceOut)
        {
            if (!mDeviceState)
            {
                mDeviceState = LogVole::gpu::makeZkMatMulDeviceState(mStatement);
            }
            if (mDeviceState)
            {
                auto st = std::static_pointer_cast<LogVole::gpu::ZkMatMulDeviceState>(mDeviceState);
                ok = LogVole::gpu::zkMatMulProverResponseDevice(
                    mStatement, *asScalars(mWiresDevice), *asScalars(mVole.outputDevice()), ch,
                    mVole.modulus(), *st, mLastProofs);
            }
        }
        mCheckOnDevice = ok;
#endif
        if (!ok)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            // With the output device resident there is nothing on the host to fall
            // back to, so a failed device check is fatal rather than silent.
            if (deviceOut)
            {
                throw std::runtime_error("LogVole ZK could not run its device check");
            }
#endif
            ok = zkMatMulProverResponse(
                mStatement, wires, std::span<const u64>(mMacs.data(), mMacs.size()), ch,
                mVole.modulus(), mVole.mNumThreads, mLastProofs);
        }
        if (!ok) throw std::runtime_error("LogVole ZK matmul prover could not build its response");
        mLastProof = mLastProofs.front();
        mCheckMs = msSinceCheck(tCheck);

        co_await sendMatMulProofs(sock, mLastProofs);
        mVole.mKeepOutputOnDevice = false;
        mVole.mInputDevice.reset();
    }

    void ZkMatMulVerifier::configure(
        LogVole::ZkMatMulStatement statement, u32 plaintextModulusBits, u32 numThreads,
        LogVole::CivoleSetting setting, u64 voleRequest)
    {
        if (!validateZkMatMulStatement(statement))
            throw std::invalid_argument("LogVole ZK matmul statement is invalid");
        mStatement = statement;
        mVoleRequest = std::max(voleRequest, mStatement.voleCount());
        mVole.configure(mVoleRequest, plaintextModulusBits, numThreads, setting);
        mKeys.resize(0);
        mDeviceState.reset();
        mLastValues.clear();
        mLastValue = 0;
        mAccepted = false;
    }

    task<> ZkMatMulVerifier::offline(u64 delta, PRNG& prng, Socket& sock)
    {
        co_await mVole.offline(delta, prng, sock);
    }

    task<> ZkMatMulVerifier::verify(std::span<const u64> publicProduct, PRNG& prng, Socket& sock)
    {
        mAccepted = false;
        if (!LogVole::validMatMulPublicProduct(mStatement, publicProduct, mVole.modulus()))
            throw std::invalid_argument("LogVole ZK matmul public product must contain n^2 canonical field elements");
        // Fix the application statement before any authentication or challenge.
        // The caller can reuse its buffer once the coroutine reaches the socket.
        LogVole::AlignedUnVec<u64> product(publicProduct.size());
        std::copy(publicProduct.begin(), publicProduct.end(), product.begin());
        const bool device = mUseDevice;
        mVole.mKeepOutputOnDevice = device;

        mKeys.resize(static_cast<std::size_t>(mVoleRequest));
        co_await mVole.send(std::span<u64>(mKeys.data(), mKeys.size()), prng, sock);

        const block seed = prng.get<block>();
        mLastSeed = seed;
        co_await sendBlock(sock, seed);

        mDrainMs = 0;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (device)
        {
            const auto tDrain = std::chrono::steady_clock::now();
            LogVole::gpu::zkDrainProducer(mVole.outputDevice());
            LogVole::gpu::zkDrainSelf();
            mDrainMs = msSinceCheck(tDrain);
        }
#endif
        const auto tCheck = std::chrono::steady_clock::now();
        LogVole::ZkMatMulChallenge ch{};
        zkMatMulChallenge(mStatement, seed, mVole.modulus(), ch);

        std::vector<u64> values;
        bool ok = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool deviceOut = device && mVole.outputDevice() != nullptr;
        if (deviceOut)
        {
            if (!mDeviceState)
            {
                mDeviceState = LogVole::gpu::makeZkMatMulDeviceState(mStatement);
            }
            if (mDeviceState)
            {
                auto st = std::static_pointer_cast<LogVole::gpu::ZkMatMulDeviceState>(mDeviceState);
                ok = LogVole::gpu::zkMatMulVerifierValueDevice(
                    mStatement, *asScalars(mVole.outputDevice()), product, ch, mVole.mDelta,
                    mVole.modulus(), *st, values);
            }
        }
        mCheckOnDevice = ok;
#endif
        if (!ok)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            // With the output device resident there is nothing on the host to fall
            // back to, so a failed device check is fatal rather than silent.
            if (deviceOut)
            {
                throw std::runtime_error("LogVole ZK could not run its device check");
            }
#endif
            ok = zkMatMulVerifierValue(
                mStatement, std::span<const u64>(mKeys.data(), mKeys.size()), product, ch, mVole.mDelta,
                mVole.modulus(), mVole.mNumThreads, values);
        }
        if (!ok) throw std::runtime_error("LogVole ZK matmul verifier could not evaluate the check");
        mCheckMs = msSinceCheck(tCheck);

        const auto proofs = co_await recvMatMulProofs(sock, mStatement.repetitions());
        mLastValues = std::move(values);
        mLastValue = mLastValues.front();
        mAccepted = zkMatMulAccept(proofs, mLastValues, mVole.mDelta, mVole.modulus());
        mVole.mKeepOutputOnDevice = false;
    }
}
