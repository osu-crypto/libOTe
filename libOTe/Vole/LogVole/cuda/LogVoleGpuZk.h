#pragma once

// Device kernels for the VOLE-based ZK checks in libOTe/Vole/LogVole/LogVoleZk.h.
//
// The point of running these on the GPU is not that the arithmetic is heavy -
// the multiplication-gate check is five modular multiplies per gate - but that
// the MACs are *already* in device memory when the check runs. LogVole's online
// phase can leave the VOLE output on the device (mKeepOutputOnDevice), so a
// check that runs there too makes a proof cost 32 bytes of PCIe traffic instead
// of two full-length transfers of MACs and keys. At 2^24 gates that is 268 MB
// per party that never moves.
//
// Like the rest of the CUDA layer this header is free of CUDA and SEAL types so
// that ordinary translation units can include it. Sums of products modulo p are
// order independent when every partial sum is reduced, so the tree reductions
// below return exactly what the host loops in LogVoleZk.cpp return.

#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"

namespace osuCrypto::LogVole::gpu
{
    // Write the fresh mask by value, with no borrowed host-buffer lifetime.
    bool launchZkSetMask(u64* destination, u64 mask, void* stream);

    // Exact floor(2^128 / modulus), computed on device for 2 <= modulus < 2^61.
    // out is one device HostModulus; no primality assumption is required.
    bool launchZkPrepareModulus(u64 modulus, HostModulus* out, void* stream);
    // One device word receives the exact acceptance bit. Inputs are not
    // assumed reduced; verifierValue is compared without reducing it.
    bool launchZkAccept(u64 proofU, u64 proofV, u64 verifierValue, u64 delta,
        const HostModulus& mod, u64* accepted, void* stream);

    // Pack already reduced AES draws as the layered circuit's absolute indices.
    bool launchZkPackOperands(
        const u64* residues, u32* operands, u64 count, u64 width, void* stream);
    // Stage-1 grid width. Fixed so that callers can size the partial-sum scratch
    // without asking; the kernels use a grid-stride loop, so this is a launch
    // shape rather than a limit on the work.
    constexpr u32 kZkReduceBlocks = 1024;
    // u64 of scratch a check needs for its partial sums.
    constexpr u32 kZkScratchWords = 2 * kZkReduceBlocks;

    // U = sum_g chi^(g+1) * M[x_g]*M[y_g]                        + M[r]
    // V = sum_g chi^(g+1) * (M[z_g] - x_g*M[y_g] - y_g*M[x_g])    - r
    //
    // Gate g reads operands[2g], operands[2g+1] and owns output wire
    // firstOutWire + g; r is wires[maskIndex]. `outUV` is a device array of 2.
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
        void* stream);

    // B = sum_g chi^(g+1) * (K[x_g]*K[y_g] + K[z_g]*Delta) + K[r]. `outB` is a
    // device array of 1.
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
        void* stream);

    // ---- matrix multiplication -------------------------------------------
    // Check all n^2 length-n inner products directly. Wires and MACs contain
    // row-major A followed by B; coefficients has one independent field value
    // for every output entry. scratch has 2*n^2 words and outUV has two.
    // The final reduction adds M[maskIndex] to U and subtracts its value from V.
    bool launchZkMatMulProver(
        const u64* wires, const u64* macs, const u64* coefficients,
        u32 n, u64 maskIndex, const HostModulus& mod,
        u64* scratch, u64* outUV, void* stream);

    // Public C is a separate row-major n^2 array. Per-entry verifier terms are
    // sum_k K[A_ik]*K[B_kj] - C_ij*Delta^2. scratch has n^2 words; outB has one.
    // The final reduction adds K[maskIndex].
    bool launchZkMatMulVerifier(
        const u64* keys, const u64* publicProduct, const u64* coefficients,
        u32 n, u64 maskIndex, u64 delta, const HostModulus& mod,
        u64* scratch, u64* outB, void* stream);

    // c = a * b mod p for row-major n x n matrices. This is the prover's own
    // honest computation, not part of the proof; it lives here so that the
    // public product can be built separately from the authenticated witness.
    bool launchZkMatMulGemm(
        const u64* a, const u64* b, u64* c, u32 n, const HostModulus& mod, void* stream);

    // One layer of the circuit's own evaluation:
    //   wires[firstOutWire + firstGate + j] =
    //       wires[operands[2g]] * wires[operands[2g + 1]]   for g = firstGate + j
    //
    // Also the prover's own computation rather than part of the proof, but it has
    // to happen somewhere, and on the host it is larger than the proof it feeds:
    // 188 ms on 8 cores against a 74 ms proof at 2^24 gates. A layer is
    // width-parallel, so the whole circuit is `depth` launches of this.
    bool launchZkMulEvalLayer(
        u64* wires,
        const u32* operands,
        u64 firstGate,
        u64 width,
        u64 firstOutWire,
        const HostModulus& mod,
        void* stream);

    // out[i] = prng-free uniform-ish fill is *not* provided on purpose: witness
    // values come from the host PRNG so that the CPU and GPU paths prove the same
    // statement.
}
