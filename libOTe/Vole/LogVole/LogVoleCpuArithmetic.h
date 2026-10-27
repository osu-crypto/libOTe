#pragma once

#include "cryptoTools/Common/Defines.h"
#include "seal/modulus.h"
#include "seal/util/rns.h"
#include <cstddef>
#include <span>

namespace osuCrypto::LogVole { struct wideU64; }

namespace osuCrypto::LogVole::detail
{
    // Returns false without changing c when the vector specialization is not
    // available. Accepts arbitrary u64 coefficients and exact in-place aliases.
    bool cpuDyadicMultiplyAdd(const u64* a, const u64* b, u64* c,
        std::size_t count, const seal::Modulus& modulus);

    // c -= a*b mod q, with the same normalization and fallback contract.
    bool cpuDyadicMultiplySubtract(const u64* a, const u64* b, u64* c,
        std::size_t count, const seal::Modulus& modulus);

    // c += sum(a[t]*b[t]) mod q, with a single reduction per coefficient.
    // Accepts arbitrary u64 inputs and 3..32 terms; false changes no output.
    bool cpuDyadicInnerProduct(const u64* const* a, const u64* const* b,
        std::size_t terms, u64* c, std::size_t count, const seal::Modulus& modulus);

    // Reduce arbitrary u64 inputs, including exact in-place operation. The
    // optional rejection limit checks the original inputs before reduction;
    // false leaves the entire destination untouched. Used by SEAL-compatible
    // uniform sampling to preserve the order of replacement random draws.
    bool cpuReduceMod(const u64* source, u64* destination,
        std::size_t count, const seal::Modulus& modulus,
        const u64* rejectionLimit = nullptr);

    // Exact existing 128-bit fixed-point CRT scale-and-round, vectorized across
    // coefficients. Arbitrary-u64 modulus-major input; nonoverlapping scalar
    // output. Supports the production rings and 2 <= p < 2^modulus_bits.
    // False leaves the output untouched for the general scalar fallback.
    bool cpuScaleAndRoundRns(const u64* source, u64* destination,
        std::size_t count, const seal::util::RNSBase& base, u64 plaintextModulus);

    // Denoising is scale-and-round to q_target. Uses the identical fractional
    // residues as reduced-base recovery, so the 128-bit rounding is unchanged.
    bool cpuDenoiseRns(const u64* source, u64* destination,
        std::size_t count, const seal::util::RNSBase& base, std::size_t target);

    // Exact GoldenSeed fixed-point margin predicate, including masked tails.
    // source is modulus-major; the indexed limbs contribute to a 128-bit sum.
    // False declines dispatch and leaves accepted unchanged.
    bool cpuCheckRoundingMargin(const u64* source, std::size_t count,
        std::span<const seal::Modulus> moduli, std::span<const std::size_t> sourceLimbs,
        std::span<const seal::util::MultiplyUIntModOperand> inverse,
        std::span<const wideU64> reciprocal, wideU64 margin, bool& accepted);

    // Canonical RNS input (modulus-major) to canonical CRT integers
    // (coefficient-major). Input and output must not overlap. False leaves the
    // output untouched and asks the caller to use SEAL's general implementation.
    bool cpuComposeRns(const u64* source, u64* destination,
        std::size_t count, const seal::util::RNSBase& base);

    // Fused CRT and balanced high-digit extraction (start=1, levels=1).
    // Canonical modulus-major input/output, nonoverlapping. Specializes the
    // production 4x55/110-bit and 8x52/208-bit shapes; false leaves output intact.
    bool cpuCenteredHighDigit(const u64* source, u64* destination,
        std::size_t count, unsigned digitBits, const seal::util::RNSBase& base);

    // Fused canonical CRT, unsigned low-digit extraction and RNS expansion.
    // Same production shapes and nonoverlap/canonical-input rules as above.
    bool cpuLowDigitRns(const u64* source, u64* destination,
        std::size_t count, unsigned digitBits, const seal::util::RNSBase& base);

    // Undo a recursive leaf's CRT lift, center its selected residue, and
    // replicate it into the full RNS base. Canonical input; nonoverlapping
    // modulus-major output. False leaves output unchanged for scalar fallback.
    bool cpuUnliftCenteredRns(const u64* source, u64* destination,
        std::size_t count, const seal::Modulus& sourceModulus, u64 inverseLift,
        std::span<const seal::Modulus> destinationModuli);
}
