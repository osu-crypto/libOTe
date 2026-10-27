#pragma once

#include "cryptoTools/Common/Defines.h"
#include "seal/modulus.h"
#include <array>
#include <cstddef>

namespace osuCrypto::LogVole::detail
{
    // Independent witness gates whose operand wires are already available.
    // Output must not overlap any referenced input. False leaves it untouched.
    bool cpuZkWitnessRange(const u32* operands, const u64* wires, u64* outputs,
        std::size_t count, const seal::Modulus& modulus);
    // Eight independent gate lanes, with exact public challenge powers.
    // Operand indices must address the supplied witness/label arrays; outputs
    // contains this range's output-wire labels. Arbitrary u64 field values are
    // normalized. False leaves the result unchanged for the scalar fallback.
    bool cpuZkProverRange(const u32* operands, const u64* wires, const u64* macs,
        const u64* outputs, std::size_t count, u64 firstPower, u64 chi,
        const seal::Modulus& modulus, std::array<u64, 2>& result);

    bool cpuZkVerifierRange(const u32* operands, const u64* keys, const u64* outputs,
        std::size_t count, u64 firstPower, u64 chi, u64 delta,
        const seal::Modulus& modulus, u64& result);

    // Direct n-by-n matrix inner products, before independent per-entry batching.
    // A/MA are row-major; B/MB have already been transposed so each original
    // column is contiguous. Inputs must be canonical field elements and outputs
    // must not overlap inputs. Only rows [beginRow,endRow) of the n*n output
    // arrays are written. Invalid dimensions, ranges, pointers or moduli return
    // false before writing; valid empty row ranges succeed without dereferencing.
    // Exact bounded raw-product accumulation is used on uint128 platforms, with
    // an optional AVX-512 IFMA path for 51/54-bit fields. Set
    // LV_CPU_VECTOR_MATMUL=0 before the first call to force scalar accumulation.
    bool cpuZkMatMulProverTerms(
        const u64* a, const u64* ma, const u64* bTranspose, const u64* mbTranspose,
        u64* a0, u64* cross, std::size_t n, std::size_t beginRow,
        std::size_t endRow, const seal::Modulus& modulus);

    bool cpuZkMatMulVerifierTerms(
        const u64* aKeys, const u64* bKeysTranspose, u64* products,
        std::size_t n, std::size_t beginRow, std::size_t endRow,
        const seal::Modulus& modulus);
}
