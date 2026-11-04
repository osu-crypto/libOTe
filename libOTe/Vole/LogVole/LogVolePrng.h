#pragma once

#include <cstdint>

namespace osuCrypto::LogVole
{
    // RO_128(domain || seed[0..7]), with little-endian words, is the AES-128
    // key. The byte stream is AES_key(block(counter)), starting at counter 0,
    // exactly as cryptoTools::PRNG. All 512 input seed bits contribute.
    inline constexpr std::uint64_t kAesPrngSeedDomain = 0x4C56414553505231ull;
}
