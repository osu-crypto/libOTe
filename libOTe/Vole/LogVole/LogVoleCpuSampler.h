#pragma once

#include "libOTe/Tools/CpuCapabilities.h"

#include "libOTe/Vole/LogVole/LogVolePrng.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "seal/randomgen.h"
#include "seal/encryptionparams.h"

namespace osuCrypto::LogVole::detail
{
    block aesPrngKey(const seal::prng_seed_type& seed);
    // Prepare the PRNG once, then SetSeed(aesPrngKey(seed)) reuses its buffer.
    void cpuSamplePolyUniform(const CpuCapabilities& cache, PRNG& prng,
        const seal::EncryptionParameters& parms, std::uint64_t* destination);
    // Optional SEAL boundary only. Callers own the factory; there is no global
    // factory cache. SEAL's base-class allocation is not used by the direct path.
    // This custom type is not SEAL's built-in seeded-ciphertext serialization.
    std::shared_ptr<seal::UniformRandomGeneratorFactory> makeAesPrngFactory();

    // Identical to SEAL's sample_poly_uniform, including rejection thresholds
    // and PRNG consumption. Vectorizes reduction when the whole limb is accepted.
    void cpuSamplePolyUniform(const CpuCapabilities& cache, std::shared_ptr<seal::UniformRandomGenerator> prng,
        const seal::EncryptionParameters& parms, std::uint64_t* destination);
}
