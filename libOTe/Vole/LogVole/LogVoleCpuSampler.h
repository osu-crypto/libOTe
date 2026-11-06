#pragma once

#include "seal/randomgen.h"
#include "seal/encryptionparams.h"

namespace osuCrypto::LogVole::detail
{
    // Keep SEAL's configured default PRNG and exact stream. BLAKE2xb builds
    // use the byte-compatible vector implementation when it is available.
    std::shared_ptr<seal::UniformRandomGeneratorFactory> cpuDefaultPrngFactory();
    // SEAL-compatible BLAKE2xb, with runtime dispatch and the original scalar
    // implementation on CPUs without AVX-512. No seed or byte-stream changes.
    std::shared_ptr<seal::UniformRandomGeneratorFactory> cpuBlake2xbFactory();
    bool cpuBlake2xbVectorAvailable();

    // Identical to SEAL's sample_poly_uniform, including rejection thresholds
    // and PRNG consumption. Vectorizes reduction when the whole limb is accepted.
    void cpuSamplePolyUniform(std::shared_ptr<seal::UniformRandomGenerator> prng,
        const seal::EncryptionParameters& parms, std::uint64_t* destination);
}
