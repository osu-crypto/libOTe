#include "libOTe/Vole/LogVole/LogVoleCpuSampler.h"
#include "libOTe/Vole/LogVole/LogVoleCpuArithmetic.h"
#include "cryptoTools/Crypto/RandomOracle.h"

#include "seal/util/common.h"
#include "seal/util/uintarithsmallmod.h"

namespace osuCrypto::LogVole::detail
{
    block aesPrngKey(const seal::prng_seed_type& seed)
    {
        RandomOracle hash(sizeof(block));
        hash.Update(&kAesPrngSeedDomain, 1);
        hash.Update(seed.data(), seed.size());
        block key;
        hash.Final(key);
        return key;
    }

    namespace
    {
        template<typename Fill>
        void sampleUniform(const CpuArithmeticCache& cache, Fill&& fill, const seal::EncryptionParameters& parms,
            std::uint64_t* destination)
        {
            const auto& moduli = parms.coeff_modulus();
            const auto count = parms.poly_modulus_degree();
            fill(seal::util::mul_safe(moduli.size(), count, sizeof(std::uint64_t)),
                reinterpret_cast<seal::seal_byte*>(destination));
            for (const auto& modulus : moduli)
            {
                constexpr std::uint64_t max = ~std::uint64_t{0};
                const auto limit = max - seal::util::barrett_reduce_64(max, modulus) - 1;
                if (!cpuReduceMod(cache, destination, destination, count, modulus, &limit))
                {
                    for (std::size_t i = 0; i < count; ++i)
                    {
                        auto value = destination[i];
                        while (value >= limit)
                            fill(sizeof(value), reinterpret_cast<seal::seal_byte*>(&value));
                        destination[i] = seal::util::barrett_reduce_64(value, modulus);
                    }
                }
                destination += count;
            }
        }

        class SealAesPrng final : public seal::UniformRandomGenerator
        {
            AES mAes;
            u64 mCounter = 0;
        public:
            explicit SealAesPrng(const seal::prng_seed_type& seed)
                : UniformRandomGenerator(seed), mAes(aesPrngKey(seed)) {}
            ~SealAesPrng() override { seal::util::seal_memzero(&mAes, sizeof(mAes)); }
        private:
            seal::prng_type type() const noexcept override { return seal::prng_type::unknown; }
            void refill_buffer() override
            {
                const auto blocks = buffer_size_ / sizeof(block);
                mAes.ecbEncCounterMode(mCounter, blocks, reinterpret_cast<block*>(buffer_begin_));
                mCounter += blocks;
            }
        };

        class SealAesPrngFactory final : public seal::UniformRandomGeneratorFactory
        {
            std::shared_ptr<seal::UniformRandomGenerator> create_impl(seal::prng_seed_type seed) override
            {
                return std::make_shared<SealAesPrng>(seed);
            }
        };
    }

    std::shared_ptr<seal::UniformRandomGeneratorFactory> makeAesPrngFactory()
    {
        return std::make_shared<SealAesPrngFactory>();
    }

    void cpuSamplePolyUniform(const CpuArithmeticCache& cache, PRNG& prng,
        const seal::EncryptionParameters& parms, std::uint64_t* destination)
    {
        sampleUniform(cache, [&](std::size_t bytes, seal::seal_byte* out) {
            prng.get(reinterpret_cast<u8*>(out), bytes);
        }, parms, destination);
    }

    void cpuSamplePolyUniform(const CpuArithmeticCache& cache, std::shared_ptr<seal::UniformRandomGenerator> prng,
        const seal::EncryptionParameters& parms, std::uint64_t* destination)
    {
        sampleUniform(cache, [&](std::size_t bytes, seal::seal_byte* out) {
            prng->generate(bytes, out);
        }, parms, destination);
    }

}
