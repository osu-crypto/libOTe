#include "libOTe/Vole/LogVole/LogVoleCpuSampler.h"
#include "libOTe/Vole/LogVole/LogVoleCpuArithmetic.h"

#include "seal/util/blake2.h"
#include "seal/util/common.h"
#include "seal/util/uintarithsmallmod.h"

#include <cstdlib>
#include <stdexcept>

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define LV_CPU_BLAKE_AVX512 1
#endif

namespace osuCrypto::LogVole::detail
{
    void cpuSamplePolyUniform(std::shared_ptr<seal::UniformRandomGenerator> prng,
        const seal::EncryptionParameters& parms, std::uint64_t* destination)
    {
        const auto& moduli = parms.coeff_modulus();
        const auto count = parms.poly_modulus_degree();
        prng->generate(seal::util::mul_safe(moduli.size(), count, sizeof(std::uint64_t)),
            reinterpret_cast<seal::seal_byte*>(destination));
        for (const auto& modulus : moduli)
        {
            constexpr std::uint64_t max = ~std::uint64_t{0};
            const auto limit = max - seal::util::barrett_reduce_64(max, modulus) - 1;
            if (!cpuReduceMod(destination, destination, count, modulus, &limit))
            {
                // A rejected limb is still entirely untouched. Visit every
                // coefficient in SEAL's order, including consecutive rejections
                // and refills, before proceeding to the next modulus.
                for (std::size_t i = 0; i < count; ++i)
                {
                    auto value = destination[i];
                    while (value >= limit)
                        prng->generate(sizeof(value), reinterpret_cast<seal::seal_byte*>(&value));
                    destination[i] = seal::util::barrett_reduce_64(value, modulus);
                }
            }
            destination += count;
        }
    }

    bool cpuBlake2xbVectorAvailable()
    {
#if defined(LV_CPU_BLAKE_AVX512)
        return __builtin_cpu_supports("avx512f");
#else
        return false;
#endif
    }

    namespace
    {
#if defined(LV_CPU_BLAKE_AVX512)
        constexpr std::uint64_t iv[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };
        constexpr unsigned char sigma[12][16] = {
            {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
            {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
            {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
            {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
            {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
            {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
            {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
            {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
            {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
            {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
            {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
            {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3}
        };

        // Each SIMD lane is an independent output node of the same BLAKE2xb
        // root, not a different hash construction. SEAL refills 4096 bytes.
        __attribute__((target("avx512f")))
        void outputBlocks(const std::uint64_t* root, seal::seal_byte* destination)
        {
            const auto lanes = _mm512_setr_epi64(0, 1, 2, 3, 4, 5, 6, 7);
            const auto offsets = _mm512_slli_epi64(lanes, 3);
            static const bool transposeOutput = [] {
                const char* value = std::getenv("LV_CPU_BLAKE_TRANSPOSE");
                return !value || value[0] != '0';
            }();
            for (unsigned node = 0; node < 64; node += 8)
            {
                __m512i h[8], v[16], m[16];
                for (unsigned j = 0; j < 8; ++j)
                {
                    h[j] = _mm512_set1_epi64(iv[j]);
                    m[j] = _mm512_set1_epi64(root[j]);
                    m[j + 8] = _mm512_setzero_si512();
                    v[j + 8] = h[j];
                }
                h[0] = _mm512_xor_si512(h[0], _mm512_set1_epi64(64ULL | (64ULL << 32)));
                h[1] = _mm512_xor_si512(h[1], _mm512_add_epi64(lanes,
                    _mm512_set1_epi64((4096ULL << 32) | node)));
                h[2] = _mm512_xor_si512(h[2], _mm512_set1_epi64(64ULL << 8));
                for (unsigned j = 0; j < 8; ++j) v[j] = h[j];
                v[12] = _mm512_xor_si512(v[12], _mm512_set1_epi64(64));
                v[14] = _mm512_xor_si512(v[14], _mm512_set1_epi64(-1));

#define LV_CPU_BLAKE_G(a, b, c, d, x, y) \
                v[a] = _mm512_add_epi64(_mm512_add_epi64(v[a], v[b]), m[x]); \
                v[d] = _mm512_ror_epi64(_mm512_xor_si512(v[d], v[a]), 32); \
                v[c] = _mm512_add_epi64(v[c], v[d]); \
                v[b] = _mm512_ror_epi64(_mm512_xor_si512(v[b], v[c]), 24); \
                v[a] = _mm512_add_epi64(_mm512_add_epi64(v[a], v[b]), m[y]); \
                v[d] = _mm512_ror_epi64(_mm512_xor_si512(v[d], v[a]), 16); \
                v[c] = _mm512_add_epi64(v[c], v[d]); \
                v[b] = _mm512_ror_epi64(_mm512_xor_si512(v[b], v[c]), 63)
#pragma GCC unroll 12
                for (unsigned round = 0; round < 12; ++round)
                {
                    const auto* s = sigma[round];
                    LV_CPU_BLAKE_G(0,4,8,12,s[0],s[1]);
                    LV_CPU_BLAKE_G(1,5,9,13,s[2],s[3]);
                    LV_CPU_BLAKE_G(2,6,10,14,s[4],s[5]);
                    LV_CPU_BLAKE_G(3,7,11,15,s[6],s[7]);
                    LV_CPU_BLAKE_G(0,5,10,15,s[8],s[9]);
                    LV_CPU_BLAKE_G(1,6,11,12,s[10],s[11]);
                    LV_CPU_BLAKE_G(2,7,8,13,s[12],s[13]);
                    LV_CPU_BLAKE_G(3,4,9,14,s[14],s[15]);
                }
#undef LV_CPU_BLAKE_G
                __m512i words[8];
                for (unsigned j = 0; j < 8; ++j)
                {
                    words[j] = _mm512_xor_si512(h[j], _mm512_xor_si512(v[j], v[j + 8]));
                    if (!transposeOutput)
                        _mm512_i64scatter_epi64(destination + node * 64 + j * 8, offsets, words[j], 8);
                }
                if (!transposeOutput) continue;
                // Transpose eight independent hashes into contiguous output
                // blocks. Eight full stores replace 64 scattered word stores.
                __m512i pairs[8], quads[8];
                for (unsigned j = 0; j < 8; j += 2)
                {
                    pairs[j] = _mm512_unpacklo_epi64(words[j], words[j+1]);
                    pairs[j+1] = _mm512_unpackhi_epi64(words[j], words[j+1]);
                }
                for (unsigned j = 0; j < 8; j += 4)
                {
                    quads[j] = _mm512_shuffle_i64x2(pairs[j], pairs[j+2], 0x88);
                    quads[j+1] = _mm512_shuffle_i64x2(pairs[j+1], pairs[j+3], 0x88);
                    quads[j+2] = _mm512_shuffle_i64x2(pairs[j], pairs[j+2], 0xdd);
                    quads[j+3] = _mm512_shuffle_i64x2(pairs[j+1], pairs[j+3], 0xdd);
                }
                for (unsigned j = 0; j < 4; ++j)
                {
                    _mm512_storeu_si512(destination + (node+j)*64,
                        _mm512_shuffle_i64x2(quads[j], quads[j+4], 0x88));
                    _mm512_storeu_si512(destination + (node+j+4)*64,
                        _mm512_shuffle_i64x2(quads[j], quads[j+4], 0xdd));
                }
            }
        }

        class VectorBlake2xb final : public seal::UniformRandomGenerator
        {
        public:
            explicit VectorBlake2xb(seal::prng_seed_type seed) : UniformRandomGenerator(seed) {}

        protected:
            seal::prng_type type() const noexcept override { return seal::prng_type::blake2xb; }

            void refill_buffer() override
            {
                // Retain SEAL's keyed root, counter and buffer boundaries, so
                // arbitrary generate()/refresh() calls preserve its byte stream.
                blake2xb_state state{};
                std::uint64_t root[8];
                if (blake2xb_init_key(&state, 4096, seed_.cbegin(), 64) ||
                    blake2xb_update(&state, &mCounter, sizeof(mCounter)) ||
                    blake2b_final(state.S, root, sizeof(root)))
                    throw std::runtime_error("BLAKE2xb root failed");
                outputBlocks(root, buffer_begin_);
                seal::util::seal_memzero(root, sizeof(root));
                seal::util::seal_memzero(&state, sizeof(state));
                ++mCounter;
            }

        private:
            std::uint64_t mCounter = 0;
        };

        class VectorBlake2xbFactory final : public seal::UniformRandomGeneratorFactory
        {
            std::shared_ptr<seal::UniformRandomGenerator> create_impl(seal::prng_seed_type seed) override
            {
                return std::make_shared<VectorBlake2xb>(seed);
            }
        };
#endif
    }

    std::shared_ptr<seal::UniformRandomGeneratorFactory> cpuBlake2xbFactory()
    {
        static const std::shared_ptr<seal::UniformRandomGeneratorFactory> factory = [] {
#if defined(LV_CPU_BLAKE_AVX512)
            const char* enabled = std::getenv("LV_CPU_VECTOR_BLAKE2");
            if (cpuBlake2xbVectorAvailable() && (!enabled || enabled[0] != '0'))
                return std::shared_ptr<seal::UniformRandomGeneratorFactory>(
                    std::make_shared<VectorBlake2xbFactory>());
#endif
            return std::shared_ptr<seal::UniformRandomGeneratorFactory>(
                std::make_shared<seal::Blake2xbPRNGFactory>());
        }();
        return factory;
    }

    std::shared_ptr<seal::UniformRandomGeneratorFactory> cpuDefaultPrngFactory()
    {
        static const auto factory = [] {
            auto original = seal::UniformRandomGeneratorFactory::DefaultFactory();
            return original->create(seal::prng_seed_type{})->info().type_ == seal::prng_type::blake2xb
                ? cpuBlake2xbFactory() : original;
        }();
        return factory;
    }
}
