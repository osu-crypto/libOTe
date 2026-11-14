#pragma once
#include "ChosenBaaField.h"
#include <array>
#include <algorithm>

namespace osuCrypto::chosen_baa_detail
{
    struct AdditivePoints : ChosenBaaField<block>
    {
        static block point(u64 i) { return block(0, i); }
    };

    // For evaluation points 0..7 and 8..15 the Lagrange matrix has entries
    // M[i,j]=c[i XOR j]. Translate the group algebra by t_i=x_i+1; then
    // t_i^2=0. A three-bit subset convolution replaces 64 field products
    // with 19 (24 SIMD slots). The transform is its own inverse in char 2.
    struct AdditiveRs8
    {
        std::array<block, 24> coefficients;
        template<unsigned Bit = 0, unsigned I = 0>
        static OC_FORCEINLINE void zeta(block* v)
        {
            if constexpr (Bit < 3)
            {
                if constexpr (I < 8)
                {
                    if constexpr (!(I & (1u << Bit))) v[I] ^= v[I | (1u << Bit)];
                    zeta<Bit, I + 1>(v);
                }
                else zeta<Bit + 1, 0>(v);
            }
        }
        void init(const block* c)
        {
            std::array<block, 8> v;
            std::copy_n(c, 8, v.data()); zeta(v.data());
            if (v[0] != OneBlock) throw std::logic_error("Additive RS row sum.");
            coefficients = {v[1],v[2],v[3],v[4],v[5],v[6],v[7],ZeroBlock,
                v[2],v[1],v[4],v[1],v[4],v[2],v[6],v[5],
                v[4],v[3],v[2],v[1],ZeroBlock,ZeroBlock,ZeroBlock,ZeroBlock};
        }
        OC_FORCEINLINE void apply(const block* input, block* output) const
        {
            std::array<block, 8> u;
            std::copy_n(input, 8, u.data()); zeta(u.data());
            std::array<block, 8> a{u[0],u[0],u[0],u[0],u[0],u[0],u[0],ZeroBlock};
            std::array<block, 8> b{u[1],u[2],u[1],u[4],u[2],u[4],u[1],u[2]};
            std::array<block, 8> c{u[3],u[4],u[5],u[6],ZeroBlock,ZeroBlock,ZeroBlock,ZeroBlock};
            ChosenBaaField<block>::mul8(a.data(), coefficients.data());
            ChosenBaaField<block>::mul8(b.data(), coefficients.data() + 8);
            ChosenBaaField<block>::mul8(c.data(), coefficients.data() + 16);
            u[1] ^= a[0]; u[2] ^= a[1]; u[3] ^= a[2] ^ b[0] ^ b[1];
            u[4] ^= a[3]; u[5] ^= a[4] ^ b[2] ^ b[3]; u[6] ^= a[5] ^ b[4] ^ b[5];
            u[7] ^= a[6] ^ b[6] ^ b[7] ^ c[0] ^ c[1] ^ c[2] ^ c[3];
            zeta(u.data()); std::copy(u.begin(), u.end(), output);
        }
    };
}
