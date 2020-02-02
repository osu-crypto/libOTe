/*
Copyright (C) 2017 Ming-Shing Chen

This file is part of BitPolyMul.

BitPolyMul is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

BitPolyMul is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with BitPolyMul.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "libOTe/config.h"
#ifdef ENABLE_SILENTOT

#include "bc.h"
#include "bpmDefines.h"

#include <emmintrin.h>
#include <immintrin.h>
#define BC_CODE_GEN

#define LOG2(X) ((u64) (8*sizeof (u64) - __builtin_clzll((X)) - 1))
#define MAX(x,y) (((x)>(y))?(x):(y))
#define MIN(x,y) (((x)<(y))?(x):(y))

namespace bpm 
{


     inline
        void __xor_down_256(__m256i* poly, u64 dest_idx, u64 src_idx, u64 len)
    {
        for (u64 i = len; i > 0;) {
            i--;
            poly[dest_idx + i] = xor256(poly[dest_idx + i], poly[src_idx + i]);
        }
    }

    //USED;
     inline
        void __xor_up_256(__m256i* poly, u64 dest_idx, u64 src_idx, u64 len)
    {
        for (u64 i = 0; i < len; i++) {
            poly[dest_idx + i] = xor256(poly[dest_idx + i], poly[src_idx + i]);
        }
    }

     inline
        void __xor_down_256_2(__m256i* poly, u64 len, u64 l_st) {
        __xor_down_256(poly, l_st, len, len);
    }

     inline
        void xor_up_256(__m256i* poly, u64 st, u64 len, u64 diff)
    {
        __xor_up_256(poly, st, diff + st, len);
    }

     inline
        void __xor_up_256_2(__m256i* poly, u64 len, u64 l_st) {
        __xor_up_256(poly, l_st, len, len);
    }


    
        __m256i _mm256_alignr_255bit_zerohigh(__m256i zerohigh, __m256i low)
    {
        __m256i l_shr_15 = _mm256_srli_epi16(low, 15);
        __m256i r_1 = _mm256_permute2x128_si256(l_shr_15, zerohigh, 0x21);
        return _mm256_srli_si256(r_1, 14);
    }

    
        __m256i _mm256_alignr_254bit_zerohigh(__m256i zerohigh, __m256i low)
    {
        __m256i l_shr_14 = _mm256_srli_epi16(low, 14);
        __m256i r_2 = _mm256_permute2x128_si256(l_shr_14, zerohigh, 0x21);
        return _mm256_srli_si256(r_2, 14);
    }

    
        __m256i _mm256_alignr_252bit_zerohigh(__m256i zerohigh, __m256i low)
    {
        __m256i l_shr_12 = _mm256_srli_epi16(low, 12);
        __m256i r_4 = _mm256_permute2x128_si256(l_shr_12, zerohigh, 0x21);
        return _mm256_srli_si256(r_4, 14);
    }

    
        __m256i _mm256_alignr_255bit(__m256i high, __m256i low)
    {
        __m256i l_shr_15 = _mm256_srli_epi16(low, 15);
        __m256i h_shr_15 = _mm256_srli_epi16(high, 15);
        __m256i h_shl_1 = _mm256_slli_epi16(high, 1);
        __m256i r = xor256(h_shl_1, _mm256_slli_si256(h_shr_15, 2));

        __m256i r_1 = _mm256_permute2x128_si256(l_shr_15, h_shr_15, 0x21);
        r = xor256(r, _mm256_srli_si256(r_1, 14));
        return r;
    }

    
        __m256i _mm256_alignr_254bit(__m256i high, __m256i low)
    {
        __m256i l_shr_14 = _mm256_srli_epi16(low, 14);
        __m256i h_shr_14 = _mm256_srli_epi16(high, 14);
        __m256i h_shl_2 = _mm256_slli_epi16(high, 2);
        __m256i r = xor256(h_shl_2, _mm256_slli_si256(h_shr_14, 2));

        __m256i r_2 = _mm256_permute2x128_si256(l_shr_14, h_shr_14, 0x21);
        r = xor256(r, _mm256_srli_si256(r_2, 14));
        return r;
    }

    
        __m256i _mm256_alignr_252bit(__m256i high, __m256i low)
    {
        __m256i l_shr_12 = _mm256_srli_epi16(low, 12);
        __m256i h_shr_12 = _mm256_srli_epi16(high, 12);
        __m256i h_shl_4 = _mm256_slli_epi16(high, 4);
        __m256i r = xor256(h_shl_4, _mm256_slli_si256(h_shr_12, 2));

        __m256i r_4 = _mm256_permute2x128_si256(l_shr_12, h_shr_12, 0x21);
        r = xor256(r, _mm256_srli_si256(r_4, 14));
        return r;
    }

    
        __m256i _mm256_alignr_31byte(__m256i high, __m256i low)
    {
        __m256i l0 = _mm256_permute2x128_si256(low, high, 0x21);
        return _mm256_alignr_epi8(high, l0, 15);
    }

    
        __m256i _mm256_alignr_30byte(__m256i high, __m256i low)
    {
        __m256i l0 = _mm256_permute2x128_si256(low, high, 0x21);
        return _mm256_alignr_epi8(high, l0, 14);
    }

    
        __m256i _mm256_alignr_28byte(__m256i high, __m256i low)
    {
        __m256i l0 = _mm256_permute2x128_si256(low, high, 0x21);
        return _mm256_alignr_epi8(high, l0, 12);
    }

    
        __m256i _mm256_alignr_24byte(__m256i high, __m256i low)
    {
        __m256i l0 = _mm256_permute2x128_si256(low, high, 0x21);
        return _mm256_alignr_epi8(high, l0, 8);
    }

    
        __m256i _mm256_alignr_16byte(__m256i high, __m256i low)
    {
        return _mm256_permute2x128_si256(low, high, 0x21);
    }

    //USED;
    
        __m256i (*_sh_op[8]) (__m256i h, __m256i l) = {
            _mm256_alignr_255bit, _mm256_alignr_254bit, _mm256_alignr_252bit, _mm256_alignr_31byte, _mm256_alignr_30byte, _mm256_alignr_28byte, _mm256_alignr_24byte, _mm256_alignr_16byte
    };

    //USED;
    
        __m256i (*_sh_op_zerohigh[8]) (__m256i h, __m256i l) = {
            _mm256_alignr_255bit_zerohigh , _mm256_alignr_254bit_zerohigh , _mm256_alignr_252bit_zerohigh , _mm256_alignr_31byte, _mm256_alignr_30byte, _mm256_alignr_28byte, _mm256_alignr_24byte, _mm256_alignr_16byte
    };


    //USED;
     inline
        void __sh_xor_down(__m256i* poly256, u64 unit, u64 _op, __m256i zero)
    {
        u64 unit_2 = unit >> 1;
        poly256[unit_2] = xor256(poly256[unit_2], _sh_op_zerohigh[_op](zero, poly256[unit - 1]));
        for (u64 i = 0; i < unit_2 - 1; i++) {
            poly256[unit_2 - 1 - i] = xor256(poly256[unit_2 - 1 - i], _sh_op[_op](poly256[unit - 1 - i], poly256[unit - 2 - i]));
        }
        poly256[0] = xor256(poly256[0], _sh_op[_op](poly256[unit_2], zero));
    }


    //USED;
    
        void varsub_x256(__m256i* poly256, u64 n_256)
    {
        if (1 >= n_256) return;
        u64 log_n = __builtin_ctzll(n_256);
        __m256i zero = _mm256_setzero_si256();

        while (log_n > 8) {
            u64 unit = 1ull << log_n;
            u64 num = n_256 / unit;
            u64 unit_2 = unit >> 1;
            for (u64 j = 0; j < num; j++) __xor_down_256_2(poly256 + j * unit, unit_2, (1ull << (log_n - 9)));
            log_n--;
        }

        for (u64 i = log_n; i > 0; i--) {
            u64 unit = (1ull << i);
            u64 num = n_256 / unit;
            for (u64 j = 0; j < num; j++) __sh_xor_down(poly256 + j * unit, unit, i - 1, zero);
        }

    }


    //USED;
     inline
        void __sh_xor_up(__m256i* poly256, u64 unit, u64 _op, __m256i zero)
    {
        u64 unit_2 = unit >> 1;
        poly256[0] = xor256(poly256[0], _sh_op[_op](poly256[unit_2], zero));
        for (u64 i = 0; i < unit_2 - 1; i++) {
            poly256[i + 1] = xor256(poly256[i + 1], _sh_op[_op](poly256[unit_2 + i + 1], poly256[unit_2 + i]));
        }
        poly256[unit_2] = xor256(poly256[unit_2], _sh_op_zerohigh[_op](zero, poly256[unit - 1]));
    }



    //USED;
    
        void i_varsub_x256(__m256i* poly256, u64 n_256)
    {
        if (1 >= n_256) return;
        u64 log_n = __builtin_ctzll(n_256);
        __m256i zero = _mm256_setzero_si256();

        u64 _log_n = (log_n > 8) ? 8 : log_n;
        for (u64 i = 1; i <= _log_n; i++) {
            u64 unit = (1ull << i);
            u64 num = n_256 / unit;
            for (u64 j = 0; j < num; j++) __sh_xor_up(poly256 + j * unit, unit, i - 1, zero);
        }

        for (u64 i = 9; i <= log_n; i++) {
            u64 unit = 1ull << i;
            u64 num = n_256 / unit;
            u64 unit_2 = unit >> 1;
            for (u64 j = 0; j < num; j++) __xor_up_256_2(poly256 + j * unit, unit_2, (1ull << (i - 9)));
        }
    }

    //USED;
    void bc_to_lch_2_unit256(bc_sto_t* poly, u64 n_terms)
    {
        assert(0 == (n_terms & (n_terms - 1)));
        assert(4 <= n_terms);

        __m256i* poly256 = (__m256i*) poly;
        u64 n_256 = n_terms >> 2;

        varsub_x256(poly256, n_256);
#ifdef BC_CODE_GEN
        int logn = LOG2(n_256);
        bc_to_lch_256_30_12(poly256, logn);
        for (int i = 0; i < (1 << (MAX(0, logn - 19))); ++i) {
            bc_to_lch_256_19_17(poly256 + i * (1ull << 19), MIN(19, logn));
        }
        for (int i = 0; i < (1 << (MAX(0, logn - 16))); ++i) {
            bc_to_lch_256_16(poly256 + i * (1ull << 16), MIN(16, logn));
        }
#else
        _bc_to_lch_256(poly256, n_256, 1);
#endif
    }


    //USED;
    void bc_to_mono_2_unit256(bc_sto_t* poly, u64 n_terms)
    {
        assert(0 == (n_terms & (n_terms - 1)));
        assert(4 <= n_terms);

        __m256i* poly256 = (__m256i*) poly;
        u64 n_256 = n_terms >> 2;

#ifdef BC_CODE_GEN
        int logn = LOG2(n_256);
        for (int i = 0; i < (1 << (MAX(0, logn - 16))); ++i) {
            bc_to_mono_256_16(poly256 + i * (1ull << 16), MIN(16, logn));
        }
        for (int i = 0; i < (1 << (MAX(0, logn - 19))); ++i) {
            bc_to_mono_256_19_17(poly256 + i * (1ull << 19), MIN(19, logn));
        }
        bc_to_mono_256_30_20(poly256, logn);
#else
        _bc_to_mono_256(poly256, n_256, 1);
#endif
        i_varsub_x256(poly256, n_256);
    }

}
#endif