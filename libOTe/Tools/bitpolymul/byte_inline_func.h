#pragma once
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
#ifdef ENABLE_BITPOLYMUL

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "bpmDefines.h"
#include <cryptoTools/gsl/gsl>
#include <immintrin.h>

namespace bpm {
    static inline
        unsigned byte_is_zero(const uint64_t* vec, unsigned n) { unsigned r = 0; for (unsigned i = 0; i < n; i++) r |= vec[i]; return (0 == r); }

    static inline
        void byte_xor(uint64_t* v1, const uint64_t* v2, unsigned n) { for (unsigned i = 0; i < n; i++) v1[i] ^= v2[i]; }


    static inline
        void u64_rand(uint64_t* vec, unsigned n) { for (unsigned i = 0; i < n; i++) vec[i] = rand() & 0xff; }

    static inline
        void byte_rand(uint8_t* vec, unsigned n) { for (unsigned i = 0; i < n; i++) vec[i] = rand() & 0xff; }

    static inline
        void u64_fdump(FILE* fp, gsl::span<const uint64_t> v) {
        fprintf(fp, "[%2d][", v.size());
        for (unsigned i = 0; i < v.size(); i++) { fprintf(fp, "0x%02lx,", v[i]); if (7 == (i % 8)) fprintf(fp, " "); }
        fprintf(fp, "]");
    }

    static inline
        void byte_fdump(FILE* fp, const uint8_t* v, unsigned _num_byte) {
        fprintf(fp, "[%2d][", _num_byte);
        for (unsigned i = 0; i < _num_byte; i++) { fprintf(fp, "0x%02x,", v[i]); if (7 == (i % 8)) fprintf(fp, " "); }
        fprintf(fp, "]");
    }

    static inline
        void u64_dump(gsl::span<const uint64_t>v) { u64_fdump(stdout, v); }

    static inline
        void byte_dump(const uint8_t* v, unsigned _num_byte) { byte_fdump(stdout, v, _num_byte); }




    static inline
        void xmm_rand(__m128i* vec, unsigned n) { byte_rand((uint8_t*)vec, n * 16); }

    static inline
        uint64_t xmm_is_zero(const __m128i* vec, unsigned n) {
        __m128i r = _mm_setzero_si128();
        for (unsigned i = 0; i < n; i++) r = or128(r, vec[i]);
        return 0xffff == _mm_movemask_epi8(_mm_cmpeq_epi8(r, _mm_setzero_si128()));
    }

    static inline
        void xmm_xor(__m128i* v1, const __m128i* v2, unsigned n) { for (unsigned i = 0; i < n; i++) v1[i] = xor128(v1[i], v2[i]); }

    static inline
        void xmm_fdump(FILE* fp, const __m128i* v, unsigned n) {
        fprintf(fp, "[%2d][", n);
        const uint64_t* v64 = (const uint64_t*)v;
        for (unsigned i = 0; i < n; i++) { fprintf(fp, "0x%02lx-%02lx, ", v64[i * 2 + 1], v64[i * 2]); if (7 == (i % 8)) fprintf(fp, "|"); }
        fprintf(fp, "]");
    }

    static inline
        void xmm_dump(const __m128i* v, unsigned n) { xmm_fdump(stdout, v, n); }

}
#endif
