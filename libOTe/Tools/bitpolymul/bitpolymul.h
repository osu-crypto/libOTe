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


#include <stdint.h>
#include <cryptoTools/Common/Defines.h>
#include <vector>
#include <boost/align/aligned_allocator.hpp>


namespace bpm
{
    void bitpolymul_2_128(uint64_t* c, const uint64_t* a, const uint64_t* b, oc::u64 n_64);

    void bitpolymul_2_64(uint64_t* c, const uint64_t* a, const uint64_t* b, oc::u64 n_64);



    void bitpolymul(uint64_t* c, const uint64_t* a, const uint64_t* b, uint64_t n_64);


    template <typename T>
    using aligned_vector = std::vector<T, boost::alignment::aligned_allocator<T, 32>>;


    template<typename T>
    using span = oc::span<T>;

    using u64 = oc::u64;
    using u32 = oc::u32;
    using u8 = oc::u8;

    class FFTPoly
    {
    public:

        FFTPoly() = default;
        FFTPoly(const FFTPoly&) = default;
        FFTPoly(FFTPoly&&) = default;

        FFTPoly(span<const u64> data)
        {
            encode(data);
        }

        u64 mN = 0, mNPow2 = 0;
        aligned_vector<u64> mPoly;

        void resize(u64 n);

        void encode(span<const u64> data);


        void mult(const FFTPoly& a, const FFTPoly& b);
        void multEq(const FFTPoly& b);

        void add(const FFTPoly& a, const FFTPoly& b);
        void addEq(const FFTPoly& b);


        struct DecodeCache
        {
            aligned_vector<u64> mTemp, mTemp2;
        };

        void decode(span<u64> dest, bool destructive = true);
        void decode(span<u64> dest, DecodeCache& cache, bool destructive);

    };
}

#endif
