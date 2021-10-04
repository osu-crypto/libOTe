#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_BITPOLYMUL


#include <stdint.h>
#include <cryptoTools/Common/Defines.h>
#include <vector>
#include <boost/align/aligned_allocator.hpp>
#include "bitpolymul/bitpolymul.h"

namespace osuCrypto
{

    template <typename T>
    using aligned_vector = std::vector<T, boost::alignment::aligned_allocator<T, 32>>;




    void bitpolymul(uint64_t* c, const uint64_t* a, const uint64_t* b, uint64_t n_64);

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

    inline std::ostream& operator<<(std::ostream& o, const FFTPoly& p)
    {
        //o << toStr(p.mPoly);
        o << "[" << p.mPoly.size() << "][";
        for (const auto& v : p.mPoly)
        {
            o << v << ", ";
        }
        o << "]";
        return o;
    }
}

#endif
