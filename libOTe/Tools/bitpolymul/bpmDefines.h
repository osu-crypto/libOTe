#pragma once

#include <stdint.h>
#include <cryptoTools/Common/Defines.h>
#include <vector>
#include <boost/align/aligned_allocator.hpp>

namespace bpm
{

    template <typename T>
    using aligned_vector = std::vector<T, boost::alignment::aligned_allocator<T, 32>>;

    template<typename T>
    using span = oc::span<T>;

    using u64 = oc::u64;
    using u32 = oc::u32;
    using u8 = oc::u8;


    template<typename T>
    struct toStr_ {
        const T& mV;
        toStr_(const T& v) : mV(v) {}


    };
    template<typename T>
    inline toStr_<T> toStr(const T& v)
    {
        return toStr_<T>(v);
    }
    template<typename T>
    inline std::ostream& operator<<(std::ostream& o, const toStr_<T>& t)
    {
        o << "[" <<t.mV.size() << "][";
        for (const auto& v : t.mV)
        {
            o << v << ", ";
        }
        o << "]";
        return o;
    }
}


#ifdef _MSC_VER
#include <intrin.h>
#include <malloc.h>

//#define (x) 

 inline int __builtin_ctz(uint32_t x) {
    unsigned long ret;
    _BitScanForward(&ret, x);
    return (int)ret;
}

 inline int __builtin_ctzll(unsigned long long x) {
    unsigned long ret;
    _BitScanForward64(&ret, x);
    return (int)ret;
}



 inline int __builtin_ctzl(unsigned long x) { return sizeof(x) == 8 ? __builtin_ctzll(x) : __builtin_ctz((uint32_t)x); }
 inline int __builtin_clz(uint32_t x) { return (int)__lzcnt(x); }
 inline int __builtin_clzll(unsigned long long x) { return (int)__lzcnt64(x); }
 inline int __builtin_clzl(unsigned long x) { return sizeof(x) == 8 ? __builtin_clzll(x) : __builtin_clz((uint32_t)x); }

 inline int __builtin_ctzl(unsigned long long x) { return __builtin_ctzll(x); }
 inline int __builtin_clzl(unsigned long long x) { return __builtin_clzll(x); }

#endif

#include <immintrin.h>
#include <mmintrin.h>
#include <xmmintrin.h>

#define xor128(v1,v2) _mm_xor_si128(v1,v2)
#define xor256(v1,v2) _mm256_xor_si256(v1,v2)
#define and128(v1,v2) _mm_and_si128(v1,v2)
#define and256(v1,v2) _mm256_and_si256(v1,v2)
#define or128(v1,v2) _mm_or_si128(v1,v2)
#define or256(v1,v2) _mm256_or_si256(v1,v2)


#define cache_prefetch(d, p) _mm_prefetch((const char*)d, p)