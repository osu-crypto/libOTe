#pragma once

#include <stdint.h>
#include <cryptoTools/Common/Defines.h>
#include <vector>
#include <boost/align/aligned_allocator.hpp>

namespace bpm
{
    template <typename T>
    using aligned_vector = std::vector<T, boost::alignment::aligned_allocator<T, 32>>;
}


#ifdef _MSC_VER
#include <intrin.h>
#include <malloc.h>

//#define aligned_alloc(a,s)  malloc(s)
//_aligned_malloc(s,a)

#define BIT_POLY_ALIGN(x) 

static inline int __builtin_ctz(uint32_t x) {
    unsigned long ret;
    _BitScanForward(&ret, x);
    return (int)ret;
}

static inline int __builtin_ctzll(unsigned long long x) {
    unsigned long ret;
    _BitScanForward64(&ret, x);
    return (int)ret;
}



static inline int __builtin_ctzl(unsigned long x) { return sizeof(x) == 8 ? __builtin_ctzll(x) : __builtin_ctz((uint32_t)x); }
static inline int __builtin_clz(uint32_t x) { return (int)__lzcnt(x); }
static inline int __builtin_clzll(unsigned long long x) { return (int)__lzcnt64(x); }
static inline int __builtin_clzl(unsigned long x) { return sizeof(x) == 8 ? __builtin_clzll(x) : __builtin_clz((uint32_t)x); }

#ifdef __cplusplus
static inline int __builtin_ctzl(unsigned long long x) { return __builtin_ctzll(x); }
static inline int __builtin_clzl(unsigned long long x) { return __builtin_clzll(x); }
#endif

#else

#define BIT_POLY_ALIGN(x) __attribute__((aligned(x)))

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
//
//inline void cache_prefetch(__m128i* d, int p)
//{
//    _mm_prefetch((const char*)d, p);
//}
//inline void cache_prefetch(__m256i* d, int p)
//{
//    _mm_prefetch((const char*)d, p);
//}
