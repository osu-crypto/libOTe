#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 

#include <cinttypes>
#include <iomanip>
#include <vector>
#include <emmintrin.h>
#include <smmintrin.h>
#include <sstream>
#include <iostream>
#include "boost/lexical_cast.hpp"
#include <memory>
#include "Common/Timer.h"

#ifdef GetMessage
#undef GetMessage
#endif

#ifndef _MSC_VER
#pragma GCC diagnostic ignored "-Wignored-attributes"
#endif

#ifdef _MSC_VER 
#define __STR2__(x) #x
#define __STR1__(x) __STR2__(x)
#define TODO(x) __pragma(message (__FILE__ ":"__STR1__(__LINE__) " Warning:TODO - " #x))
#define ALIGNED(__Declaration, __alignment) __declspec(align(__alignment)) __Declaration 
#else
#define TODO(x) 
#define ALIGNED(__Declaration, __alignment) __Declaration __attribute__((aligned (16)))
#endif

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define LOCATION __FILE__ ":" STRINGIZE(__LINE__)


namespace osuCrypto {
    template<typename T> using ptr = T*;
    template<typename T> using uPtr = std::unique_ptr<T>;
    template<typename T> using sPtr = std::shared_ptr<T>;

    typedef uint64_t u64;
    typedef int64_t i64;
    typedef uint32_t u32;
    typedef int32_t i32;
    typedef uint16_t u16;
    typedef int16_t i16;
    typedef uint8_t u8;
    typedef int8_t i8;

    enum Role
    {
        First = 0,
        Second = 1
    };

    extern Timer gTimer;

    template<typename T>
    static std::string ToString(const T& t)
    {
        return boost::lexical_cast<std::string>(t);
    }

    typedef  __m128i block;
    inline block toBlock(u8*data)
    { return _mm_set_epi64x(((u64*)data)[1], ((u64*)data)[0]);}

    template <size_t N>
    using  MultiBlock = std::array<block, N>;

#ifdef _MSC_VER
    inline block operator^(const block& lhs, const block& rhs)
    {
        return _mm_xor_si128(lhs, rhs);
    }
    inline block operator&(const block& lhs, const block& rhs)
    {
        return _mm_and_si128(lhs, rhs);
    }

    inline block operator<<(const block& lhs, const u8& rhs)
    {
        return _mm_slli_epi64(lhs, rhs);
    }
    inline block operator>>(const block& lhs, const u8& rhs)
    {
        return _mm_srli_epi64(lhs, rhs);
    }
    inline block operator+(const block& lhs, const block& rhs)
    {
        return _mm_add_epi64(lhs, rhs);
    }

    
#endif

    template <size_t N>
    inline MultiBlock<N> operator^(const MultiBlock<N>& lhs, const MultiBlock<N>& rhs)
    {
        MultiBlock<N> rs;

        for (u64 i = 0; i < N; ++i)
        {
            rs[i] = lhs[i] ^ rhs[i];
        }
        return rs;
    }
    template <size_t N>
    inline MultiBlock<N> operator&(const MultiBlock<N>& lhs, const MultiBlock<N>& rhs)
    {
        MultiBlock<N> rs;

        for (u64 i = 0; i < N; ++i)
        {
            rs[i] = lhs[i] & rhs[i];
        }
        return rs;
    }

    extern const block ZeroBlock;
    extern const block OneBlock;
    extern const block AllOneBlock;
    extern const block CCBlock;

    inline u64 roundUpTo(u64 val, u64 step)
    {
        return ((val + step - 1) / step) * step;
    }

    inline u8* ByteArray(const block& b)
    {
        return ((u8 *)(&b));
    }

    template <size_t N>
    inline u8* ByteArray(const MultiBlock<N>& b)
    {
        return ((u8 *)(&b));
    }

    std::ostream& operator<<(std::ostream& out, const block& block);
    
    template <size_t N>
    std::ostream& operator<<(std::ostream& out, const MultiBlock<N>& block);

    class Commit;
    class BitVector;

    std::ostream& operator<<(std::ostream& out, const Commit& comm);
    //std::ostream& operator<<(std::ostream& out, const BitVector& vec);
    //typedef block block;

    block PRF(const block& b, u64 i);

    void split(const std::string &s, char delim, std::vector<std::string> &elems);
    std::vector<std::string> split(const std::string &s, char delim);


    u64 log2ceil(u64);
    u64 log2floor(u64);

}

inline bool eq(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    osuCrypto::block neq = _mm_xor_si128(lhs, rhs);
    return _mm_test_all_zeros(neq, neq) != 0;
}

inline bool neq(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    osuCrypto::block neq = _mm_xor_si128(lhs, rhs);
    return _mm_test_all_zeros(neq, neq) == 0;
}

template<size_t N>
inline bool neq(const osuCrypto::MultiBlock<N>& lhs, const osuCrypto::MultiBlock<N>& rhs)
{
    osuCrypto::MultiBlock<N> neq = lhs^ rhs;

    using namespace osuCrypto;

    int ret = 0;
    for (u64 i = 0; i < N; ++i)
    {
        ret |= _mm_test_all_zeros(neq[i], neq[i]);
    }
    return ret;
}


#ifdef _MSC_VER
inline bool operator==(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    return eq(lhs, rhs);
}

inline bool operator!=(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    return neq(lhs, rhs);
}
inline bool operator<(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    return lhs.m128i_u64[1] < rhs.m128i_u64[1] || (eq(lhs, rhs) && lhs.m128i_u64[0] < rhs.m128i_u64[0]);
}


#endif
//typedef struct largeBlock {
//
//} largeBlock;
//typedef  std::array<block, 4>  blockRIOT;

//
//#ifdef _MSC_VER // if Visual C/C++
//__inline __m64 _mm_set_pi64x(const __int64 i) {
//    union {
//        __int64 i;
//        __m64 v;
//    } u;
//
//    u.i = i;
//    return u.v;
//}
//#endif
