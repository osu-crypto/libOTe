#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <utility>
#ifdef OC_ENABLE_VPCLMUL
#include <immintrin.h>
#endif

namespace osuCrypto
{
    // Stateless field policy. F's PRNG::Any constructor must sample uniformly
    // in F (not copy bytes into a modular representation). Override this policy
    // for fields with a different representation or sampling interface.
    // point(0)..point(15) must be distinct; config() checks this requirement.
    template<typename F>
    struct ChosenBaaField
    {
        using Element = F;
        static F zero() { return F(0); }
        static F one() { return F(1); }
        static F point(u64 i) { return F(i + 1); }
        static F add(const F& a, const F& b) { return a + b; }
        static F sub(const F& a, const F& b) { return a - b; }
        static F mul(const F& a, const F& b) { return a * b; }
        static F inverse(const F& a) { return a.inverse(); }
        static void sample8(PRNG& random, F* out)
        {
            for (u64 i = 0; i < 8; ++i)
                do { out[i] = F(random.get()); } while (out[i] == zero());
        }
        template<std::size_t... I>
        static OC_FORCEINLINE void mul8Impl(F* a, const F* b, std::index_sequence<I...>)
        { ((a[I] = mul(a[I], b[I])), ...); }
        static OC_FORCEINLINE void mul8(F* a, const F* b)
        { mul8Impl(a, b, std::make_index_sequence<8>{}); }
        template<u64 K, u64 Row = 0, u64 Col = 0>
        static OC_FORCEINLINE F dot(const F* in, const F* matrix, F sum)
        {
            if constexpr (Col == 16 - K) return sum;
            else return dot<K, Row, Col + 1>(in, matrix,
                add(sum, mul(in[K + Col], matrix[Col * K + Row])));
        }
        template<u64 K, u64 Row = 0>
        static OC_FORCEINLINE void local(const F* in, F* out, const F* matrix)
        {
            if constexpr (Row < K)
            {
                out[Row] = dot<K, Row>(in, matrix, in[Row]);
                local<K, Row + 1>(in, out, matrix);
            }
        }
        template<u64 K, u64 Col, u64 Row = 0>
        static OC_FORCEINLINE F forwardDot(const F* in, const F* matrix, F sum)
        {
            if constexpr (Row == K) return sum;
            else return forwardDot<K, Col, Row + 1>(in, matrix,
                add(sum, mul(in[Row], matrix[Row * (16 - K) + Col])));
        }
        template<u64 K, u64 Col = 0>
        static OC_FORCEINLINE void localForward(const F* in, F* out, const F* matrix)
        {
            if constexpr (Col < 16 - K)
            {
                out[K + Col] = forwardDot<K, Col>(in, matrix, zero());
                localForward<K, Col + 1>(in, out, matrix);
            }
        }
    };

    namespace chosen_baa_detail
    {
#ifdef OC_ENABLE_VPCLMUL
        // Each 128-bit lane is an independent field product. No horizontal
        // reduction, gathers, or cross-lane permutations in either kernel.
        struct Wide
        {
#ifdef ENABLE_AVX512
            using V = __m512i;
            static constexpr u64 lanes = 4;
            static OC_FORCEINLINE V load(const block* p) { return _mm512_loadu_si512(p); }
            static OC_FORCEINLINE void store(block* p, V x) { _mm512_storeu_si512(p, x); }
            static OC_FORCEINLINE V broadcast(block x) { return _mm512_broadcast_i32x4(x); }
            static OC_FORCEINLINE V bxor(V x, V y) { return _mm512_xor_si512(x, y); }
            static OC_FORCEINLINE V swap(V x) { return _mm512_shuffle_epi32(x, _MM_PERM_BADC); }
            template<int I> static OC_FORCEINLINE V clmul(V x, V y) { return _mm512_clmulepi64_epi128(x,y,I); }
            static OC_FORCEINLINE V left(V x) { return _mm512_bslli_epi128(x,8); }
            static OC_FORCEINLINE V right(V x) { return _mm512_bsrli_epi128(x,8); }
#else
            using V = __m256i;
            static constexpr u64 lanes = 2;
            static OC_FORCEINLINE V load(const block* p) { return _mm256_loadu_si256(reinterpret_cast<const V*>(p)); }
            static OC_FORCEINLINE void store(block* p, V x) { _mm256_storeu_si256(reinterpret_cast<V*>(p), x); }
            static OC_FORCEINLINE V broadcast(block x) { return _mm256_broadcastsi128_si256(x); }
            static OC_FORCEINLINE V bxor(V x, V y) { return _mm256_xor_si256(x, y); }
            static OC_FORCEINLINE V swap(V x) { return _mm256_shuffle_epi32(x, 0x4e); }
            template<int I> static OC_FORCEINLINE V clmul(V x, V y) { return _mm256_clmulepi64_epi128(x,y,I); }
            static OC_FORCEINLINE V left(V x) { return _mm256_slli_si256(x,8); }
            static OC_FORCEINLINE V right(V x) { return _mm256_srli_si256(x,8); }
#endif
            static OC_FORCEINLINE void product(V x, V y, V& lo, V& hi)
            {
                lo = clmul<0x00>(x,y);
                hi = clmul<0x11>(x,y);
                auto cross = bxor(clmul<0x00>(bxor(x,swap(x)),bxor(y,swap(y))),bxor(lo,hi));
                lo = bxor(lo,left(cross));
                hi = bxor(hi,right(cross));
            }
            static OC_FORCEINLINE V reduce(V lo, V hi)
            {
                const auto modulus = broadcast(block(0,0x87));
                auto t = clmul<0x01>(hi,modulus);
                lo = bxor(lo,left(t));
                hi = bxor(hi,right(t));
                return bxor(lo,clmul<0x00>(hi,modulus));
            }
        };
#endif
    }

    // Specialize arithmetic without virtual calls or callbacks in the encoder.
    // The byte stream and field representation are identical on every backend.
    template<>
    struct ChosenBaaField<block>
    {
        using Element = block;
        static block zero() { return ZeroBlock; }
        static block one() { return OneBlock; }
        static block point(u64 i) { return block(0, i + 1); }
        static OC_FORCEINLINE block add(block a, block b) { return a ^ b; }
        static OC_FORCEINLINE block sub(block a, block b) { return a ^ b; }
        static OC_FORCEINLINE block mul(block a, block b) { return a.gf128Mul(b); }
        static block inverse(block x)
        {
            block result = x;
            for (u64 i = 1; i < 127; ++i)
                result = mul(mul(result,result),x);
            return mul(result,result);
        }
        static OC_FORCEINLINE void sample8(PRNG& random, block* out)
        {
            random.get(out,8);
            // Preserve the existing draw order even on the negligible rejection
            // path, so all backends instantiate precisely the same matrix.
            for (u64 i = 0; i < 8; ++i)
                while (out[i] == ZeroBlock) out[i] = random.get<block>();
        }
        template<u64 I = 0>
        static OC_FORCEINLINE void mul8(block* a, const block* b)
        {
            if constexpr (I < 8)
            {
#ifdef OC_ENABLE_VPCLMUL
                using W = chosen_baa_detail::Wide;
                W::V lo, hi;
                W::product(W::load(a+I), W::load(b+I), lo, hi);
                W::store(a+I,W::reduce(lo,hi));
                mul8<I+W::lanes>(a,b);
#else
                a[I] = mul(a[I],b[I]);
                mul8<I+1>(a,b);
#endif
            }
        }
        template<u64 K, u64 Row, u64 Col = 0, typename V>
        static OC_FORCEINLINE void dot(const block* in, const block* matrix, V& lo, V& hi)
        {
            if constexpr (Col < 16 - K)
            {
#ifdef OC_ENABLE_VPCLMUL
                using W = chosen_baa_detail::Wide;
                V l,h;
                W::product(W::broadcast(in[K+Col]),W::load(matrix+Col*K+Row),l,h);
                lo=W::bxor(lo,l); hi=W::bxor(hi,h);
#else
                block l,h;
                in[K+Col].gf128Mul(matrix[Col*K+Row],l,h);
                lo^=l; hi^=h;
#endif
                dot<K,Row,Col+1>(in,matrix,lo,hi);
            }
        }
        template<u64 K, u64 Row = 0>
        static OC_FORCEINLINE void local(const block* in, block* out, const block* matrix)
        {
            if constexpr (Row < K)
            {
#ifdef OC_ENABLE_VPCLMUL
                using W = chosen_baa_detail::Wide;
                auto lo=W::broadcast(ZeroBlock),hi=lo;
                dot<K,Row>(in,matrix,lo,hi);
                W::store(out+Row,W::bxor(W::load(in+Row),W::reduce(lo,hi)));
                local<K,Row+W::lanes>(in,out,matrix);
#else
                block lo=ZeroBlock,hi=ZeroBlock;
                dot<K,Row>(in,matrix,lo,hi);
                out[Row]=in[Row]^lo.gf128Reduce(hi);
                local<K,Row+1>(in,out,matrix);
#endif
            }
        }
        template<u64 K, u64 Col, u64 Row = 0, typename V>
        static OC_FORCEINLINE void forwardDot(const block* in, const block* matrix, V& lo, V& hi)
        {
            if constexpr (Row < K)
            {
#ifdef OC_ENABLE_VPCLMUL
                using W = chosen_baa_detail::Wide;
                V l, h;
                W::product(W::broadcast(in[Row]), W::load(matrix + Row * (16 - K) + Col), l, h);
                lo = W::bxor(lo, l); hi = W::bxor(hi, h);
#else
                block l, h;
                in[Row].gf128Mul(matrix[Row * (16 - K) + Col], l, h);
                lo ^= l; hi ^= h;
#endif
                forwardDot<K, Col, Row + 1>(in, matrix, lo, hi);
            }
        }
        template<u64 K, u64 Col = 0>
        static OC_FORCEINLINE void localForward(const block* in, block* out, const block* matrix)
        {
            if constexpr (Col < 16 - K)
            {
#ifdef OC_ENABLE_VPCLMUL
                using W = chosen_baa_detail::Wide;
                auto lo = W::broadcast(ZeroBlock), hi = lo;
                forwardDot<K, Col>(in, matrix, lo, hi);
                W::store(out + K + Col, W::reduce(lo, hi));
                localForward<K, Col + W::lanes>(in, out, matrix);
#else
                block lo = ZeroBlock, hi = ZeroBlock;
                forwardDot<K, Col>(in, matrix, lo, hi);
                out[K + Col] = lo.gf128Reduce(hi);
                localForward<K, Col + 1>(in, out, matrix);
#endif
            }
        }
    };
}
