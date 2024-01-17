#pragma once
#include "libOTe/Vole/Noisy/NoisyVoleSender.h"
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/BitVector.h"

namespace osuCrypto {

    /*
     * Primitive CoeffCtx for integers-like types
     */
    struct CoeffCtxInteger
    {

        template<typename R, typename F1, typename F2>
        static OC_FORCEINLINE void plus(R&& ret, F1&& lhs, F2&& rhs) {
            ret = lhs + rhs;
        }

        template<typename R, typename F1, typename F2>
        static OC_FORCEINLINE void minus(R&& ret, F1&& lhs, F2&& rhs) {
            ret = lhs - rhs;
        }
        template<typename R, typename F1, typename F2>
        static OC_FORCEINLINE void mul(R&& ret, F1&& lhs, F2&& rhs) {
            ret = lhs * rhs;
        }

        template<typename F>
        static OC_FORCEINLINE bool eq(F&& lhs, F&& rhs) {
            return lhs == rhs;
        }


        // the bit size require to prepresent F
        // the protocol will perform binary decomposition
        // of F using this many bits
        template<typename F>
        static u64 bitSize()
        {
            return sizeof(F) * 8;
        }


        template<typename F>
        static OC_FORCEINLINE BitVector binaryDecomposition(F& x) {
            static_assert(std::is_trivially_copyable<F>::value, "memcpy is used so must be trivially_copyable.");
            return { (u8*)&x, sizeof(F) * 8 };
        }

        template<typename F>
        static OC_FORCEINLINE void fromBlock(F& ret, const block& b) {
            static_assert(std::is_trivially_copyable<F>::value, "memcpy is used so must be trivially_copyable.");

            if constexpr (sizeof(F) <= sizeof(block))
            {
                memcpy(&ret, &b, sizeof(F));
            }
            else
            {
                auto constexpr size = (sizeof(F) + sizeof(block) - 1) / sizeof(block);
                std::array<block, size> buffer;
                mAesFixedKey.ecbEncCounterMode(b, buffer);
                memcpy(&ret, buffer.data(), sizeof(ret));
            }
        }

        template<typename F>
        static OC_FORCEINLINE void pow(F& ret, u64 power) {
            static_assert(std::is_trivially_copyable<F>::value, "memcpy is used so must be trivially_copyable.");
            memset(&ret, 0, sizeof(F));
            *BitIterator((u8*)&ret, power) = 1;
        }


        template<typename F>
        static OC_FORCEINLINE void copy(F& dst, const F& src)
        {
            dst = src;
        }

        template<typename SrcIter, typename DstIter>
        static OC_FORCEINLINE void copy(
            SrcIter begin,
            SrcIter end,
            DstIter dstBegin)
        {
            using F1 = std::remove_reference_t<decltype(*begin)>;
            using F2 = std::remove_reference_t<decltype(*dstBegin)>;
            static_assert(std::is_trivially_copyable<F1>::value, "memcpy is used so must be trivially_copyable.");
            static_assert(std::is_same_v<F1, F2>, "src and destication types are not the same.");

            std::copy(begin, end, dstBegin);
        }

        // must have 
        // .size()
        // operator[] that returns the element.
        // begin() iterator
        // end() iterator
        template<typename F>
        using Vec = AlignedUnVector<F>;

        // the size of F when serialized.
        template<typename F>
        static u64 byteSize()
        {
            return sizeof(F);
        }


        // deserialize buff into dst
        template<typename F>
        static void deserialize(Vec<F>& dst, span<u8> buff)
        {
            if (dst.size() * sizeof(F) != buff.size())
            {
                std::cout << "bad buffer size " << LOCATION << std::endl;
                std::terminate();
            }
            static_assert(std::is_trivially_copyable<F>::value, "memcpy is used so must be trivially_copyable.");
            memcpy(dst.data(), buff.data(), buff.size());
        }

        // serial buff into dst
        template<typename F>
        static void serialize(span<u8> dst, Vec<F>& buff)
        {
            if (buff.size() * sizeof(F) != dst.size())
            {
                std::cout << "bad buffer size " << LOCATION << std::endl;
                std::terminate();
            }
            static_assert(std::is_trivially_copyable<F>::value, "memcpy is used so must be trivially_copyable.");
            memcpy(dst.data(), buff.data(), dst.size());
        }

        template<typename Iter>
        static void zero(Iter begin, Iter end)
        {
            using F = std::remove_reference_t<decltype(*begin)>;
            static_assert(std::is_trivially_copyable<F>::value, "memcpy is used so must be trivially_copyable.");

            if (begin != end)
            {
                auto n = std::distance(begin, end);
                assert(n > 0);
                memset(&*begin, 0, n * sizeof(F));
            }
        }

        template<typename Iter>
        static void one(Iter begin, Iter end)
        {
            std::fill(begin, end, 1);
        }

        // resize Vec
        template<typename FVec>
        static void resize(FVec&& f, u64 size)
        {
            f.resize(size);
        }
    };

    // CoeffCtx for GF fields. 
    // ^ operator is used for addition.
    struct CoeffCtxGF : CoeffCtxInteger
    {

        template<typename F>
        static OC_FORCEINLINE void plus(F& ret, const F& lhs, const F& rhs) {
            ret = lhs ^ rhs;
        }
        template<typename F>
        static OC_FORCEINLINE void minus(F& ret, const F& lhs, const F& rhs) {
            ret = lhs ^ rhs;
        }
    };

    // block does not use operator*
    struct CoeffCtxGFBlock : CoeffCtxGF
    {
        static OC_FORCEINLINE void mul(block& ret, const block& lhs, const block& rhs) {
            ret = lhs.gf128Mul(rhs);
        }
    };


    template<typename G, u64 N>
    struct CoeffCtxArray : CoeffCtxInteger
    {
        using F = std::array<G, N>;

        static OC_FORCEINLINE void plus(F& ret, const F& lhs, const F& rhs) {
            for (u64 i = 0; i < lhs.size(); ++i) {
                ret[i] = lhs[i] + rhs[i];
            }
        }

        static OC_FORCEINLINE void plus(G& ret, const  G& lhs, const G& rhs) {
            ret = lhs + rhs;
        }

        static OC_FORCEINLINE void minus(F& ret, const F& lhs, const F& rhs)
        {
            for (u64 i = 0; i < lhs.size(); ++i) {
                ret[i] = lhs[i] - rhs[i];
            }
        }

        static OC_FORCEINLINE void minus(G& ret, const G& lhs, const G& rhs) {
            ret = lhs - rhs;
        }

        static OC_FORCEINLINE void mul(F& ret, const F& lhs, const G& rhs)
        {
            for (u64 i = 0; i < lhs.size(); ++i) {
                ret[i] = lhs[i] * rhs;
            }
        }

        static OC_FORCEINLINE bool eq(const F& lhs, const F& rhs)
        {
            for (u64 i = 0; i < lhs.size(); ++i) {
                if (lhs[i] != rhs[i])
                    return false;
            }
            return true;
        }

        static OC_FORCEINLINE bool eq(const G& lhs, const G& rhs)
        {
            return lhs == rhs;
        }
    };

    template<typename F, typename G = F>
    struct DefaultCoeffCtx : CoeffCtxInteger {
    };

    // GF128 vole
    template<> struct DefaultCoeffCtx<block, block> : CoeffCtxGFBlock {};

    // OT
    template<> struct DefaultCoeffCtx<block, bool> : CoeffCtxGFBlock {};
}
