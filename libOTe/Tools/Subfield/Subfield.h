#include "libOTe/Vole/Noisy/NoisyVoleSender.h"
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/BitVector.h"

namespace osuCrypto::Subfield {

    struct F128 {
        block b;
        F128() = default;
        explicit F128(const block& b) : b(b) {}
//        OC_FORCEINLINE F128 operator+(const F128& rhs) const {
//            F128 ret;
//            ret.b = b ^ rhs.b;
//            return ret;
//        }
//        OC_FORCEINLINE F128 operator-(const F128& rhs) const {
//            F128 ret;
//            ret.b = b ^ rhs.b;
//            return ret;
//        }
//        OC_FORCEINLINE F128 operator*(const F128& rhs) const {
//            F128 ret;
//            ret.b = b.gf128Mul(rhs.b);
//            return ret;
//        }
//        OC_FORCEINLINE bool operator==(const F128& rhs) const {
//            return b == rhs.b;
//        }
//        OC_FORCEINLINE bool operator!=(const F128& rhs) const {
//            return b != rhs.b;
//        }
    };

    /*
     * Primitive TypeTrait for integers
     */
    template<typename T>
    struct TypeTraitPrimitive {
        using G = T;
        using F = T;

        static constexpr size_t bitsG = sizeof(G) * 8;
        static constexpr size_t bitsF = sizeof(F) * 8;
        static constexpr size_t bytesG = sizeof(G);
        static constexpr size_t bytesF = sizeof(F);

        static OC_FORCEINLINE F plus(const F& lhs, const F& rhs) {
            return lhs + rhs;
        }
        static OC_FORCEINLINE F minus(const F& lhs, const F& rhs) {
            return lhs - rhs;
        }
        static OC_FORCEINLINE F mul(const F& lhs, const F& rhs) {
            return lhs * rhs;
        }
        static OC_FORCEINLINE bool eq(const F& lhs, const F& rhs) {
            return lhs == rhs;
        }

        static OC_FORCEINLINE BitVector BitVectorF(F& x) {
            return {(u8*)&x, bitsF};
        }

        static OC_FORCEINLINE F fromBlock(const block& b) {
            return b.get<F>()[0];
        }
        static OC_FORCEINLINE F pow(u64 power) {
            F ret = 1;
            ret <<= power;
            return ret;
        }
    };

    using TypeTrait64 = TypeTraitPrimitive<u64>;

    /*
     * TypeTrait for GF(2^128)
     */
    struct TypeTraitF128 {
        using G = block;
        using F = block;

        static constexpr size_t bitsG = sizeof(G) * 8;
        static constexpr size_t bitsF = sizeof(F) * 8;
        static constexpr size_t bytesG = sizeof(G);
        static constexpr size_t bytesF = sizeof(F);

        static OC_FORCEINLINE F plus(const F& lhs, const F& rhs) {
            return lhs ^ rhs;
        }
        static OC_FORCEINLINE F minus(const F& lhs, const F& rhs) {
            return lhs ^ rhs;
        }
        static OC_FORCEINLINE F mul(const F& lhs, const F& rhs) {
            return lhs.gf128Mul(rhs);
        }
        static OC_FORCEINLINE bool eq(const F& lhs, const F& rhs) {
            return lhs == rhs;
        }

        static OC_FORCEINLINE BitVector BitVectorF(F& x) {
            return {(u8*)&x, bitsF};
        }

        static OC_FORCEINLINE F fromBlock(const block& b) {
            return b;
        }
        static OC_FORCEINLINE F pow(u64 power) {
            F ret = ZeroBlock;
            *BitIterator((u8*)&ret, power) = 1;
            return ret;
        }
    };

    // array
    template<typename T, size_t N>
    struct Vec {
        std::array<T, N> v;
        OC_FORCEINLINE Vec operator+(const Vec& rhs) const {
            Vec ret;
            for (u64 i = 0; i < N; ++i) {
                ret.v[i] = v[i] + rhs.v[i];
            }
            return ret;
        }
        OC_FORCEINLINE Vec operator-(const Vec& rhs) const {
            Vec ret;
            for (u64 i = 0; i < N; ++i) {
                ret.v[i] = v[i] - rhs.v[i];
            }
            return ret;
        }
        OC_FORCEINLINE Vec operator*(const T& rhs) const {
            Vec ret;
            for (u64 i = 0; i < N; ++i) {
                ret.v[i] = v[i] * rhs;
            }
            return ret;
        }
        OC_FORCEINLINE T operator[](u64 idx) const {
            return v[idx];
        }
        OC_FORCEINLINE T& operator[](u64 idx) {
            return v[idx];
        }
        OC_FORCEINLINE bool operator==(const Vec& rhs) const {
            for (u64 i = 0; i < N; ++i) {
                if (v[i] != rhs.v[i]) return false;
            }
            return true;
        }
        OC_FORCEINLINE bool operator!=(const Vec& rhs) const {
            return !(*this == rhs);
        }
    };

    // TypeTraitVec for array of integers
    template<typename T, size_t N>
    struct TypeTraitVec {
        using G = T;
        using F = Vec<T, N>;

        static constexpr size_t bitsG = sizeof(G) * 8;
        static constexpr size_t bitsF = sizeof(F) * 8;
        static constexpr size_t bytesG = sizeof(G);
        static constexpr size_t bytesF = sizeof(F);

        static constexpr size_t sizeBlocks = (bytesF + sizeof(block) - 1) / sizeof(block);
        static constexpr size_t size = N;

        static OC_FORCEINLINE F plus(const F& lhs, const F& rhs) {
            F ret;
            for (u64 i = 0; i < N; ++i) {
                ret.v[i] = lhs.v[i] + rhs.v[i];
            }
            return ret;
        }
        static OC_FORCEINLINE F minus(const F& lhs, const F& rhs) {
            F ret;
            for (u64 i = 0; i < N; ++i) {
                ret.v[i] = lhs.v[i] - rhs.v[i];
            }
            return ret;
        }
        static OC_FORCEINLINE F mul(const F& lhs, const G& rhs) {
            F ret;
            for (u64 i = 0; i < N; ++i) {
                ret.v[i] = lhs.v[i] * rhs;
            }
            return ret;
        }
        static OC_FORCEINLINE bool eq(const F& lhs, const F& rhs) {
            for (u64 i = 0; i < N; ++i) {
                if (lhs.v[i] != rhs.v[i]) return false;
            }
            return true;
        }
        static OC_FORCEINLINE G plus(const G& lhs, const G& rhs) {
            return lhs + rhs;
        }

        static OC_FORCEINLINE BitVector BitVectorF(F& x) {
            return {(u8*)&x, bitsF};
        }

        static OC_FORCEINLINE F fromBlock(const block& b) {
            F ret;
            if (N * sizeof(T) <= sizeof(block)) {
                memcpy(ret.v.data(), &b, bytesF);
                return ret;
            }
            else {
                std::array<block, sizeBlocks> buf;
                for (u64 i = 0; i < sizeBlocks; ++i) {
                    buf[i] = b + block(i, i);
                }
                mAesFixedKey.hashBlocks<sizeBlocks>(buf.data(), buf.data());
                memcpy(&ret, &buf, sizeof(F));
                return ret;
            }
        }

        static OC_FORCEINLINE F pow(u64 power) {
            F ret;
            memset(&ret, 0, sizeof(ret));
            *BitIterator((u8*)&ret, power) = 1;
            return ret;
        }
    };

}
