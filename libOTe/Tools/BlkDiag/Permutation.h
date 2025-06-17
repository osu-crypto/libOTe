#include <vector>
#include <numeric>
#include <algorithm>
#include <random>
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "Randomness.h"

namespace osuCrypto {

    template<typename Inner, typename T>
    struct PermIterator
    {
        Inner mPermIter;
        T* mBase = nullptr;

        auto& operator*() { return mBase[*mPermIter]; }
        auto& operator++() { ++mPermIter; return *this; }

        bool operator==(const PermIterator& other) const { return mPermIter == other.mPermIter; }
        bool operator!=(const PermIterator& other) const { return mPermIter != other.mPermIter; }
    };


    struct VectorPerm
    {
        AlignedUnVector<u32> mPerm;

        void init(u64 n, block seed = block(451324523, 2345234523)) {
            PRNG prng(seed);
            mPerm.resize(n);
            std::iota(mPerm.begin(), mPerm.end(), 0);
            std::shuffle(mPerm.begin(), mPerm.end(), prng);
        }

        template<typename T>
        PermIterator<u32*, T> begin(T* out) {
            return { mPerm.data(), out };
        }

        template<typename T>
        PermIterator<u32*, T> end() {
            return { mPerm.data() + mPerm.size(), nullptr};
        }
    };

    struct IdentityPerm
    {
        u64 mN = 0;
        IdentityPerm() = default;
        IdentityPerm(u64 n) : mN(n) {}

		void init(u64 n) {
			mN = n;
		}

        struct Inner
        {
            u32 mIdx = 0;
			u32 operator*() { return mIdx; }
			auto& operator++() { ++mIdx; return *this; }
			bool operator==(const Inner& other) const { return mIdx == other.mIdx; }
			bool operator!=(const Inner& other) const { return mIdx != other.mIdx; }
		};

        template<typename T>
        PermIterator<Inner, T> begin(T* out) {
            return { 0, out };
        }
        template<typename T>
        PermIterator<Inner, T> end() {
            return { nullptr, mN };
        }
    };

    // the size must be a power of 2.
    class Feistel2KPerm {
    public:

        static constexpr u32 chunkSize = 8;

        u64 mN = 0;
        std::vector<u32> mKeys;
        std::vector<block> mBlkKeys;

        u32 mLeftSideBits, mLeftSideMask, mRightSideBits, mRightSideMask;

		block mLMask, mRMask;

        Feistel2KPerm() = default;

        Feistel2KPerm(u64 n, block seed = block(34123421, 2134123), u32 numRounds = 4)
        {
            init(n, seed, numRounds);
        }
        void init(u64 n, block seed = block(34123421, 2134123), u32 numRounds = 4)
        {
            mN = n;
            auto totalBits = log2ceil(n);
            if (log2ceil(n) != log2floor(n))
                throw RTE_LOC;

            mLeftSideBits = totalBits / 2;
            mLeftSideMask = (1ull << mLeftSideBits) - 1;
            mRightSideBits = totalBits - mLeftSideBits;
            mRightSideMask = (1ull << mRightSideBits) - 1;

            mLMask = block::allSame(mLeftSideMask);
            mRMask = block::allSame(mRightSideMask);

            PRNG prng(seed);
            mKeys.resize(numRounds);
            mBlkKeys.resize(numRounds);
            for (u64 i = 0; i < numRounds; ++i) {
                mKeys[i] = prng.get();
                mBlkKeys[i] = block::allSame<u32>(mKeys[i]);
            }
        }


        u32 feistelBijection(const u32 val) const {

            u32 L = static_cast<u32>(val >> mRightSideBits);
            u32 R = static_cast<u32>(val & mRightSideMask);

            for (u32 i = 0; i < mKeys.size(); i++)
            {
                if (i & 1)
                {
                    // F(k,x) = truncate(H(k + x) ^ x)
                    // L = L ^ F(k, R)
					L ^= (xorshifthash(mKeys[i] + R) ^ R) & mLeftSideMask;
                }
                else
                {
					// F(k,x) = truncate(H(k + x) ^ x)
					// R = R ^ F(k, L)
					R ^= (xorshifthash(mKeys[i] + L) ^ L) & mRightSideMask;
                }
            }

            // Combine the left and right sides into a single value
            return L << mRightSideBits | R;
        }


        block feistelBijection(block vals) const 
        {
            block L = _mm_srli_epi32(vals, mRightSideBits);
            block R = vals & mRMask;

            for (u32 i = 0; i < mKeys.size(); i++)
            {
                if (i & 1)
                {
                    // F(k,x) = truncate(H(k + x) ^ x)
                    // L = L ^ F(k, R)
                    L ^= (xorshifthash(mBlkKeys[i] + R) ^ R) & mLMask;
                }
                else
                {
                    // F(k,x) = truncate(H(k + x) ^ x)
                    // R = R ^ F(k, L)
                    R ^= (xorshifthash(mBlkKeys[i] + L) ^ L) & mRMask;
                }
            }

            // Combine the left and right sides into a single value
            return block(_mm_slli_epi32(L, mRightSideBits)) | R;
        }



        template<typename T>
        void invoke(span<const T> in, span<T> out) const 
        {
            if (in.size() != mN) {
                throw std::invalid_argument("Data size must match the initialized size.");
            }
            if (out.size() != mN) {
                throw std::invalid_argument("Data size must match the initialized size.");
            }

            auto b = begin(out.data());
            for (u64 i = 0; i < mN; ++i) {
                *b++ = in[i];
            }
        }

        struct Iterator 
        {
            const Feistel2KPerm& mFeistel;
            u32 mIdx = 0;
            Iterator(const Feistel2KPerm& feistel, u64 index)
                : mFeistel(feistel)
                , mIdx(index)
            {
            }

            u32 operator*()
            {
                return mFeistel.feistelBijection(mIdx);
            }
            auto& operator++()
            {
                ++mIdx;
                return *this;
            }

			bool operator==(const Iterator& other) const { return mIdx == other.mIdx; }
            bool operator!=(const Iterator& other) const { return mIdx != other.mIdx; }
        };

        template<typename T>
        auto begin(T* data) const {
            return PermIterator<Iterator, T>(Iterator{ *this, 0 }, data);
        }
        template<typename T>
        auto begin() const {
            return PermIterator<Iterator, T>(Iterator{ *this, mN }, nullptr);
        }


		auto begin() const {
			return Iterator(*this, 0);
		}
        auto end() const {
            return Iterator(*this, mN);
        }


        template<typename T>
        inline void chunk(PermIterator<Iterator, T>& out, T* in)
        {
            std::array<block, 2> idxs;
            __m128i increment = _mm_set_epi32(3, 2, 1, 0);
            auto idx = out.mPermIter.mIdx;
            idxs[0] = _mm_add_epi32(_mm_set1_epi32(idx), increment);
            idxs[1] = _mm_add_epi32(_mm_set1_epi32(idx + 4), increment);

            idxs[0] = feistelBijection(idxs[0]);
            idxs[1] = feistelBijection(idxs[1]);

            for (u64 i = 0; i < 2; ++i)
            {
                for (u64 j = 0; j < 4; ++j)
                {
					auto d = idxs[i].get<u32>(j);
                    assert(d < mN);
                    out.mBase[d] = *in++;
                }
            }

            out.mPermIter.mIdx += chunkSize;
        }
    };

}