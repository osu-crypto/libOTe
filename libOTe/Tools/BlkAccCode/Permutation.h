#pragma once
#include <vector>
#include <numeric>
#include <algorithm>
#include <random>
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "Randomness.h"

namespace osuCrypto {


    /**
     * @brief Iterator adapter for permutation classes
     *
     * This iterator lets us use an iterator into a permutation as a way to write values
     * to output locations. It acts as a mapping from a sequential iterator to a permuted
     * output destination.
     *
     * @tparam Inner The type of the inner iterator that produces indices
     * @tparam T The type of elements being permuted
     */
    template<typename Inner, typename T>
    struct PermIterator
    {
        PermIterator(Inner in, T base)
            : mPermIter(std::move(in))
            , mBase(std::move(base))
        { }

        Inner mPermIter;
        T mBase;

        auto& operator*() { return *(mBase + *mPermIter); }
        auto& operator++() { ++mPermIter; return *this; }

        bool operator==(const PermIterator& other) const { return mPermIter == other.mPermIter; }
        bool operator!=(const PermIterator& other) const { return mPermIter != other.mPermIter; }
    };


    /**
     * @brief Basic vector-based permutation implementation
     *
     * Stores a full permutation as an explicit vector of indices.
     * Fast to generate and easy to understand but requires O(n) memory.
     */
    struct VectorPerm
    {
        AlignedUnVector<u32> mPerm;

        /**
         * @brief Initialize the permutation with n random elements
         *
         * @param n The size of the permutation
         * @param seed The seed for the random number generator
         */
        void init(u64 n, block seed = block(451324523, 2345234523)) {
            PRNG prng(seed);
            mPerm.resize(n);
            std::iota(mPerm.begin(), mPerm.end(), 0);
            std::shuffle(mPerm.begin(), mPerm.end(), prng);
        }


        /**
		 * @brief Get an iterator to the beginning of the permutation
         *
		 * @param out Pointer to the output location where permuted values will be written
         */
        template<typename T>
        PermIterator<u32*, T> begin(T* out) {
            return { mPerm.data(), out };
        }

        /**
         * @brief Get an iterator to the end of the permutation
         *
         * @return An iterator pointing past the last element of the permutation
		 */
        template<typename T>
        PermIterator<u32*, T> end() {
            return { mPerm.data() + mPerm.size(), nullptr};
        }
    };

    /**
     * @brief Identity permutation implementation
     *
     * Represents a trivial permutation where each index maps to itself.
     * Useful for cases where no permutation is needed.
	 */
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


    /**
     * @brief Feistel network-based permutation for power-of-2 sized domains
     *
     * Implements a permutation using a Feistel network, which is a cryptographic construction
     * that creates a bijective mapping. This is much more memory-efficient than storing
     * a full permutation table, requiring only O(1) memory.
     *
     * The size must be a power of 2.
     */
    class Feistel2KPerm {
    public:

        // Batch size for operations
        static constexpr u32 chunkSize = 8;

        u64 mN = 0;  // Size of the permutation
        std::vector<u32> mKeys;  // Round keys for the Feistel network
        std::vector<block> mBlkKeys;  // Block-aligned keys for SIMD operations

        // Bit manipulation fields
        u32 mLeftSideBits, mLeftSideMask, mRightSideBits, mRightSideMask;

        // Block-aligned masks for SIMD operations
		block mLMask, mRMask;

        Feistel2KPerm() = default;

        /**
         * @brief Construct a Feistel permutation with the given size and seed
         *
         * @param n Size of the permutation (must be a power of 2)
         * @param seed Random seed
         * @param numRounds Number of Feistel rounds (more rounds = better security)
         */
        Feistel2KPerm(u64 n, block seed = block(34123421, 2134123), u32 numRounds = 4)
        {
            init(n, seed, numRounds);
        }

        /**
         * @brief Initialize the Feistel permutation
         *
         * @param n Size of the permutation (must be a power of 2)
         * @param seed Random seed
         * @param numRounds Number of Feistel rounds
         */
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

        /**
         * @brief Apply the Feistel permutation to a single value
         *
         * Implements the core Feistel network operation for a single input value.
         * This is a bijection from [0,n) to [0,n).
         *
         * @param val The input value
         * @return The permuted value
         */
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

        /**
         * @brief Apply the Feistel permutation to a block of 4 values in parallel
         *
         * SIMD version of the Feistel network that processes 4 inputs at once.
         *
         * @param vals Block containing 4 input values
         * @return Block containing 4 permuted values
         */
        block feistelBijection(block vals) const 
        {
            block L = vals.srl_epi32(mRightSideBits);
            //block L = _mm_srli_epi32(vals, mRightSideBits);
            block R = vals & mRMask;

            for (u32 i = 0; i < mKeys.size(); i++)
            {
                if (i & 1)
                {
                    // F(k,x) = truncate(H(k + x) ^ x)
                    // L = L ^ F(k, R)
                    L ^= (xorshifthash(mBlkKeys[i].add_epi32(R)) ^ R) & mLMask;
                }
                else
                {
                    // F(k,x) = truncate(H(k + x) ^ x)
                    // R = R ^ F(k, L)
                    R ^= (xorshifthash(mBlkKeys[i].add_epi32(L)) ^ L) & mRMask;
                }
            }

            // Combine the left and right sides into a single value
            //return block(_mm_slli_epi32(L, mRightSideBits)) | R;
            return L.sll_epi32(mRightSideBits) | R;
        }


        /**
         * @brief Apply the permutation to data, moving from 'in' to 'out'
         *
         * @tparam T Element type
         * @param in Source data
         * @param out Destination buffer
         */
        template<typename T>
        void dualEncode(span<const T> in, span<T> out) const 
        {
            if (in.size() != mN) {
                throw std::invalid_argument("Data size must match the initialized size.");
            }
            if (out.size() != mN) {
                throw std::invalid_argument("Data size must match the initialized size.");
            }

            auto b = begin(out.data());
            for (u64 i = 0; i < mN; ++i) {
                *b = in[i];
                ++b;
            }
        }

        /**
         * @brief Iterator for the Feistel permutation
         *
         * Generates permuted indices on-the-fly rather than storing them.
         */
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
        auto begin(T data) const {
            return PermIterator<Iterator, T>(Iterator{ *this, 0 }, data);
        }
        //template<typename T>
        //auto begin() const {
        //    return PermIterator<Iterator, T>(Iterator{ *this, mN }, {});
        //}


		auto begin() const {
			return Iterator(*this, 0);
		}
        auto end() const {
            return Iterator(*this, mN);
        }

        /**
         * @brief Process a chunk of elements at once for better performance
         *
         * Optimized method to permute multiple values at once using SIMD operations.
         *
         * @tparam T Element type
         * @param out Output iterator
         * @param in Input data pointer
         */
        template<typename T>
        inline void chunk(PermIterator<Iterator, T>& out, auto in)
        {
            std::array<block, 2> idxs;
            //__m128i increment = _mm_set_epi32(3, 2, 1, 0);
            block increment(3, 2, 1, 0);
            auto idx = out.mPermIter.mIdx;
            idxs[0] = block::allSame<u32>(idx).add_epi32(increment);
            idxs[1] = block::allSame<u32>(idx + 4).add_epi32(increment);
            //idxs[0] = _mm_add_epi32(_mm_set1_epi32(idx), increment);
            //idxs[1] = _mm_add_epi32(_mm_set1_epi32(idx + 4), increment);

            idxs[0] = feistelBijection(idxs[0]);
            idxs[1] = feistelBijection(idxs[1]);

            for (u64 i = 0; i < 2; ++i)
            {
                for (u64 j = 0; j < 4; ++j)
                {
					auto d = idxs[i].get<u32>(j);
                    assert(d < mN);
                    out.mBase[d] = *in;
					++in;
                }
            }

            out.mPermIter.mIdx += chunkSize;
        }

    };

    /**
     * @brief Feistel network-based permutation for domains of any size
     *
     * Extends the power-of-2 Feistel permutation to work with any domain size.
     * This is done by using a Feistel network on a power-of-2 sized domain,
     * and rejecting outputs that are outside the desired range.
     */
    class FeistelPerm {
    public:
        static constexpr u32 chunkSize = 8;
        static constexpr u32 bufferSize = 128; // Size of the buffer for precomputed values

        u64 mN = 0;                // Original domain size
        u64 mPow2N = 0;            // Next power of 2 domain size
        Feistel2KPerm mFeistel;    // The underlying power-of-2 Feistel permutation

        // Buffer for precomputed valid indices
        AlignedUnVector<u32> mBuffer;
        u32 mBufferPos = 0;        // Current position in the buffer
        u32 mBufferSize = 0;       // Number of valid indices in the buffer
        u32 mNextIdx = 0;          // Next index to try in the power-of-2 domain

        FeistelPerm() = default;

        /**
         * @brief Construct a Feistel permutation for any domain size
         *
         * @param n Size of the permutation (can be any positive integer)
         * @param seed Random seed
         * @param numRounds Number of Feistel rounds
         */
        FeistelPerm(u64 n, block seed = block(34123421, 2134123), u32 numRounds = 4)
        {
            init(n, seed, numRounds);
        }

        /**
         * @brief Initialize the permutation for any domain size
         *
         * @param n Size of the permutation
         * @param seed Random seed
         * @param numRounds Number of Feistel rounds
         */
        void init(u64 n, block seed = block(34123421, 2134123), u32 numRounds = 4)
        {
            mN = n;
            // Calculate the next power of 2 that's >= n
            mPow2N = 1ull << log2ceil(n);

            // Initialize the Feistel permutation for the power-of-2 domain
            mFeistel.init(mPow2N, seed, numRounds);

            // Initialize the buffer
            mBuffer.resize(bufferSize);
            mBufferPos = 0;
            mBufferSize = 0;
            mNextIdx = 0;

            // Prefill the buffer
            fillBuffer();
        }

        /**
         * @brief Fill the buffer with valid indices (those < mN) using block operations
         *
         * This function computes permuted indices in batches using SIMD operations,
         * and keeps only those that are within the target domain.
         */
        void fillBuffer()
        {
            mBufferSize = 0;
            mBufferPos = 0;

            // Process in blocks of 4 for better efficiency
            block increment = std::array<u32, 4>{ 0,1,2,3 };

            while (mBufferSize < mBuffer.size() && mNextIdx < mPow2N)
            {
                // Calculate how many indices we can process at once
                u64 remainingSpace = std::min<u64>(mBuffer.size() - mBufferSize, (mPow2N - mNextIdx));
                u64 blockCount = std::min<u64>(remainingSpace, static_cast<u64>(4));

                if (blockCount == 0)
                    break;

                if (blockCount == 4) {
                    // Process 4 values at once using block operations
                    block idxBlock = block::allSame<u32>(mNextIdx).add_epi32(increment);
                    block permBlock = mFeistel.feistelBijection(idxBlock);

                    // Extract individual values and check if they're within the domain
                    for (u64 j = 0; j < 4; ++j)
                    {
                        u32 permIdx = permBlock.get<u32>(j);
                        if (permIdx < mN)
                        {
                            mBuffer[mBufferSize++] = permIdx;
                        }
                    }

                    mNextIdx += 4;
                }
                else {
                    // For the last few indices, process them individually
                    for (u64 i = 0; i < blockCount; ++i)
                    {
                        u32 permIdx = mFeistel.feistelBijection(mNextIdx);
                        mNextIdx++;

                        if (permIdx < mN)
                        {
                            mBuffer[mBufferSize++] = permIdx;
                        }
                    }
                }
            }
        }

        /**
         * @brief Get the current permuted index from the buffer
         *
         * @return The permuted index
         */
        u32 get() const
        {
            return mBuffer[mBufferPos];
        }

        /**
         * @brief Move to the next permuted index
         *
         * Advances to the next index in the buffer, refilling if necessary.
         */
        void increment()
        {
            ++mBufferPos;

            // If buffer is empty or we've used all buffered indices, refill it
            if (mBufferPos >= mBufferSize)
                fillBuffer();
        }

        /**
         * @brief Iterator for the FeistelPerm
         *
         * Uses the buffered approach to generate permuted indices efficiently.
         */
        struct Iterator
        {
            FeistelPerm& mFeistelPerm;
            u64 mIdx = 0;

            Iterator(FeistelPerm& feistelPerm, u64 index)
                : mFeistelPerm(feistelPerm)
                , mIdx(index)
            {
            }

            u32 operator*() const
            {
                // For the beginning iterator, we return values from the buffer
                return mFeistelPerm.get();
            }

            auto& operator++()
            {
                mFeistelPerm.increment();
                return *this;
            }

            bool operator==(const Iterator& other) const { return mIdx == other.mIdx; }
            bool operator!=(const Iterator& other) const { return mIdx != other.mIdx; }
        };

        template<typename T>
        auto begin(T data) {
            // Reset buffer state when starting a new iteration
            mBufferPos = mBufferSize = 0;
            mNextIdx = 0;
            fillBuffer();
            return PermIterator<Iterator, T>(Iterator{ *this, 0 }, data);
        }

        auto begin() {
            // Reset buffer state when starting a new iteration
            mBufferPos = mBufferSize = 0;
            mNextIdx = 0;
            fillBuffer();
            return Iterator(*this, 0);
        }

        auto end() {
            return Iterator(*this, mN);
        }

        /**
         * @brief Apply the permutation to data, moving from 'in' to 'out'
         *
         * @tparam T Element type
         * @param in Source data
         * @param out Destination buffer
         */
        template<typename T>
        void dualEncode(span<const T> in, span<T> out)
        {
            if (in.size() != mN) {
                throw std::invalid_argument("Data size must match the initialized size.");
            }
            if (out.size() != mN) {
                throw std::invalid_argument("Data size must match the initialized size.");
            }

            auto b = begin(out.data());
            for (u64 i = 0; i < mN; ++i) {
                *b = in[i];
                ++b;
            }
        }

        /**
         * @brief Process a chunk of elements at once for better performance
         *
         * Unlike Feistel2KPerm's chunk method, this version works with arbitrary
         * domain sizes by using the buffered approach.
         *
         * @tparam T Element type
         * @param out Output iterator
         * @param in Input data pointer
         */
        template<typename T>
        inline void chunk(PermIterator<Iterator, T>& out, auto in)
        {
            // Calculate how many elements to process (up to chunkSize)
            u32 remainingElements = std::min<u32>(chunkSize, static_cast<u32>(mN - out.mPermIter.mIdx));

            for (u32 i = 0; i < remainingElements; ++i)
            {
                *out = *in;
                ++out;
                ++in;
            }
        }

    };

}