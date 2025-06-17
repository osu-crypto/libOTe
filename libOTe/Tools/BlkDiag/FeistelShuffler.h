#pragma once
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <random>
#include <ctime>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
namespace osuCrypto
{

    class FeistelShuffler {
    public:

        u64 mSize;
        u64 mRounds;
        std::vector<u32> mKeys;

        u64 mLeftSideBits, mLeftSideMask, mRightSideBits, mRightSideMask;

        void initializeFeistelParams() {
            u64 totalBits = 0;
            u64 temp = mSize - 1;
            while (temp) {
                totalBits++;
                temp >>= 1;
            }

            mLeftSideBits = totalBits / 2;
            mLeftSideMask = (1ull << mLeftSideBits) - 1;
            mRightSideBits = totalBits - mLeftSideBits;
            mRightSideMask = (1ull << mRightSideBits) - 1;
        }


        u64 feistelBijection(const u64 val) const {
            u32 state[2] = {
                static_cast<u32>(val >> mRightSideBits),  // Left side
                static_cast<u32>(val & mRightSideMask)   // Right side
            };

            constexpr u64 M0 = 0xD2B74407B1CE6E93;
            for (u32 i = 0; i < mRounds; i++) {


                // Perform 64-bit multiplication and extract high and low 32 bits
                u64 product = static_cast<u64>(M0) * state[0];
                u32 hi = static_cast<u32>(product >> 32);
                u32 lo = static_cast<u32>(product);

                // Update the state
                lo = (lo << (mRightSideBits - mLeftSideBits)) | (state[1] >> mLeftSideBits);
                state[0] = ((hi ^ mKeys[i]) ^ state[1]) & static_cast<u32>(mLeftSideMask);
                state[1] = lo & static_cast<u32>(mRightSideMask);
            }

            // Combine the left and right sides into a single value
            return (static_cast<u64>(state[0]) << mRightSideBits) | static_cast<u64>(state[1]);
        }


        FeistelShuffler(u64 size_, u32 numRounds_ = 24)
            : mSize(size_), mRounds(numRounds_) {
            if (mSize == 0 || (mSize & (mSize - 1)) != 0) {
                throw std::invalid_argument("Size must be a power of 2 and greater than 0.");
            }

            initializeFeistelParams();

            // TODO: Use PRNG instead of std::mt19937
            std::mt19937 rng(static_cast<unsigned int>(time(0)));
            mKeys.resize(mRounds);
            for (u32& key : mKeys) {
                key = rng();
            }
        }

        void shuffle(std::vector<u64>& data) const {
            if (data.size() != mSize) {
                throw std::invalid_argument("Data size must match the initialized size.");
            }

            std::vector<u64> result(mSize);
            for (u64 i = 0; i < mSize; ++i) {
                u64 permutedIdx = feistelBijection(i);
                result[permutedIdx] = data[i];
            }

            data = std::move(result);
        }

        class Iterator {
        private:
            const FeistelShuffler& shuffler;
            u64 currentIndex;

        public:
            Iterator(const FeistelShuffler& shuffler_)
                : shuffler(shuffler_), currentIndex(0) {}

            u64 next() {
                if (currentIndex >= shuffler.mSize) {
                    throw std::out_of_range("Iterator has reached the end.");
                }
                return shuffler.feistelBijection(currentIndex++);
            }

            bool hasNext() const {
                return currentIndex < shuffler.mSize;
            }
        };

        Iterator getIterator() const {
            return Iterator(*this);
        }
    };


}