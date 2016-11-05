#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "Common/Defines.h"

namespace osuCrypto
{

    /// <summary>
    /// A class that performs read/write to a single bit.
    /// </summary>
    class BitReference
    {
        BitReference() = delete;

        u8* mByte;
        u8 mMask, mShift;
    public:

        BitReference(const BitReference& rhs)
            :mByte(rhs.mByte), mMask(rhs.mMask), mShift(rhs.mShift)
        {}

        BitReference(u8* byte, u8 shift)
            :mByte(byte), mMask(1 << shift), mShift(shift) {}

        BitReference(u8* byte, u8 mask, u8 shift)
            :mByte(byte), mMask(mask), mShift(shift) {}

        void operator=(const BitReference& rhs)
        {
            *this = (u8)rhs;
        }

        inline void operator=(u8 n) {

            //*mByte |= ((n | (~n + 1)) >> 7)  << mShift;
            if (n > 0)
            {
                *mByte |= mMask;
            }
            else
            {
                *mByte &= ~mMask;
            }
        }

        operator u8() const;
    };

    std::ostream& operator<<(std::ostream& out, const BitReference& bit);

    class BitIterator
    {

    public:

        u8* mByte;
        u8 mMask, mShift;

        BitIterator(u8* byte, u8 shift)
            :mByte(byte), mMask(1 << shift), mShift(shift) {}


        BitIterator(const BitIterator& cp)
            : mByte(cp.mByte)
            , mMask(cp.mMask)
            , mShift(cp.mShift)
        {}


        BitReference operator*()
        {
            return BitReference(mByte, mMask, mShift);
        }


        BitIterator& operator++()
        {
            // pre inc
            mByte += (mShift == 7) & 1;
            ++mShift &= 7;
            mMask = 1 << mShift;

            return *this;
        }


        BitIterator operator++(int)
        {
            // post int
            BitIterator ret(*this);


            mByte += (mShift == 7) & 1;
            ++mShift &= 7;
            mMask = 1 << mShift;


            return ret;
        }

        BitIterator operator+(i64 v)const
        {
            if (v < 0)
                throw std::runtime_error("not impl");

            BitIterator ret(*this);

            ret.mByte += (v / 8);
            ret.mShift += (v & 7);
            
            if (ret.mShift > 7)
                ++ret.mByte;
            
            ret.mShift &= 7;
            ret.mMask = 1 << mShift;

            return ret;
        }

        bool operator==(const BitIterator& cmp)
        {
            return mByte == cmp.mByte && mShift == cmp.mShift;
        }
    };
}