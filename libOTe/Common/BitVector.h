#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 

#include "Common/Defines.h"
#include "Network/Channel.h"
#include "Crypto/PRNG.h"
#include "Common/BitIterator.h"
#include "Common/ArrayView.h"
namespace osuCrypto {


    //class PRNG;

    class BitVector : public ChannelBuffer
    {

        u8* mData;
        u64 mNumBits, mAllocBytes;

    public:

        BitVector()
            :mData(nullptr),
            mNumBits(0),
            mAllocBytes(0)
        {}

        BitVector(u8* data, u64 length);

        
        BitVector(std::string data);

        explicit BitVector(size_t n)
            :mData(nullptr),
            mNumBits(0),
            mAllocBytes(0)
        {
            reset(n);
        }

        BitVector(const BitVector& K)
            :mData(nullptr),
            mNumBits(0),
            mAllocBytes(0)
        {
            assign(K);
        }

        BitVector(BitVector&& rref);

        ~BitVector() { delete[] mData; }

         

        void assign(const block& b);
        void assign(const BitVector& K); 

        void append(u8* data, u64 length, u64 offset = 0);
        void append(const BitVector& k) { append(k.data(), k.size()); }

        // erases original contents
        void reset(size_t new_nbits = 0);
        void resize(u64 newSize);
        void reserve(u64 bits);

        void copy(const BitVector& src, u64 idx, u64 length);

        u64 capacity() const { return mAllocBytes * 8; }
        u64 size() const { return mNumBits; }
        u64 sizeBytes() const { return (mNumBits + 7) / 8; }
        u8* data() const { return mData; }

        BitVector& operator=(const BitVector& K);
        BitReference operator[](const u64 idx) const;
        BitVector operator^(const BitVector& B)const;
        BitVector operator&(const BitVector& B)const;
        BitVector operator|(const BitVector& B)const;
        BitVector operator~()const;
        void operator^=(const BitVector& A);
        void operator&=(const BitVector& A);
        void operator|=(const BitVector& A);
        bool operator==(const BitVector& k) { return equals(k); }
        bool operator!=(const BitVector& k)const { return !equals(k); }

        bool equals(const BitVector& K) const;
         
        void fromString(std::string data);


        BitIterator begin() const;
        BitIterator end() const;
        void nChoosek(u64 n, u64 k, PRNG& prng);
        u64 hammingWeight() const;

        void pushBack(u8 bit);
        inline BitReference back() { return (*this)[size() - 1]; }

        void randomize(PRNG& G); 
        u8 parity();  

        std::string hex()const;



        template<class T>
        ArrayView<T> getArrayView() const;

    protected:
        u8* ChannelBufferData() const override { return mData; }
        u64 ChannelBufferSize() const override { return sizeBytes(); };
        void ChannelBufferResize(u64 len) override
        {
            if (sizeBytes() != len)
                throw std::invalid_argument("asdsdasfaf ;) "); 
        }


    };

    template<class T>
    inline ArrayView<T> BitVector::getArrayView() const
    {
        return ArrayView<T>((T*)mData, (T*)mData + (sizeBytes() / sizeof(T)), false);
    }

    std::ostream& operator<<(std::ostream& in, const BitVector& val);
}