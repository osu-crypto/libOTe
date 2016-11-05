#include <string.h>

#include "Common/ByteStream.h" 
#include <sstream>
#include "Crypto/Commit.h"

namespace osuCrypto {

    ByteStream::ByteStream(u64 maxlen)
    {
        mCapacity = maxlen; mPutHead = maxlen; mGetHead = 0;
        mData = mCapacity ? new u8[mCapacity]() : nullptr;
    }


    ByteStream::ByteStream(const ByteStream& os)
    {
        mCapacity = os.mCapacity;
        mPutHead = os.mPutHead;
        mData = new u8[mCapacity]();
        memcpy(mData, os.mData, mPutHead*sizeof(u8));
        mGetHead = os.mGetHead;
    }

    ByteStream::ByteStream(const u8 * data, u64 length)
        :mPutHead(0),
        mCapacity(0),
        mGetHead(0),
        mData(nullptr)
    {
        append(data, length);
    }

    void ByteStream::reserve(u64 l)
    {
        if (l > mCapacity) {
            u8* nd = new u8[l]();
            memcpy(nd, mData, mPutHead*sizeof(u8));
    
            if(mData)
                delete[] mData;
            
            mData = nd;
            mCapacity = l;
        }
    }

    void ByteStream::resize(u64 size)
    {
        reserve(size);
        setp(size);
    }

    void ByteStream::setg(u64 loc) {
        if (loc > mPutHead) throw std::runtime_error("rt error at " LOCATION);
        mGetHead = loc;
    }

    void ByteStream::setp(u64 loc)
    {
        if (loc > mCapacity) throw std::runtime_error("rt error at " LOCATION);
        mPutHead = loc;
        mGetHead = std::min(mGetHead, mPutHead);
    }

    u64 ByteStream::tellg()const
    {
        return mGetHead;
    }

    u64 ByteStream::tellp()const
    {
        return mPutHead;
    }

    ByteStream& ByteStream::operator=(const ByteStream& os)
    {
        if (os.mPutHead >= mCapacity)
        {
            delete[] mData;
            mCapacity = os.mCapacity;
            mData = new u8[mCapacity]();
        }
        mPutHead = os.mPutHead;
        memcpy(mData, os.mData, mPutHead*sizeof(u8));
        mGetHead = os.mGetHead;

        return *this;
    }

    bool ByteStream::operator==(const ByteStream& a) const
    {
        if (mPutHead != a.mPutHead) { return false; }
        for (u64 i = 0; i < mPutHead; i++)
        {
            if (mData[i] != a.mData[i]) { return false; }
        }
        return true;
    }


    bool ByteStream::operator!=(const ByteStream& a) const
    {
        return !(*this == a);
    }

    void ByteStream::append(const u8* x, const u64 l)
    {
        if(tellp() + l > mCapacity)
        {
            reserve(std::max(mCapacity * 2, tellp() + l));
        }

        memcpy(mData + mPutHead, x, l*sizeof(u8));
        mPutHead += l;
    }

    void ByteStream::append(const block& b)
    {
        append((const u8*)(&b), sizeof(block));
    }    
    
    //void ByteStream::append(const blockRIOT& b, u64 l)
    //{
    //    append((const u8*)(&b), l); 
    //}
    //
    void ByteStream::append(const Commit& b)
    {
        append((const u8*)(&b), sizeof(Commit));
    }

    void ByteStream::consume(u8* x, const u64 l)
    {
        if (mGetHead + l > mPutHead) throw std::runtime_error("rt error at " LOCATION);
        memcpy(x, mData + mGetHead, l*sizeof(u8));
        mGetHead += l;
    }


    std::ostream& operator<<(std::ostream& s, const ByteStream& o)
    {
        std::stringstream ss;
        ss << std::hex;
        for (u64 i = 0; i < o.mPutHead; i++)
        {
            u32 t0 = o.mData[i] & 15;
            u32 t1 = o.mData[i] >> 4;
            ss  << t1 << t0;
        }
        s << ss.str();
        return s;
    }


    BitIterator ByteStream::bitIterBegin() const
    {
        return BitIterator(mData,0);
    }

    void ByteStream::ChannelBufferResize(u64 length)
    {
        if (length > mCapacity)
        {
            delete[] mData;
            mData = new u8[mCapacity = length]();
        }
        mPutHead = length;
        mGetHead = 0;
    }

}
