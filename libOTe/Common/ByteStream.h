#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
 
#include "Common/Defines.h"
#include "Network/Channel.h" 
#include "ArrayView.h"
#include "MatrixView.h"
#include "Common/BitIterator.h"


namespace osuCrypto { 

    class Commit; 

    template <class T>
    class BSIterator
    {
        T* mCur, *mBegin, *mEnd;


    public:
        BSIterator(T* cur, T* begin, T*end)
            :
            mCur(cur),
            mBegin(begin),
            mEnd(end)
        {}

        T& operator*() 
        { 
            if (mCur >= mEnd || mCur < mBegin)
                throw std::runtime_error("rt error at " LOCATION);

            return *mCur; 
        }

        BSIterator& operator++() 
        { 
            ++mCur; 
            if (mCur == mEnd) 
                throw std::runtime_error("rt error at " LOCATION); 
            return *this; 
        }

        BSIterator operator++(int) 
        { 
            BSIterator ret(*this); 
            ++mCur; 
            if (mCur > mEnd) 
                throw std::runtime_error("rt error at " LOCATION); 
            return ret; 
        }

        BSIterator& operator+(int i)
        {
            mCur += i;
            if (mCur > mEnd)
                throw std::runtime_error("rt error at " LOCATION);
            return *this;
        }

        BSIterator& operator--()
        {
            --mCur;
            if (mCur < mBegin)
                throw std::runtime_error("rt error at " LOCATION);

            return *this;
        }
        BSIterator operator--(int)
        {
            BSIterator ret(*this);
            --mCur;
            if (mCur < mBegin)
                throw std::runtime_error("rt error at " LOCATION);

            return ret;
        }

        BSIterator& operator-(int i)
        {
            mCur -= i;
            if (mCur < mBegin)
                throw std::runtime_error("rt error at " LOCATION);
            return *this;
        }


        T* operator->()
        {
            return raw();
        }


        T* raw()
        {
            if (mCur >= mEnd || mCur < mBegin)
                throw std::runtime_error("rt error at " LOCATION);
            return mCur;
        }

        bool operator==(const BSIterator& rhs) const
        {
            return mCur == rhs.mCur;
        }


        bool operator!=(const BSIterator& rhs) const
        {
            return mCur != rhs.mCur;
        }

        bool operator>(const BSIterator& rhs) const
        {
            return mCur > rhs.mCur;
        }
        bool operator>=(const BSIterator& rhs) const
        {
            return mCur >= rhs.mCur;
        }
        bool operator<(const BSIterator& rhs) const
        {
            return mCur < rhs.mCur;
        }
        bool operator<=(const BSIterator& rhs) const
        {
            return mCur <= rhs.mCur;
        }

    };

    class ByteStream : public ChannelBuffer
    {
        friend std::ostream& operator<<(std::ostream& s, const ByteStream& o);
        friend class PRNG;

    public: 
        ByteStream(u64 size = 0);
        ByteStream(const ByteStream& os);
        ByteStream(const u8* data, u64 length);

        ~ByteStream() { delete[] mData; }
         
        /// <summary>The size of the unconsumed steam/data.</summary>
        u64 size() const { return tellp() - tellg(); }

        /// <summary>The capacity of the container.</summary>
        u64 capacity() const { return mCapacity; }

        /// <summary>The location of the data.</summary>
        u8* data() const { return mData; }

        /// <summary>The start location of that data unconsumed data.</summary>
        u8* begin() const { return mData + tellg(); }

        /// <summary>The end location of that data.</summary>
        u8* end() const { return mData + tellp(); }

        /// <summary>Returns the offset of where data will be PUT in the stream.</summary>
        u64 tellp() const;

        /// <summary>Sets the offset of where data will be PUT in the stream.</summary>
        void setp(u64 loc);

        /// <summary>Returns the offset of where data will be GET in the stream.</summary>
        u64 tellg()const;

        /// <summary>Sets the offset of where data will be GET in the stream.</summary>
        void setg(u64 loc);

        /// <summary>Grows the size of the underlying container to fit length bytes</summary>
        void reserve(u64 length);
        
        void resize(u64 size);

        /// <summary>Copies length bytes starting at data to the end of the container tellp().</summary>
        void append(const u8* data, const u64 length);

        /// <summary>Copies the next length bytes starting at data() + tellg()  to dest</summary>
        void consume(u8* dest, const u64 length);

        void append(const block& b);
        //void append(const blockRIOT& b, const u64 length);
        void append(const Commit& b);

        ByteStream& operator=(const ByteStream& os);
        bool operator==(const ByteStream& rhs) const;
        bool operator!=(const ByteStream& rhs) const;

        template<class T>
        BSIterator<T>    begin();

        template<class T>
        BSIterator<T>    end();

        template<class T>
        ArrayView<T> getArrayView() const;


        template<class T>
        MatrixView<T> getMatrixView(u64 columnSize) const;


        BitIterator bitIterBegin() const;

    protected:
        u8* ChannelBufferData() const override { return begin(); }
        u64 ChannelBufferSize() const override { return size(); };
        void ChannelBufferResize(u64 length) override;

    private:

        u64 mPutHead, mCapacity, mGetHead;
        u8 *mData;
    };
    typedef ByteStream Buff;

    template<class T>
    inline BSIterator<T> ByteStream::begin()
    {
        return BSIterator<T>((T*)mData, (T*)mData, ((T*)mData) + ((mPutHead + sizeof(T) - 1)/ sizeof(T)));
    }

    template<class T>
    inline BSIterator<T> ByteStream::end()
    {
        auto end = ((T*)mData) + ((mPutHead + sizeof(T) - 1) / sizeof(T));
        return BSIterator<T>(end, (T*)mData, end);
    }

    template<class T>
    inline ArrayView<T> ByteStream::getArrayView() const
    {
        return ArrayView<T>((T*)mData, (T*)mData + (mPutHead / sizeof(T)), false);
    }
    template<class T>
    inline MatrixView<T> ByteStream::getMatrixView(u64 columnSize) const
    {
        u64 numRows = mPutHead / (columnSize * sizeof(T));
        return MatrixView<T>((T*)mData, numRows, columnSize, false);
    }
}

