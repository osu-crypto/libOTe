#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 

/* Define the hash based commitment scheme */
#include "Common/Defines.h"
#include "Crypto/PRNG.h"
#include "Common/ByteStream.h"
//#include "Common/Exceptions.h"
#include "Crypto/sha1.h"
#include <iostream>

namespace osuCrypto {

#define COMMIT_BUFF_u32_SIZE  5
static_assert(SHA1::HashSize == sizeof(u32) * COMMIT_BUFF_u32_SIZE, "buffer need to be the same size as hash size");
class Commit //:  public ChannelBuffer
    {
        u32 buff[COMMIT_BUFF_u32_SIZE];

    public:
        Commit(const block& in)
        {
            hash(ByteArray(in), sizeof(block));
        }
        Commit(const std::array<block,3>& in)
        {
            hash(ByteArray(in[0]), sizeof(block));
            hash(ByteArray(in[1]), sizeof(block));
            hash(ByteArray(in[2]), sizeof(block));
        }

        Commit(const block& in, PRNG& prng)
        {
            block rand = prng.get<block>();
            hash(ByteArray(in), sizeof(block), rand);
        }
        Commit(const block& in, block& rand)
        {
             hash(ByteArray(in), sizeof(block), rand);
        }

        Commit(const ByteStream& in, PRNG& prng)
        {
            block rand = prng.get<block>();
             hash(in.data(), in.size(), rand);
        }
        Commit(const ByteStream& in, block& rand)
        {
             hash(in.data(), in.size(), rand);
        }

        Commit(const ByteStream& in)
        {
            hash(in.data(), in.size());
        }


        Commit(u8* d, u64 s)
        {
            hash(d, s);
        }

        Commit()
        {}

        bool operator==(const Commit& rhs)
        {
            for (u64 i = 0; i < COMMIT_BUFF_u32_SIZE; ++i)
            {
                if (buff[i] != rhs.buff[i])
                    return false;
            }
            return true;
        }

        bool operator!=(const Commit& rhs)
        {
            return !(*this == rhs);
        }

        u8* data() const
        {
            return (u8*)buff;
        }

        static u64 size()
        {
            return SHA1::HashSize;
        }

    private:

        void hash(u8* data, u64 size)
        {
            SHA1 sha;
            sha.Update(data, size);
            sha.Final((u8*)buff);
        }

         void hash(u8* data, u64 size, block& rand)
         {
              SHA1 sha;
              sha.Update(data, size);
              sha.Update(rand);
              sha.Final((u8*)buff);
         }


    
    protected:


        //u8* CBData() const override
        //{
        //    return (u8*)buff;
        //}
        //u64 CBSize() const override
        //{
        //    return SHA1::HashSize;
        //}
        //void CBResize(u64 length) override
        //{
        //    if (length != SHA1::HashSize)
        //        throw std::invalid_argument("Resize size can only be SHA1::HashSize i.e. 20 bytes");
        //}


    };

    static_assert(sizeof(Commit) == SHA1::HashSize, "needs to be Pod type");

    //void CommitComm(ByteStream& comm, ByteStream& open, const ByteStream& data, PRNG& prng);
    //bool CommitOpen(ByteStream& data, const ByteStream& comm, const ByteStream& open);
    //void CommitComm(ByteStream& comm, const block& rand, const block& data);
    //bool Commitopen(const ByteStream& comm, const block& rand, const block& data);

}
