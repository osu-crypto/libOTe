#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "Common/Defines.h"
extern void sha1_compress(uint32_t state[5], const uint8_t block[64]);

namespace osuCrypto {
    class SHA1
    {
    public:
        static const u64 HashSize = 20;
        SHA1() { Reset(); }


        inline void Reset()
        {
            //mSha.Restart();
            memset(state, 0, sizeof(u32) * 5);
            memset(block, 0,sizeof(u8) * 64);
            idx = 0;
        }
        inline void Update(const u8* dataIn, u64 length)
        {
            //sha1_compress(nullptr, nullptr);
            //mSha.Update(dataIn, length);
            while (length)
            {
                u64 step = std::min(length, u64(64) - idx);

                memcpy(block + idx, dataIn, step);

                idx += step; 
                dataIn += step;
                length -= step;


                if (idx == 64)
                {
                    sha1_compress(state, block);
                    idx = 0;
                }

            }
        }
        inline void Update(const block& blk)
        {
            Update(ByteArray(blk), sizeof(block));
        }

        //inline void Update(const blockRIOT& blk, u64 length)
        //{
        //    Update(ByteArray(blk), length);
        //}

        inline void Final(u8* DataOut)
        {
            if(idx)
                sha1_compress(state, block);

            idx = 0;
            memcpy(DataOut, state, sizeof(u32) * 5);
            //mSha.Final(DataOut);
        }

        inline const SHA1& operator=(const SHA1& src)
        {
            //mSha = src.mSha;
            memcpy(state, src.state, sizeof(u32) * 5);
            memcpy(block, src.block, sizeof(u8) * 64);
            return *this;
        }

    private:
        //CryptoPP::SHA1 mSha;
        uint32_t state[5];
        uint8_t block[64];
        u64 idx;
    };
    
    //u64    SHA1::HashSize(20);

    //void blk_SHA1_Init(blk_SHA_CTX *ctx);
    //void blk_SHA1_Update(blk_SHA_CTX *ctx, const void *dataIn, unsigned long len);
    //void blk_SHA1_Final(unsigned char hashout[20], blk_SHA_CTX *ctx);
    //
    //#define git_SHA_CTX    blk_SHA_CTX
    //#define git_SHA1_Init    blk_SHA1_Init
    //#define git_SHA1_Update    blk_SHA1_Update
    //#define git_SHA1_Final    blk_SHA1_Final
    //class SHA2
    //{
    //public:
    //    static const u64 HashSize = 512;
    //    SHA2() { Reset(); }

    //    //u64 mSize;
    //    //u32 mH[5];
    //    //u32 mW[16];

    //    inline void Reset()
    //    {
    //        mSha.Restart();
    //    }
    //    inline void Update(const u8* dataIn, u64 length)
    //    {
    //        mSha.Update(dataIn, length);
    //    }
    //    inline void Update(const block& blk)
    //    {
    //        Update(ByteArray(blk), sizeof(block));
    //    }
    //    inline void Final(u8* DataOut)
    //    {
    //        mSha.Final(DataOut);
    //    }

    //private:
    //    //void Block(const u32* data);
    //    CryptoPP::SHA512 mSha;

    //};

}
