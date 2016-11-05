#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "Common/Defines.h"
#define AES_DECRYPTION
#include <wmmintrin.h>

namespace osuCrypto {

#define AES_BLK_SIZE 16




    class AES
    {
    public:

        AES();
        AES(const block& userKey);


        void setKey(const block& userKey);


        void ecbEncBlock(const block& plaintext, block& cyphertext) const;
        block ecbEncBlock(const block& plaintext) const;

        void ecbEncBlocks(const block* plaintexts, u64 blockLength, block* cyphertext) const;

        void ecbEncTwoBlocks(const block* plaintexts, block* cyphertext) const;
        void ecbEncFourBlocks(const block* plaintexts, block* cyphertext) const;
        void ecbEnc16Blocks(const block* plaintexts, block* cyphertext) const;


        void ecbEncCounterMode(u64 baseIdx, u64 longth, block* cyphertext);
        //void ecbEncCounterMode(u64 baseIdx, u64 longth, block* cyphertext, const u64* destIdxs);

        block mRoundKey[11];
    };


    extern     const AES mAesFixedKey;

    class AESDec
    {
    public:

        AESDec();
        AESDec(const block& userKey);

        void setKey(const block& userKey);

        void ecbDecBlock(const block& cyphertext, block& plaintext);
        block ecbDecBlock(const block& cyphertext);
        block mRoundKey[11];
    };

}
