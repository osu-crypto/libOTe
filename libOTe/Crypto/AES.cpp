#include "AES.h"

#include <array>
namespace osuCrypto {

    const AES mAesFixedKey(_mm_set_epi8(36, -100, 50, -22, 92, -26, 49, 9, -82, -86, -51, -96, 98, -20, 29, -13));


    block keyGenHelper(block key, block keyRcon)
    {
        keyRcon = _mm_shuffle_epi32(keyRcon, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        return _mm_xor_si128(key, keyRcon);
    }

    AES::AES()
    {
    }

    AES::AES(const block & userKey)
    {
        setKey(userKey);
    }

    void AES::setKey(const block & userKey)
    {
        mRoundKey[0] = userKey;
        mRoundKey[1] = keyGenHelper(mRoundKey[0], _mm_aeskeygenassist_si128(mRoundKey[0], 0x01));
        mRoundKey[2] = keyGenHelper(mRoundKey[1], _mm_aeskeygenassist_si128(mRoundKey[1], 0x02));
        mRoundKey[3] = keyGenHelper(mRoundKey[2], _mm_aeskeygenassist_si128(mRoundKey[2], 0x04));
        mRoundKey[4] = keyGenHelper(mRoundKey[3], _mm_aeskeygenassist_si128(mRoundKey[3], 0x08));
        mRoundKey[5] = keyGenHelper(mRoundKey[4], _mm_aeskeygenassist_si128(mRoundKey[4], 0x10));
        mRoundKey[6] = keyGenHelper(mRoundKey[5], _mm_aeskeygenassist_si128(mRoundKey[5], 0x20));
        mRoundKey[7] = keyGenHelper(mRoundKey[6], _mm_aeskeygenassist_si128(mRoundKey[6], 0x40));
        mRoundKey[8] = keyGenHelper(mRoundKey[7], _mm_aeskeygenassist_si128(mRoundKey[7], 0x80));
        mRoundKey[9] = keyGenHelper(mRoundKey[8], _mm_aeskeygenassist_si128(mRoundKey[8], 0x1B));
        mRoundKey[10] = keyGenHelper(mRoundKey[9], _mm_aeskeygenassist_si128(mRoundKey[9], 0x36));
    }

    void  AES::ecbEncBlock(const block & plaintext, block & cyphertext) const
    {
        cyphertext = _mm_xor_si128(plaintext, mRoundKey[0]);
        cyphertext = _mm_aesenc_si128(cyphertext, mRoundKey[1]);
        cyphertext = _mm_aesenc_si128(cyphertext, mRoundKey[2]);
        cyphertext = _mm_aesenc_si128(cyphertext, mRoundKey[3]);
        cyphertext = _mm_aesenc_si128(cyphertext, mRoundKey[4]);
        cyphertext = _mm_aesenc_si128(cyphertext, mRoundKey[5]);
        cyphertext = _mm_aesenc_si128(cyphertext, mRoundKey[6]);
        cyphertext = _mm_aesenc_si128(cyphertext, mRoundKey[7]);
        cyphertext = _mm_aesenc_si128(cyphertext, mRoundKey[8]);
        cyphertext = _mm_aesenc_si128(cyphertext, mRoundKey[9]);
        cyphertext = _mm_aesenclast_si128(cyphertext, mRoundKey[10]);
    }

    block AES::ecbEncBlock(const block & plaintext) const
    {
        block ret;
        ecbEncBlock(plaintext, ret);
        return ret;
    }

    void AES::ecbEncBlocks(const block * plaintexts, u64 blockLength, block * cyphertext) const
    {
        const u64 step = 8;
        u64 idx = 0;
        u64 length = blockLength - blockLength % step;

        std::array<block, step> temp;


        for (; idx < length; idx += step)
        {
            temp[0] = _mm_xor_si128(plaintexts[idx + 0], mRoundKey[0]);
            temp[1] = _mm_xor_si128(plaintexts[idx + 1], mRoundKey[0]);
            temp[2] = _mm_xor_si128(plaintexts[idx + 2], mRoundKey[0]);
            temp[3] = _mm_xor_si128(plaintexts[idx + 3], mRoundKey[0]);
            temp[4] = _mm_xor_si128(plaintexts[idx + 4], mRoundKey[0]);
            temp[5] = _mm_xor_si128(plaintexts[idx + 5], mRoundKey[0]);
            temp[6] = _mm_xor_si128(plaintexts[idx + 6], mRoundKey[0]);
            temp[7] = _mm_xor_si128(plaintexts[idx + 7], mRoundKey[0]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[1]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[1]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[1]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[1]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[1]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[1]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[1]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[1]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[2]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[2]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[2]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[2]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[2]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[2]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[2]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[2]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[3]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[3]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[3]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[3]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[3]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[3]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[3]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[3]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[4]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[4]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[4]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[4]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[4]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[4]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[4]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[4]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[5]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[5]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[5]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[5]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[5]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[5]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[5]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[5]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[6]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[6]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[6]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[6]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[6]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[6]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[6]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[6]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[7]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[7]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[7]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[7]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[7]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[7]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[7]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[7]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[8]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[8]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[8]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[8]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[8]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[8]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[8]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[8]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[9]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[9]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[9]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[9]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[9]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[9]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[9]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[9]);

            cyphertext[idx + 0] = _mm_aesenclast_si128(temp[0], mRoundKey[10]);
            cyphertext[idx + 1] = _mm_aesenclast_si128(temp[1], mRoundKey[10]);
            cyphertext[idx + 2] = _mm_aesenclast_si128(temp[2], mRoundKey[10]);
            cyphertext[idx + 3] = _mm_aesenclast_si128(temp[3], mRoundKey[10]);
            cyphertext[idx + 4] = _mm_aesenclast_si128(temp[4], mRoundKey[10]);
            cyphertext[idx + 5] = _mm_aesenclast_si128(temp[5], mRoundKey[10]);
            cyphertext[idx + 6] = _mm_aesenclast_si128(temp[6], mRoundKey[10]);
            cyphertext[idx + 7] = _mm_aesenclast_si128(temp[7], mRoundKey[10]);
        }

        for (; idx < blockLength; ++idx)
        {
            cyphertext[idx] = _mm_xor_si128(plaintexts[idx], mRoundKey[0]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[1]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[2]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[3]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[4]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[5]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[6]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[7]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[8]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[9]);
            cyphertext[idx] = _mm_aesenclast_si128(cyphertext[idx], mRoundKey[10]);
        }
    }


    void AES::ecbEncTwoBlocks(const block * plaintexts, block * cyphertext) const
    {
        cyphertext[0] = _mm_xor_si128(plaintexts[0], mRoundKey[0]);
        cyphertext[1] = _mm_xor_si128(plaintexts[1], mRoundKey[0]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[1]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[1]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[2]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[2]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[3]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[3]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[4]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[4]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[5]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[5]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[6]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[6]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[7]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[7]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[8]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[8]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[9]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[9]);

        cyphertext[0] = _mm_aesenclast_si128(cyphertext[0], mRoundKey[10]);
        cyphertext[1] = _mm_aesenclast_si128(cyphertext[1], mRoundKey[10]);
    }

    void AES::ecbEncFourBlocks(const block * plaintexts, block * cyphertext) const
    {
        cyphertext[0] = _mm_xor_si128(plaintexts[0], mRoundKey[0]);
        cyphertext[1] = _mm_xor_si128(plaintexts[1], mRoundKey[0]);
        cyphertext[2] = _mm_xor_si128(plaintexts[2], mRoundKey[0]);
        cyphertext[3] = _mm_xor_si128(plaintexts[3], mRoundKey[0]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[1]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[1]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[1]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[1]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[2]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[2]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[2]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[2]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[3]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[3]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[3]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[3]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[4]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[4]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[4]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[4]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[5]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[5]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[5]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[5]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[6]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[6]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[6]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[6]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[7]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[7]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[7]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[7]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[8]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[8]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[8]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[8]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[9]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[9]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[9]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[9]);

        cyphertext[0] = _mm_aesenclast_si128(cyphertext[0], mRoundKey[10]);
        cyphertext[1] = _mm_aesenclast_si128(cyphertext[1], mRoundKey[10]);
        cyphertext[2] = _mm_aesenclast_si128(cyphertext[2], mRoundKey[10]);
        cyphertext[3] = _mm_aesenclast_si128(cyphertext[3], mRoundKey[10]);
    }

    void AES::ecbEnc16Blocks(const block * plaintexts, block * cyphertext) const
    {
        cyphertext[0] = _mm_xor_si128(plaintexts[0], mRoundKey[0]);
        cyphertext[1] = _mm_xor_si128(plaintexts[1], mRoundKey[0]);
        cyphertext[2] = _mm_xor_si128(plaintexts[2], mRoundKey[0]);
        cyphertext[3] = _mm_xor_si128(plaintexts[3], mRoundKey[0]);
        cyphertext[4] = _mm_xor_si128(plaintexts[4], mRoundKey[0]);
        cyphertext[5] = _mm_xor_si128(plaintexts[5], mRoundKey[0]);
        cyphertext[6] = _mm_xor_si128(plaintexts[6], mRoundKey[0]);
        cyphertext[7] = _mm_xor_si128(plaintexts[7], mRoundKey[0]);
        cyphertext[8] = _mm_xor_si128(plaintexts[8], mRoundKey[0]);
        cyphertext[9] = _mm_xor_si128(plaintexts[9], mRoundKey[0]);
        cyphertext[10] = _mm_xor_si128(plaintexts[10], mRoundKey[0]);
        cyphertext[11] = _mm_xor_si128(plaintexts[11], mRoundKey[0]);
        cyphertext[12] = _mm_xor_si128(plaintexts[12], mRoundKey[0]);
        cyphertext[13] = _mm_xor_si128(plaintexts[13], mRoundKey[0]);
        cyphertext[14] = _mm_xor_si128(plaintexts[14], mRoundKey[0]);
        cyphertext[15] = _mm_xor_si128(plaintexts[15], mRoundKey[0]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[1]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[1]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[1]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[1]);
        cyphertext[4] = _mm_aesenc_si128(cyphertext[4], mRoundKey[1]);
        cyphertext[5] = _mm_aesenc_si128(cyphertext[5], mRoundKey[1]);
        cyphertext[6] = _mm_aesenc_si128(cyphertext[6], mRoundKey[1]);
        cyphertext[7] = _mm_aesenc_si128(cyphertext[7], mRoundKey[1]);
        cyphertext[8] = _mm_aesenc_si128(cyphertext[8], mRoundKey[1]);
        cyphertext[9] = _mm_aesenc_si128(cyphertext[9], mRoundKey[1]);
        cyphertext[10] = _mm_aesenc_si128(cyphertext[10], mRoundKey[1]);
        cyphertext[11] = _mm_aesenc_si128(cyphertext[11], mRoundKey[1]);
        cyphertext[12] = _mm_aesenc_si128(cyphertext[12], mRoundKey[1]);
        cyphertext[13] = _mm_aesenc_si128(cyphertext[13], mRoundKey[1]);
        cyphertext[14] = _mm_aesenc_si128(cyphertext[14], mRoundKey[1]);
        cyphertext[15] = _mm_aesenc_si128(cyphertext[15], mRoundKey[1]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[2]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[2]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[2]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[2]);
        cyphertext[4] = _mm_aesenc_si128(cyphertext[4], mRoundKey[2]);
        cyphertext[5] = _mm_aesenc_si128(cyphertext[5], mRoundKey[2]);
        cyphertext[6] = _mm_aesenc_si128(cyphertext[6], mRoundKey[2]);
        cyphertext[7] = _mm_aesenc_si128(cyphertext[7], mRoundKey[2]);
        cyphertext[8] = _mm_aesenc_si128(cyphertext[8], mRoundKey[2]);
        cyphertext[9] = _mm_aesenc_si128(cyphertext[9], mRoundKey[2]);
        cyphertext[10] = _mm_aesenc_si128(cyphertext[10], mRoundKey[2]);
        cyphertext[11] = _mm_aesenc_si128(cyphertext[11], mRoundKey[2]);
        cyphertext[12] = _mm_aesenc_si128(cyphertext[12], mRoundKey[2]);
        cyphertext[13] = _mm_aesenc_si128(cyphertext[13], mRoundKey[2]);
        cyphertext[14] = _mm_aesenc_si128(cyphertext[14], mRoundKey[2]);
        cyphertext[15] = _mm_aesenc_si128(cyphertext[15], mRoundKey[2]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[3]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[3]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[3]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[3]);
        cyphertext[4] = _mm_aesenc_si128(cyphertext[4], mRoundKey[3]);
        cyphertext[5] = _mm_aesenc_si128(cyphertext[5], mRoundKey[3]);
        cyphertext[6] = _mm_aesenc_si128(cyphertext[6], mRoundKey[3]);
        cyphertext[7] = _mm_aesenc_si128(cyphertext[7], mRoundKey[3]);
        cyphertext[8] = _mm_aesenc_si128(cyphertext[8], mRoundKey[3]);
        cyphertext[9] = _mm_aesenc_si128(cyphertext[9], mRoundKey[3]);
        cyphertext[10] = _mm_aesenc_si128(cyphertext[10], mRoundKey[3]);
        cyphertext[11] = _mm_aesenc_si128(cyphertext[11], mRoundKey[3]);
        cyphertext[12] = _mm_aesenc_si128(cyphertext[12], mRoundKey[3]);
        cyphertext[13] = _mm_aesenc_si128(cyphertext[13], mRoundKey[3]);
        cyphertext[14] = _mm_aesenc_si128(cyphertext[14], mRoundKey[3]);
        cyphertext[15] = _mm_aesenc_si128(cyphertext[15], mRoundKey[3]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[4]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[4]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[4]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[4]);
        cyphertext[4] = _mm_aesenc_si128(cyphertext[4], mRoundKey[4]);
        cyphertext[5] = _mm_aesenc_si128(cyphertext[5], mRoundKey[4]);
        cyphertext[6] = _mm_aesenc_si128(cyphertext[6], mRoundKey[4]);
        cyphertext[7] = _mm_aesenc_si128(cyphertext[7], mRoundKey[4]);
        cyphertext[8] = _mm_aesenc_si128(cyphertext[8], mRoundKey[4]);
        cyphertext[9] = _mm_aesenc_si128(cyphertext[9], mRoundKey[4]);
        cyphertext[10] = _mm_aesenc_si128(cyphertext[10], mRoundKey[4]);
        cyphertext[11] = _mm_aesenc_si128(cyphertext[11], mRoundKey[4]);
        cyphertext[12] = _mm_aesenc_si128(cyphertext[12], mRoundKey[4]);
        cyphertext[13] = _mm_aesenc_si128(cyphertext[13], mRoundKey[4]);
        cyphertext[14] = _mm_aesenc_si128(cyphertext[14], mRoundKey[4]);
        cyphertext[15] = _mm_aesenc_si128(cyphertext[15], mRoundKey[4]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[5]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[5]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[5]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[5]);
        cyphertext[4] = _mm_aesenc_si128(cyphertext[4], mRoundKey[5]);
        cyphertext[5] = _mm_aesenc_si128(cyphertext[5], mRoundKey[5]);
        cyphertext[6] = _mm_aesenc_si128(cyphertext[6], mRoundKey[5]);
        cyphertext[7] = _mm_aesenc_si128(cyphertext[7], mRoundKey[5]);
        cyphertext[8] = _mm_aesenc_si128(cyphertext[8], mRoundKey[5]);
        cyphertext[9] = _mm_aesenc_si128(cyphertext[9], mRoundKey[5]);
        cyphertext[10] = _mm_aesenc_si128(cyphertext[10], mRoundKey[5]);
        cyphertext[11] = _mm_aesenc_si128(cyphertext[11], mRoundKey[5]);
        cyphertext[12] = _mm_aesenc_si128(cyphertext[12], mRoundKey[5]);
        cyphertext[13] = _mm_aesenc_si128(cyphertext[13], mRoundKey[5]);
        cyphertext[14] = _mm_aesenc_si128(cyphertext[14], mRoundKey[5]);
        cyphertext[15] = _mm_aesenc_si128(cyphertext[15], mRoundKey[5]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[6]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[6]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[6]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[6]);
        cyphertext[4] = _mm_aesenc_si128(cyphertext[4], mRoundKey[6]);
        cyphertext[5] = _mm_aesenc_si128(cyphertext[5], mRoundKey[6]);
        cyphertext[6] = _mm_aesenc_si128(cyphertext[6], mRoundKey[6]);
        cyphertext[7] = _mm_aesenc_si128(cyphertext[7], mRoundKey[6]);
        cyphertext[8] = _mm_aesenc_si128(cyphertext[8], mRoundKey[6]);
        cyphertext[9] = _mm_aesenc_si128(cyphertext[9], mRoundKey[6]);
        cyphertext[10] = _mm_aesenc_si128(cyphertext[10], mRoundKey[6]);
        cyphertext[11] = _mm_aesenc_si128(cyphertext[11], mRoundKey[6]);
        cyphertext[12] = _mm_aesenc_si128(cyphertext[12], mRoundKey[6]);
        cyphertext[13] = _mm_aesenc_si128(cyphertext[13], mRoundKey[6]);
        cyphertext[14] = _mm_aesenc_si128(cyphertext[14], mRoundKey[6]);
        cyphertext[15] = _mm_aesenc_si128(cyphertext[15], mRoundKey[6]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[7]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[7]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[7]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[7]);
        cyphertext[4] = _mm_aesenc_si128(cyphertext[4], mRoundKey[7]);
        cyphertext[5] = _mm_aesenc_si128(cyphertext[5], mRoundKey[7]);
        cyphertext[6] = _mm_aesenc_si128(cyphertext[6], mRoundKey[7]);
        cyphertext[7] = _mm_aesenc_si128(cyphertext[7], mRoundKey[7]);
        cyphertext[8] = _mm_aesenc_si128(cyphertext[8], mRoundKey[7]);
        cyphertext[9] = _mm_aesenc_si128(cyphertext[9], mRoundKey[7]);
        cyphertext[10] = _mm_aesenc_si128(cyphertext[10], mRoundKey[7]);
        cyphertext[11] = _mm_aesenc_si128(cyphertext[11], mRoundKey[7]);
        cyphertext[12] = _mm_aesenc_si128(cyphertext[12], mRoundKey[7]);
        cyphertext[13] = _mm_aesenc_si128(cyphertext[13], mRoundKey[7]);
        cyphertext[14] = _mm_aesenc_si128(cyphertext[14], mRoundKey[7]);
        cyphertext[15] = _mm_aesenc_si128(cyphertext[15], mRoundKey[7]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[8]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[8]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[8]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[8]);
        cyphertext[4] = _mm_aesenc_si128(cyphertext[4], mRoundKey[8]);
        cyphertext[5] = _mm_aesenc_si128(cyphertext[5], mRoundKey[8]);
        cyphertext[6] = _mm_aesenc_si128(cyphertext[6], mRoundKey[8]);
        cyphertext[7] = _mm_aesenc_si128(cyphertext[7], mRoundKey[8]);
        cyphertext[8] = _mm_aesenc_si128(cyphertext[8], mRoundKey[8]);
        cyphertext[9] = _mm_aesenc_si128(cyphertext[9], mRoundKey[8]);
        cyphertext[10] = _mm_aesenc_si128(cyphertext[10], mRoundKey[8]);
        cyphertext[11] = _mm_aesenc_si128(cyphertext[11], mRoundKey[8]);
        cyphertext[12] = _mm_aesenc_si128(cyphertext[12], mRoundKey[8]);
        cyphertext[13] = _mm_aesenc_si128(cyphertext[13], mRoundKey[8]);
        cyphertext[14] = _mm_aesenc_si128(cyphertext[14], mRoundKey[8]);
        cyphertext[15] = _mm_aesenc_si128(cyphertext[15], mRoundKey[8]);

        cyphertext[0] = _mm_aesenc_si128(cyphertext[0], mRoundKey[9]);
        cyphertext[1] = _mm_aesenc_si128(cyphertext[1], mRoundKey[9]);
        cyphertext[2] = _mm_aesenc_si128(cyphertext[2], mRoundKey[9]);
        cyphertext[3] = _mm_aesenc_si128(cyphertext[3], mRoundKey[9]);
        cyphertext[4] = _mm_aesenc_si128(cyphertext[4], mRoundKey[9]);
        cyphertext[5] = _mm_aesenc_si128(cyphertext[5], mRoundKey[9]);
        cyphertext[6] = _mm_aesenc_si128(cyphertext[6], mRoundKey[9]);
        cyphertext[7] = _mm_aesenc_si128(cyphertext[7], mRoundKey[9]);
        cyphertext[8] = _mm_aesenc_si128(cyphertext[8], mRoundKey[9]);
        cyphertext[9] = _mm_aesenc_si128(cyphertext[9], mRoundKey[9]);
        cyphertext[10] = _mm_aesenc_si128(cyphertext[10], mRoundKey[9]);
        cyphertext[11] = _mm_aesenc_si128(cyphertext[11], mRoundKey[9]);
        cyphertext[12] = _mm_aesenc_si128(cyphertext[12], mRoundKey[9]);
        cyphertext[13] = _mm_aesenc_si128(cyphertext[13], mRoundKey[9]);
        cyphertext[14] = _mm_aesenc_si128(cyphertext[14], mRoundKey[9]);
        cyphertext[15] = _mm_aesenc_si128(cyphertext[15], mRoundKey[9]);

        cyphertext[0] = _mm_aesenclast_si128(cyphertext[0], mRoundKey[10]);
        cyphertext[1] = _mm_aesenclast_si128(cyphertext[1], mRoundKey[10]);
        cyphertext[2] = _mm_aesenclast_si128(cyphertext[2], mRoundKey[10]);
        cyphertext[3] = _mm_aesenclast_si128(cyphertext[3], mRoundKey[10]);
        cyphertext[4] = _mm_aesenclast_si128(cyphertext[4], mRoundKey[10]);
        cyphertext[5] = _mm_aesenclast_si128(cyphertext[5], mRoundKey[10]);
        cyphertext[6] = _mm_aesenclast_si128(cyphertext[6], mRoundKey[10]);
        cyphertext[7] = _mm_aesenclast_si128(cyphertext[7], mRoundKey[10]);
        cyphertext[8] = _mm_aesenclast_si128(cyphertext[8], mRoundKey[10]);
        cyphertext[9] = _mm_aesenclast_si128(cyphertext[9], mRoundKey[10]);
        cyphertext[10] = _mm_aesenclast_si128(cyphertext[10], mRoundKey[10]);
        cyphertext[11] = _mm_aesenclast_si128(cyphertext[11], mRoundKey[10]);
        cyphertext[12] = _mm_aesenclast_si128(cyphertext[12], mRoundKey[10]);
        cyphertext[13] = _mm_aesenclast_si128(cyphertext[13], mRoundKey[10]);
        cyphertext[14] = _mm_aesenclast_si128(cyphertext[14], mRoundKey[10]);
        cyphertext[15] = _mm_aesenclast_si128(cyphertext[15], mRoundKey[10]);

    }

    void AES::ecbEncCounterMode(u64 baseIdx, u64 blockLength, block * cyphertext)
    {
        const u64 step = 8;
        u64 idx = 0;
        u64 length = blockLength - blockLength % step;

        std::array<block, step> temp;

        for (; idx < length; idx += step, baseIdx += step)
        {
            temp[0] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 0), mRoundKey[0]);
            temp[1] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 1), mRoundKey[0]);
            temp[2] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 2), mRoundKey[0]);
            temp[3] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 3), mRoundKey[0]);
            temp[4] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 4), mRoundKey[0]);
            temp[5] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 5), mRoundKey[0]);
            temp[6] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 6), mRoundKey[0]);
            temp[7] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 7), mRoundKey[0]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[1]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[1]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[1]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[1]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[1]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[1]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[1]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[1]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[2]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[2]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[2]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[2]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[2]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[2]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[2]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[2]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[3]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[3]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[3]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[3]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[3]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[3]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[3]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[3]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[4]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[4]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[4]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[4]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[4]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[4]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[4]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[4]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[5]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[5]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[5]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[5]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[5]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[5]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[5]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[5]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[6]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[6]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[6]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[6]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[6]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[6]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[6]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[6]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[7]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[7]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[7]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[7]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[7]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[7]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[7]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[7]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[8]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[8]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[8]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[8]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[8]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[8]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[8]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[8]);

            temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[9]);
            temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[9]);
            temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[9]);
            temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[9]);
            temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[9]);
            temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[9]);
            temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[9]);
            temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[9]);

            cyphertext[idx + 0] = _mm_aesenclast_si128(temp[0], mRoundKey[10]);
            cyphertext[idx + 1] = _mm_aesenclast_si128(temp[1], mRoundKey[10]);
            cyphertext[idx + 2] = _mm_aesenclast_si128(temp[2], mRoundKey[10]);
            cyphertext[idx + 3] = _mm_aesenclast_si128(temp[3], mRoundKey[10]);
            cyphertext[idx + 4] = _mm_aesenclast_si128(temp[4], mRoundKey[10]);
            cyphertext[idx + 5] = _mm_aesenclast_si128(temp[5], mRoundKey[10]);
            cyphertext[idx + 6] = _mm_aesenclast_si128(temp[6], mRoundKey[10]);
            cyphertext[idx + 7] = _mm_aesenclast_si128(temp[7], mRoundKey[10]);
        }

        for (; idx < blockLength; ++idx, ++baseIdx)
        {
            cyphertext[idx] = _mm_xor_si128(_mm_set1_epi64x(baseIdx), mRoundKey[0]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[1]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[2]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[3]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[4]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[5]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[6]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[7]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[8]);
            cyphertext[idx] = _mm_aesenc_si128(cyphertext[idx], mRoundKey[9]);
            cyphertext[idx] = _mm_aesenclast_si128(cyphertext[idx], mRoundKey[10]);
        }

    }


    //void AES::ecbEncCounterMode(u64 baseIdx, u64 blockLength, block* cyphertext, const u64* destIdxs)
    //{
    //	const u64 step = 8;
    //	u64 idx = 0;
    //	u64 length = blockLength - blockLength % step;

    //	std::array<block, step> temp;

    //	for (; idx < length; idx += step, baseIdx += step)
    //	{
    //		temp[0] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 0), mRoundKey[0]);
    //		temp[1] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 1), mRoundKey[0]);
    //		temp[2] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 2), mRoundKey[0]);
    //		temp[3] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 3), mRoundKey[0]);
    //		temp[4] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 4), mRoundKey[0]);
    //		temp[5] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 5), mRoundKey[0]);
    //		temp[6] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 6), mRoundKey[0]);
    //		temp[7] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 7), mRoundKey[0]);

    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[1]);
    //		temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[1]);
    //		temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[1]);
    //		temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[1]);
    //		temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[1]);
    //		temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[1]);
    //		temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[1]);
    //		temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[1]);

    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[2]);
    //		temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[2]);
    //		temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[2]);
    //		temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[2]);
    //		temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[2]);
    //		temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[2]);
    //		temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[2]);
    //		temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[2]);

    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[3]);
    //		temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[3]);
    //		temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[3]);
    //		temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[3]);
    //		temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[3]);
    //		temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[3]);
    //		temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[3]);
    //		temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[3]);

    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[4]);
    //		temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[4]);
    //		temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[4]);
    //		temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[4]);
    //		temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[4]);
    //		temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[4]);
    //		temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[4]);
    //		temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[4]);

    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[5]);
    //		temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[5]);
    //		temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[5]);
    //		temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[5]);
    //		temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[5]);
    //		temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[5]);
    //		temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[5]);
    //		temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[5]);

    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[6]);
    //		temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[6]);
    //		temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[6]);
    //		temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[6]);
    //		temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[6]);
    //		temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[6]);
    //		temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[6]);
    //		temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[6]);

    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[7]);
    //		temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[7]);
    //		temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[7]);
    //		temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[7]);
    //		temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[7]);
    //		temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[7]);
    //		temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[7]);
    //		temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[7]);

    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[8]);
    //		temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[8]);
    //		temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[8]);
    //		temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[8]);
    //		temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[8]);
    //		temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[8]);
    //		temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[8]);
    //		temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[8]);

    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[9]);
    //		temp[1] = _mm_aesenc_si128(temp[1], mRoundKey[9]);
    //		temp[2] = _mm_aesenc_si128(temp[2], mRoundKey[9]);
    //		temp[3] = _mm_aesenc_si128(temp[3], mRoundKey[9]);
    //		temp[4] = _mm_aesenc_si128(temp[4], mRoundKey[9]);
    //		temp[5] = _mm_aesenc_si128(temp[5], mRoundKey[9]);
    //		temp[6] = _mm_aesenc_si128(temp[6], mRoundKey[9]);
    //		temp[7] = _mm_aesenc_si128(temp[7], mRoundKey[9]);

    //		cyphertext[destIdxs[idx + 0]] = _mm_aesenclast_si128(temp[0], mRoundKey[10]);
    //		cyphertext[destIdxs[idx + 1]] = _mm_aesenclast_si128(temp[1], mRoundKey[10]);
    //		cyphertext[destIdxs[idx + 2]] = _mm_aesenclast_si128(temp[2], mRoundKey[10]);
    //		cyphertext[destIdxs[idx + 3]] = _mm_aesenclast_si128(temp[3], mRoundKey[10]);
    //		cyphertext[destIdxs[idx + 4]] = _mm_aesenclast_si128(temp[4], mRoundKey[10]);
    //		cyphertext[destIdxs[idx + 5]] = _mm_aesenclast_si128(temp[5], mRoundKey[10]);
    //		cyphertext[destIdxs[idx + 6]] = _mm_aesenclast_si128(temp[6], mRoundKey[10]);
    //		cyphertext[destIdxs[idx + 7]] = _mm_aesenclast_si128(temp[7], mRoundKey[10]);
    //	}


    //	for (; idx < blockLength; ++idx, ++baseIdx)
    //	{
    //		temp[0] = _mm_xor_si128(_mm_set1_epi64x(baseIdx), mRoundKey[0]);
    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[1]);
    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[2]);
    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[3]);
    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[4]);
    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[5]);
    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[6]);
    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[7]);
    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[8]);
    //		temp[0] = _mm_aesenc_si128(temp[0], mRoundKey[9]);
    //		cyphertext[destIdxs[idx]] = _mm_aesenclast_si128(temp[0], mRoundKey[10]);
    //	}

    //}

    AESDec::AESDec()
    {
    }

    AESDec::AESDec(const block & userKey)
    {
        setKey(userKey);
    }

    void AESDec::setKey(const block & userKey)
    {
        const block& v0 = userKey;
        const block  v1 = keyGenHelper(v0, _mm_aeskeygenassist_si128(v0, 0x01));
        const block  v2 = keyGenHelper(v1, _mm_aeskeygenassist_si128(v1, 0x02));
        const block  v3 = keyGenHelper(v2, _mm_aeskeygenassist_si128(v2, 0x04));
        const block  v4 = keyGenHelper(v3, _mm_aeskeygenassist_si128(v3, 0x08));
        const block  v5 = keyGenHelper(v4, _mm_aeskeygenassist_si128(v4, 0x10));
        const block  v6 = keyGenHelper(v5, _mm_aeskeygenassist_si128(v5, 0x20));
        const block  v7 = keyGenHelper(v6, _mm_aeskeygenassist_si128(v6, 0x40));
        const block  v8 = keyGenHelper(v7, _mm_aeskeygenassist_si128(v7, 0x80));
        const block  v9 = keyGenHelper(v8, _mm_aeskeygenassist_si128(v8, 0x1B));
        const block  v10 = keyGenHelper(v9, _mm_aeskeygenassist_si128(v9, 0x36));


        _mm_storeu_si128(mRoundKey, v10);
        _mm_storeu_si128(mRoundKey + 1, _mm_aesimc_si128(v9));
        _mm_storeu_si128(mRoundKey + 2, _mm_aesimc_si128(v8));
        _mm_storeu_si128(mRoundKey + 3, _mm_aesimc_si128(v7));
        _mm_storeu_si128(mRoundKey + 4, _mm_aesimc_si128(v6));
        _mm_storeu_si128(mRoundKey + 5, _mm_aesimc_si128(v5));
        _mm_storeu_si128(mRoundKey + 6, _mm_aesimc_si128(v4));
        _mm_storeu_si128(mRoundKey + 7, _mm_aesimc_si128(v3));
        _mm_storeu_si128(mRoundKey + 8, _mm_aesimc_si128(v2));
        _mm_storeu_si128(mRoundKey + 9, _mm_aesimc_si128(v1));
        _mm_storeu_si128(mRoundKey + 10, v0);

    }

    void  AESDec::ecbDecBlock(const block & cyphertext, block & plaintext)
    {
        plaintext = _mm_xor_si128(cyphertext, mRoundKey[0]);
        plaintext = _mm_aesdec_si128(plaintext, mRoundKey[1]);
        plaintext = _mm_aesdec_si128(plaintext, mRoundKey[2]);
        plaintext = _mm_aesdec_si128(plaintext, mRoundKey[3]);
        plaintext = _mm_aesdec_si128(plaintext, mRoundKey[4]);
        plaintext = _mm_aesdec_si128(plaintext, mRoundKey[5]);
        plaintext = _mm_aesdec_si128(plaintext, mRoundKey[6]);
        plaintext = _mm_aesdec_si128(plaintext, mRoundKey[7]);
        plaintext = _mm_aesdec_si128(plaintext, mRoundKey[8]);
        plaintext = _mm_aesdec_si128(plaintext, mRoundKey[9]);
        plaintext = _mm_aesdeclast_si128(plaintext, mRoundKey[10]);

    }

    block AESDec::ecbDecBlock(const block & plaintext)
    {
        block ret;
        ecbDecBlock(plaintext, ret);
        return ret;
    }


}