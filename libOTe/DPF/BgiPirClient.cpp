#include "BgiPirClient.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
namespace osuCrypto
{
    std::string ss(block b)
    {
        std::stringstream ss;

        b = b >> 2;
        ss << b;
        return ss.str();
    }
    std::string t1(block b)
    {
        std::stringstream ss;
        ss << (int)((*(u8 *)&b) & 1);
        return ss.str();
    }
    std::string t2(block b)
    {
        std::stringstream ss;
        ss << ((int)((*(u8 *)&b) & 2) >> 1);
        return ss.str();
    }
    std::string stt(block b)
    {
        return ss(b) + " " + t2(b) + " " + t1(b);
    }

    BgiPirClient::uint128_t BgiPirClient::bytesToUint128_t(const span<u8>& data)
    {
        if (data.size() > 16)  throw std::runtime_error("inputsize is too large, 128 bit max. " LOCATION);

        using boost::multiprecision::cpp_int;
        uint128_t idx(0);
        BitIterator bit(data.data(), 0);
        for (u32 i = 0; i < u32(data.size() * 8); ++i)
        {
            if (*bit++) bit_set(idx, i);
        }
        return idx;
    }

    void BgiPirClient::init(u64 depth, u64 groupBlkSize)
    {

        mDatasetSize = u64(1) << depth;
        mKDepth = depth;
        mGroupBlkSize = groupBlkSize;
    }

    block BgiPirClient::query(span<u8> idx, Channel srv0, Channel srv1, block seed)
    {

        return query(bytesToUint128_t(idx), srv0, srv1, seed);
    }


    block BgiPirClient::query(uint128_t idx, Channel srv0, Channel srv1, block seed)
    {
        std::vector<block> k0(mKDepth + 1), k1(mKDepth + 1);
        std::vector<block> g0(mGroupBlkSize), g1(mGroupBlkSize);

        keyGen(idx, seed, k0, g0, k1, g1);
        srv0.asyncSend(std::move(k0));
        srv0.asyncSend(std::move(g0));
        srv1.asyncSend(std::move(k1));
        srv1.asyncSend(std::move(g1));

        block blk0, blk1;

        srv0.recv((u8*)&blk0, sizeof(block));
        srv1.recv((u8*)&blk1, sizeof(block));

        return blk0 ^ blk1;
    }

    void BgiPirClient::keyGen(span<u8> idx, block seed, span<block> k0, span<block> g0, span<block> k1, span<block> g1)
    {

        keyGen(bytesToUint128_t(idx), seed, k0, g0, k1, g1);
    }

    void BgiPirClient::keyGen(uint128_t idx, block seed, span<block> k0, span<block> g0, span<block> k1, span<block> g1)
    {

        // static const std::array<block, 2> zeroOne{ZeroBlock, OneBlock};
        static const block notOneBlock = toBlock(~0, ~1);
        static const block notThreeBlock = toBlock(~0, ~3);

        u64 groupSize = g0.size();
        auto kIdx = idx / (groupSize * 128);
        u64 gIdx = static_cast<u64>(idx % (groupSize * 128));

        u64 kDepth = k0.size() - 1;
        std::array<std::array<block, 2>, 2> si;
        std::array<block, 2> s = PRNG(seed).get<std::array<block, 2>>();

        // make sure that s[0]'s bottom bit is the opposite of s[1]
        // This bottom bit will prepresent the t values
        s[0] = (s[0] & notOneBlock)           // take the bits [127,1] bits of  s[0]
            ^ ((s[1] & OneBlock) ^ OneBlock); // take the bits [0  ,0] bots of ~s[1]

        k0[0] = s[0];
        k1[0] = s[1];

        static AES aes0(ZeroBlock);
        static AES aes1(OneBlock);

        for (u64 i = 0, shift = kDepth - 1; i < kDepth; ++i, --shift)
        {
            const u8 keep = static_cast<u8>(kIdx >> shift) & 1;
            auto a = toBlock(keep);

            //std::cout << "keep[" << i << "]   " << (int)keep << std::endl;

            // AES(s[i][0] & notThreeBlock).ecbEncTwoBlocks(zeroOne.data(), si[0].data());
            // AES(s[i][1] & notThreeBlock).ecbEncTwoBlocks(zeroOne.data(), si[1].data());

            auto ss0 = s[0] & notThreeBlock;
            auto ss1 = s[1] & notThreeBlock;

            aes0.ecbEncBlock(ss0, si[0][0]);
            aes1.ecbEncBlock(ss0, si[0][1]);
            aes0.ecbEncBlock(ss1, si[1][0]);
            aes1.ecbEncBlock(ss1, si[1][1]);
            si[0][0] = si[0][0] ^ ss0;
            si[0][1] = si[0][1] ^ ss0;
            si[1][0] = si[1][0] ^ ss1;
            si[1][1] = si[1][1] ^ ss1;



            std::array<block, 2> siXOR{ si[0][0] ^ si[1][0], si[0][1] ^ si[1][1] };

            //std::cout << "s0*[" << i << "]    " << stt(si[0][0]) << " " << stt(si[0][1]) << std::endl;
            //std::cout << "s1*[" << i << "]    " << stt(si[1][0]) << " " << stt(si[1][1]) << std::endl;

            // get the left and right t_CW bits
            std::array<block, 2> t{
                (OneBlock & siXOR[0]) ^ a ^ OneBlock,
                (OneBlock & siXOR[1]) ^ a };

            // take scw to be the bits [127, 2] as scw = s0_loss ^ s1_loss
            auto scw = siXOR[keep ^ 1] & notThreeBlock;

            //std::cout << "scw[" << i << "]    " << stt(scw) << std::endl;
            //std::cout << "tL[" << i << "]     " << t1(t[0]) << std::endl;
            //std::cout << "tR[" << i << "]     " << t1(t[1]) << std::endl;

            k0[i + 1] = k1[i + 1] = scw              // set bits [127, 2] as scw = s0_loss ^ s1_loss
                ^ (t[0] << 1) // set bit 1 as tL
                ^ t[1];          // set bit 0 as tR

            //std::cout << "CW[" << i << "]     " << stt(k0[i + 1]) << std::endl;

            // get the the conditional XOR bits t^L_CW, t^R_CW
            auto ti0 = *(u8 *)&s[0] & 1;
            auto ti1 = *(u8 *)&s[1] & 1;

            auto si0Keep = si[0][keep];
            auto si1Keep = si[1][keep];

            // extract the t^Keep_CW bit
            auto TKeep = t[keep];

            // set the next level of s,t
            s[0] = si0Keep ^ (zeroAndAllOne[ti0] & (scw ^ TKeep));
            s[1] = si1Keep ^ (zeroAndAllOne[ti1] & (scw ^ TKeep));

            //std::cout << "s0[" << i + 1 << "]     " << stt(s[0]) << std::endl;
            //std::cout << "s1[" << i + 1 << "]     " << stt(s[1]) << std::endl;
        }

        std::vector<block> temp(g0.size() * 4);
        auto s0 = temp.data();
        auto s1 = temp.data() + g0.size();
        auto gs0 = temp.data() + g0.size() * 2;
        auto gs1 = temp.data() + g0.size() * 3;

        for (u64 i = 0; i < u64(g0.size()); ++i)
        {
            s0[i] = (s[0] & notThreeBlock) ^ toBlock(i);
            s1[i] = (s[1] & notThreeBlock) ^ toBlock(i);
        }
        aes0.ecbEncBlocks(s0, g0.size() * 2, gs0);
        for (u64 i = 0; i < u64(g0.size()); ++i)
        {
            gs0[i] = (gs0[i] ^ s0[i]);
            gs1[i] = (gs1[i] ^ s1[i]);
        }
        //std::cout << "gs0 " << gs0[0] /*<< " " << gs0[1]*/ << " = G(" << s0[0] /*<< " " << s0[1]*/ << ")" << std::endl;
        //std::cout << "gs1 " << gs1[0] /*<< " " << gs1[1]*/ << " = G(" << s1[0] /*<< " " << s1[1]*/ << ")" << std::endl;
        for (u64 i = 0; i < u64(g0.size()); ++i)
        {
            gs0[i] = gs0[i] ^ gs1[i];
        }

        u64 byteIdx = gIdx % 16 + 16 * (gIdx / 128);
        u64 bitIdx = (gIdx % 128) / 16;
        //std::cout << "cw " << gs0[0] << " " << gs0[1] << std::endl;

        auto u8View = (u8*)gs0;
        u8View[byteIdx] = u8View[byteIdx] ^ (u8(1) << bitIdx);


        //std::cout << "cw' " << gs0[0] <<  " " << gs0[1] << std::endl;
        //std::cout << "byte " << byteIdx << " bit " << bitIdx << std::endl;

        memcpy(g0.data(), u8View, g0.size() * sizeof(block));
        memcpy(g1.data(), u8View, g1.size() * sizeof(block));
    }
}
