#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <boost/multiprecision/cpp_int.hpp>

namespace osuCrypto
{
    class BgiPirClient
    {
    public:
        typedef boost::multiprecision::uint128_t uint128_t;

        static uint128_t bytesToUint128_t(const span<u8>& data);

        u64 mDatasetSize;
        u64 mKDepth, mGroupBlkSize;

        void init(u64 dataSetSize, u64 groupByteSize);
        block query(span<u8> idx, Channel srv0, Channel Srv1, block seed);
        block query(uint128_t idx, Channel srv0, Channel Srv1, block seed);

        static void keyGen(span<u8> idx, block seed, span<block> k0, span<block> g0, span<block> k1, span<block> g1);
        static void keyGen(uint128_t idx, block seed, span<block> k0, span<block> g0, span<block> k1, span<block> g1);
    };

}