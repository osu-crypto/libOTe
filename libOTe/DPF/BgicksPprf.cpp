#include "BgicksPprf.h"

#include <cryptoTools/Common/Log.h>

namespace osuCrypto
{
    BgicksMultiPprfSender::BgicksMultiPprfSender(u64 domainSize, u64 pointCount)
    {
        configure(domainSize, pointCount);
    }
    void BgicksMultiPprfSender::configure(u64 domainSize, u64 pointCount)
    {
        mDomain = domainSize;
        mDepth = log2ceil(mDomain);
        mPntCount = pointCount;
        mPntCount8 = roundUpTo(pointCount, 8);

        if (mBaseOTs.size() != baseOtCount())
            mBaseOTs.resize(0);
    }

    void BgicksMultiPprfReceiver::configure(u64 domainSize, u64 pointCount)
    {
        mDomain = domainSize;
        mDepth = log2ceil(mDomain);
        mPntCount = pointCount;
        mPntCount8 = roundUpTo(pointCount, 8);

        if (mBaseOTs.size() != baseOtCount())
            mBaseOTs.resize(0);
    }

    u64 BgicksMultiPprfSender::baseOtCount() const
    {
        return mDepth * mPntCount;
    }
    u64 BgicksMultiPprfReceiver::baseOtCount() const
    {
        return mDepth * mPntCount;
    }

    bool BgicksMultiPprfSender::hasBaseOts() const
    {
        return mBaseOTs.size();
    }
    bool BgicksMultiPprfReceiver::hasBaseOts() const
    {
        return mBaseOTs.size();
    }
    void BgicksMultiPprfSender::setBase(span<std::array<block, 2>> baseMessages)
    {
        if (baseOtCount() != baseMessages.size())
            throw RTE_LOC;

        mBaseOTs.resize(0);
        mBaseOTs.reserve(baseMessages.size());
        mBaseOTs.insert(mBaseOTs.end(), baseMessages.begin(), baseMessages.end());
    }
    void BgicksMultiPprfReceiver::setBase(span<block> baseMessages, BitVector & choices)
    {
        if (baseOtCount() != baseMessages.size())
            throw RTE_LOC;

        if (baseOtCount() != choices.size())
            throw RTE_LOC;

        mBaseOTs.resize(0);
        mBaseOTs.reserve(baseMessages.size());
        mBaseOTs.insert(mBaseOTs.end(), baseMessages.begin(), baseMessages.end());
        mBaseChoices = choices;
    }

    void BgicksMultiPprfSender::expand(Channel & chl, block value, PRNG & prng, MatrixView<block> output)
    {
        setValue(value);

        if (output.rows() != mDomain)
            throw RTE_LOC;

        if (output.cols() != mPntCount)
            throw RTE_LOC;


        std::array<Matrix<block>, 2> sums;
        sums[0].resize(mDepth, mPntCount8);
        sums[1].resize(mDepth, mPntCount8);


        std::vector<block> tree((1 << (mDepth + 1)) * mPntCount8);
        auto getLevel = [&](u64 i)
        {
            //if (i == mDepth)
            //{
            //    return span<block>(output.data(), output.size());
            //}
            auto size = (1ull << i);
            auto offset = (size - 1);

            auto b = tree.begin() + offset * mPntCount8;
            auto e = b + size * mPntCount8;
            return span<block>(b, e);
        };

        std::array<AES, 2> aes;
        aes[0].setKey(toBlock(3242342));
        aes[1].setKey(toBlock(8993849));
        prng.get(getLevel(0));

        auto print = [](span<block> b)
        {
            std::stringstream ss;
            if (b.size())
                ss << b[0];
            for (u64 i = 1; i < b.size(); ++i)
            {
                ss << ", " << b[i];
            }
            return ss.str();
        };


        for (u64 d = 0; d < mDepth; ++d)
        {
            auto level0 = getLevel(d);
            auto level1 = getLevel(d + 1);

            auto width = level1.size() / mPntCount8;

            for (u64 i = 0; i < width; ++i)
            {
                u8 keep = i & 1;
                auto i0 = i >> 1;
                auto& a = aes[keep];
                auto td = level0.subspan(i0 * mPntCount8, mPntCount8);
                auto td1 = level1.subspan(i * mPntCount8, mPntCount8);
                auto sum = sums[keep][d];

                // hash the current node td and store the result in td1.
                for (u64 j = 0; j < mPntCount8; j += 8)
                {
                    auto sub = td.subspan(j, 8);
                    auto sub1 = td1.subspan(j, 8);
                    auto s = sum.subspan(j, 8);

                    // H(x) = AES(k[keep], x) + x;
                    a.ecbEncBlocks(sub.data(), 8, sub1.data());
                    sub1[0] = sub1[0] ^ sub[0];
                    sub1[1] = sub1[1] ^ sub[1];
                    sub1[2] = sub1[2] ^ sub[2];
                    sub1[3] = sub1[3] ^ sub[3];
                    sub1[4] = sub1[4] ^ sub[4];
                    sub1[5] = sub1[5] ^ sub[5];
                    sub1[6] = sub1[6] ^ sub[6];
                    sub1[7] = sub1[7] ^ sub[7];

                    //if (d == 1 && i == 0)
                    //{
                    //    std::cout << "r[" << (d) << "] = " << sub[2] << " -> r[" << (d + 1) << "] = " << sub1[2] << std::endl;
                    //}

                    // sum += H(x)
                    s[0] = s[0] ^ sub1[0];
                    s[1] = s[1] ^ sub1[1];
                    s[2] = s[2] ^ sub1[2];
                    s[3] = s[3] ^ sub1[3];
                    s[4] = s[4] ^ sub1[4];
                    s[5] = s[5] ^ sub1[5];
                    s[6] = s[6] ^ sub1[6];
                    s[7] = s[7] ^ sub1[7];
                }
            }
            //std::cout << "s lvl[" << (d + 1) << "] " << print(getLevel(d + 1)) << std::endl;
            //std::cout << "sum0 [" << (d + 1) << "] " << print(sums[0][d]) << std::endl;
            //std::cout << "sum1 [" << (d + 1) << "] " << print(sums[1][d]) << std::endl;
        }


        chl.send(tree);


        for (u64 i = 0; i < mDepth - 1; ++i)
        {
            for (u64 j = 0; j < mPntCount; ++j)
            {
                auto idx = i * mPntCount + j;
                //u8 bit = permute[idx];

                sums[0](i, j) = sums[0](i, j) ^ mBaseOTs[idx][0];
                sums[1](i, j) = sums[1](i, j) ^ mBaseOTs[idx][1];
            }
        }


        auto i = mDepth - 1;
        std::vector<std::array<block, 4>> lastOts(mPntCount);
        for (u64 j = 0; j < mPntCount; ++j)
        {
            auto idx = i * mPntCount + j;
            //u8 bit = permute[idx];

            lastOts[j][0] = sums[0](i, j);
            lastOts[j][1] = sums[1](i, j) ^ mValue;
            lastOts[j][2] = sums[1](i, j);
            lastOts[j][3] = sums[0](i, j) ^ mValue;

            std::array<block, 4> masks, maskIn;

            maskIn[0] = mBaseOTs[idx][0];
            maskIn[1] = mBaseOTs[idx][0] ^ AllOneBlock;
            maskIn[2] = mBaseOTs[idx][1];
            maskIn[3] = mBaseOTs[idx][1] ^ AllOneBlock;

            mAesFixedKey.ecbEncFourBlocks(maskIn.data(), masks.data());
            masks[0] = masks[0] ^ maskIn[0];
            masks[1] = masks[1] ^ maskIn[1];
            masks[2] = masks[2] ^ maskIn[2];
            masks[3] = masks[3] ^ maskIn[3];

            //std::cout << "sum[" << j << "][0] " << lastOts[j][0] << " " << lastOts[j][1] << std::endl;
            //std::cout << "sum[" << j << "][1] " << lastOts[j][2] << " " << lastOts[j][3] << std::endl;

            lastOts[j][0] = lastOts[j][0] ^ masks[0];
            lastOts[j][1] = lastOts[j][1] ^ masks[1];
            lastOts[j][2] = lastOts[j][2] ^ masks[2];
            lastOts[j][3] = lastOts[j][3] ^ masks[3];
        }

        sums[0].resize(mDepth - 1, mPntCount8);
        sums[1].resize(mDepth - 1, mPntCount8);

        chl.asyncSend(std::move(sums[0]));
        chl.asyncSend(std::move(sums[1]));
        chl.asyncSend(std::move(lastOts));


        memcpy(output.data(), getLevel(mDepth).data(), output.size() * sizeof(block));

    }

    void BgicksMultiPprfSender::setValue(block value)
    {
        mValue = value;
    }

    void BgicksMultiPprfReceiver::expand(Channel & chl, span<u64> points, PRNG & prng, MatrixView<block> output)
    {

        if (output.rows() != mDomain)
            throw RTE_LOC;

        if (output.cols() != mPntCount)
            throw RTE_LOC;


        memset(points.data(), 0, points.size() * sizeof(u64));
        for (u64 i = 0; i < mDepth; ++i)
        {
            auto shift = mDepth - i - 1;
            for (u64 j = 0; j < mPntCount; ++j)
            {
                auto idx = i * mPntCount + j;
                points[j] |= u64(1 ^ mBaseChoices[idx]) << shift;
            }
        }
        for (u64 j = 0; j < mPntCount; ++j)
            std::cout << "point[" << j << "] " << points[j] << std::endl;

        std::array<std::vector<block>, 2> mySums;
        mySums[0].resize(mPntCount8);
        mySums[1].resize(mPntCount8);

        std::array<AES, 2> aes;
        aes[0].setKey(toBlock(3242342));
        aes[1].setKey(toBlock(8993849));



        std::vector<block> tree((1 << mDepth) * mPntCount8);
        std::vector<block> ftree((1 << mDepth) * mPntCount8);
        chl.recv(ftree);

        auto getLevel = [&](u64 i, bool f = false)
        {
            if (i == mDepth && f == false)
            {
                return span<block>(output.data(), output.size());
            }
            auto size = (1ull << i);
            auto offset = (size - 1);

            auto b = (f ? ftree.begin() : tree.begin()) + offset * mPntCount8;
            auto e = b + size * mPntCount8;
            return span<block>(b, e);
        };


        std::array<Matrix<block>, 2> sums;
        sums[0].resize(mDepth - 1, mPntCount8);
        sums[1].resize(mDepth - 1, mPntCount8);

        chl.recv(sums[0]);
        chl.recv(sums[1]);

        auto l1 = getLevel(1);
        auto l1f = getLevel(1, true);
        for (u64 i = 0; i < mPntCount; ++i)
        {
            u8 notAi = mBaseChoices[i];
            auto idx = i + notAi * mPntCount8;
            l1[idx] = mBaseOTs[i] ^ sums[notAi](i);
            //auto idxn = i + (notAi^1) * mPntCount8;
            //l1[idxn] = mBaseOTs[i] ^ sums[notAi^1](i);

            //std::cout << "l1[" << idx << "] " << l1[idx] << " = "
            //    << mBaseOTs[i] << " ^ "
            //    << sums[notAi](i) << " vs " << l1f[idx] << std::endl;

        }
        //std::cout << std::endl;
        //Matrix<block> fullTree(mDepth, mDomain);


        auto printLevel = [&](u64 d)
        {

            auto level0 = getLevel(d);
            auto flevel0 = getLevel(d, true);

            std::cout
                << "---------------------\nlevel " << d
                << "\n---------------------" << std::endl;

            std::array<block, 2> sums{ ZeroBlock ,ZeroBlock };
            for (u64 i = 0; i < level0.size(); ++i)
            {
                if (neq(level0[i], flevel0[i]))
                    std::cout << Color::Red;

                auto i0 = (i / mPntCount8);
                auto i1 = (i % mPntCount8);
                std::cout << "p[" << i0 << "][" << i1 << "] "
                    << level0[i] << " " << flevel0[i] << std::endl << Color::Default;

                if(i1 ==0)
                    sums[i0 & 1] = sums[i0 & 1] ^ flevel0[i];
            }

            std::cout << "sums[0] = " << sums[0] << " " << sums[1] << std::endl;
        };
        printLevel(1);

        for (u64 d = 1; d < mDepth; ++d)
        {
            auto level0 = getLevel(d);
            auto level1 = getLevel(d + 1);


            auto width = level1.size() / mPntCount8;
            memset(mySums[0].data(), 0, mySums[0].size() * sizeof(block));
            memset(mySums[1].data(), 0, mySums[1].size() * sizeof(block));

            for (u64 i = 0; i < width; ++i)
            {
                u8 keep = i & 1;
                auto i0 = i >> 1;
                auto& a = aes[keep];
                auto td = level0.subspan(i0 * mPntCount8, mPntCount8);
                auto td1 = level1.subspan(i * mPntCount8, mPntCount8);

                auto& sum = mySums[keep];


                //auto _td = &level0[i0 + mPntCount8 - 1];
                //auto _td1 = &level1[i + mPntCount8 - 1];

                // hash the current node td and store the result in td1.
                for (u64 j = 0; j < mPntCount8; j += 8)
                {
                    auto sub = td.subspan(j, 8);
                    auto sub1 = td1.subspan(j, 8);

                    // H(x) = AES(k[keep], x) + x;
                    a.ecbEncBlocks(sub.data(), 8, sub1.data());
                    sub1[0] = sub1[0] ^ sub[0];
                    sub1[1] = sub1[1] ^ sub[1];
                    sub1[2] = sub1[2] ^ sub[2];
                    sub1[3] = sub1[3] ^ sub[3];
                    sub1[4] = sub1[4] ^ sub[4];
                    sub1[5] = sub1[5] ^ sub[5];
                    sub1[6] = sub1[6] ^ sub[6];
                    sub1[7] = sub1[7] ^ sub[7];


                    for (u64 i = 0; i < 8; ++i)
                        if (eq(sub[i], ZeroBlock))
                            sub1[i] = ZeroBlock;
                    // sum += H(x)
                    sum[j + 0] = sum[j + 0] ^ sub1[0];
                    sum[j + 1] = sum[j + 1] ^ sub1[1];
                    sum[j + 2] = sum[j + 2] ^ sub1[2];
                    sum[j + 3] = sum[j + 3] ^ sub1[3];
                    sum[j + 4] = sum[j + 4] ^ sub1[4];
                    sum[j + 5] = sum[j + 5] ^ sub1[5];
                    sum[j + 6] = sum[j + 6] ^ sub1[6];
                    sum[j + 7] = sum[j + 7] ^ sub1[7];
                }
            }



            if (d != mDepth - 1)
            {

                for (u64 i = 0; i < mPntCount; ++i)
                {
                    auto a = points[i] >> (mDepth - 1 - d);
                    auto notAi = (a & 1) ^ 1;
                    auto idx = (a ^ 1) * mPntCount + i;

                    auto prev = level1[idx];
                    //level1[a] = CCBlock;
                    level1[idx] =
                        level1[idx] ^
                        sums[notAi](d, i) ^
                        mySums[notAi][i] ^
                        mBaseOTs[d * mPntCount + i]; 
                    std::cout << "up[" << i << "] = level1[" << (idx / mPntCount8) << "][" << (idx % mPntCount8) << "] "
                        << prev << " -> " << level1[idx] << " " << a << " "<< idx << std::endl;
                }

                printLevel(d + 1);
            }


            //std::cout << "r[" << (d + 1) << "] " << level1[0] << std::endl;
        }
        //printLevel(mDepth);


        std::vector<std::array<block, 4>> lastOts(mPntCount);
        chl.recv(lastOts);

        auto level = getLevel(mDepth);
        //auto flevel = getLevel(mDepth, true);
        auto d = mDepth - 1;
        for (u64 j = 0; j < mPntCount; ++j)
        {

            auto a = points[j];
            auto notAi = (a & 1) ^ 1;
            auto idx = (a ^ 1) * mPntCount + j;
            auto idx1 = a * mPntCount + j;

            //auto idx = i * mPntCount + j;

            //lastOts[j][0] = sums[0](i, j);
            //lastOts[j][1] = sums[1](i, j);
            //lastOts[j][3] = sums[0](i, j);
            //lastOts[j][2] = sums[1](i, j);

            std::array<block, 2> masks, maskIn;

            maskIn[0] = mBaseOTs[d * mPntCount + j];
            maskIn[1] = mBaseOTs[d * mPntCount + j] ^ AllOneBlock;

            mAesFixedKey.ecbEncTwoBlocks(maskIn.data(), masks.data());
            masks[0] = masks[0] ^ maskIn[0];
            masks[1] = masks[1] ^ maskIn[1];

            auto& ot0 = lastOts[j][2 * notAi + 0];
            auto& ot1 = lastOts[j][2 * notAi + 1];

            ot0 = ot0 ^ masks[0];
            ot1 = ot1 ^ masks[1];
            auto prev = level[idx];

            mySums[notAi][j] = mySums[notAi][j] ^ level[idx];
            mySums[notAi ^ 1][j] = mySums[notAi^ 1][j] ^ level[idx1];

            level[idx]  = ot0 ^ mySums[notAi][j];
            level[idx1] = ot1 ^ mySums[notAi ^ 1][j];


            //std::cout << "up[" << d << "] = level1[" << (idx / mPntCount8) << "][" << (idx % mPntCount8) << " "
            //    << prev << " -> " << level[idx] << std::endl;

            //std::cout << "    " << ot0 << " ^ " << (mySums[notAi][j] ^ flevel[idx]) << std::endl;
            //std::cout << "    " << (ot0^mySums[notAi][j]) << " ^ " << (flevel[idx]) << std::endl;
        }

        printLevel(mDepth);

    }

}

//while (leafIdx != mDomain)
//{
//    // for the current leaf index, traverse to the leaf.
//    while (d != mDepth)
//    {

//        auto level0 = getLevel(d);
//        auto level1 = getLevel(d + 1);

//        // for our current position, are we going left or right?
//        auto pIdx = (leafIdx >> (mDepth - 1 - d));
//        u8 keep = pIdx & 1;

//        auto& a = aes[keep];
//        auto td = tree[d];
//        auto td1 = tree[d + 1];
//        auto sum = &sums[keep](d, 0);

//        auto td_ = level0.subspan(pIdx >>1, mPntCount8);
//        auto td1_ = level1.subspan(pIdx, mPntCount8);

//        ++d;

//        // hash the current node td and store the result in td1.
//        for (u64 i = 0; i < mPntCount8; i += 8)
//        {
//            auto sub = td.subspan(i, 8);
//            auto sub1 = td1.subspan(i, 8);
//            auto sub1_ = td1_.subspan(i, 8);

//            // H(x) = AES(k[keep], x) + x;
//            a.ecbEncBlocks(sub.data(), 8, td1.data());


//            sub1[0] = sub1[0] ^ sub[0];
//            sub1[1] = sub1[1] ^ sub[1];
//            sub1[2] = sub1[2] ^ sub[2];
//            sub1[3] = sub1[3] ^ sub[3];
//            sub1[4] = sub1[4] ^ sub[4];
//            sub1[5] = sub1[5] ^ sub[5];
//            sub1[6] = sub1[6] ^ sub[6];
//            sub1[7] = sub1[7] ^ sub[7];

//            sub1_[0] = sub1[0];
//            sub1_[1] = sub1[1];
//            sub1_[2] = sub1[2];
//            sub1_[3] = sub1[3];
//            sub1_[4] = sub1[4];
//            sub1_[5] = sub1[5];
//            sub1_[6] = sub1[6];
//            sub1_[7] = sub1[7];
//                             
//            // sum += H(x)
//            sum[i + 0] = sum[i + 0] ^ sub1[0];
//            sum[i + 1] = sum[i + 1] ^ sub1[1];
//            sum[i + 2] = sum[i + 2] ^ sub1[2];
//            sum[i + 3] = sum[i + 3] ^ sub1[3];
//            sum[i + 4] = sum[i + 4] ^ sub1[4];
//            sum[i + 5] = sum[i + 5] ^ sub1[5];
//            sum[i + 6] = sum[i + 6] ^ sub1[6];
//            sum[i + 7] = sum[i + 7] ^ sub1[7];
//        }
//    }


//    auto td1 = &tree(d, 0);
//    memcpy(output[leafIdx].data(), td1, mPntCount * sizeof(block));

//    u64 shift = (leafIdx + 1) ^ leafIdx;
//    d -= log2floor(shift) + 1;
//    ++leafIdx;
//}
