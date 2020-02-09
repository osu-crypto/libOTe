#include "LinearCode.h"
#include <fstream>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#define BITSET
#include <bitset>
#include <iomanip>

#include <cryptoTools/Common/MatrixView.h>
namespace osuCrypto
{
    // must be a multiple of 8...
    const u16 LinearCode::sLinearCodePlainTextMaxSize(64);

    LinearCode::LinearCode()
    {
    }

    LinearCode::~LinearCode()
    {
    }

    LinearCode::LinearCode(const LinearCode &cp)
        :
        mU8RowCount(cp.mU8RowCount),
        mPow2CodeSize(cp.mPow2CodeSize),
        mPlaintextU8Size(cp.mPlaintextU8Size),
        mCodewordBitSize(cp.mCodewordBitSize),
        mG(cp.mG),
        mG8(cp.mG8)
    {
    }

    void LinearCode::loadTxtFile(const std::string & fileName)
    {
        std::ifstream in;
        in.open(fileName, std::ios::in);

        if (in.is_open() == false)
        {
            std::cout << "failed to open:\n     " << fileName << std::endl;
            throw std::runtime_error(LOCATION);
        }

        loadTxtFile(in);
    }

    void LinearCode::loadTxtFile(std::istream & in)
    {
        u64 numRows, numCols;
        in >> numRows >> numCols;
        mCodewordBitSize = numCols;

        mG.resize(numRows * ((numCols + 127) / 128));
        //mG1.resize(numRows * ((numCols + 127) / 128));

        auto iter = mG.begin();
        //auto iter1 = mG1.begin();

        BitVector buff;
        buff.reserve(roundUpTo(numCols, 128));
        buff.resize(numCols);

        //u32 v;
        std::string line;
        std::getline(in, line);

        for (u64 i = 0; i < numRows; ++i)
        {
            memset(buff.data(), 0, buff.sizeBytes());
            std::getline(in, line);

#ifndef NDEBUG
            if (line.size() != 2 * numCols - 1)
                throw std::runtime_error("");
#endif
            for (u64 j = 0; j < numCols; ++j)
            {

#ifndef NDEBUG
                if (line[j * 2] - '0' > 1)
                    throw std::runtime_error("");
#endif
                buff[j] = line[j * 2] - '0';;
            }

            block* blkView = (block*)buff.data();
            for (u64 j = 0, k = 0; j < numCols; j += 128, ++k)
            {
                *iter++ = blkView[k];
            }
        }


        generateMod8Table();
    }

    void LinearCode::load(const unsigned char * data, u64 size)
    {
        std::stringstream ss(std::stringstream::out | std::stringstream::in | std::stringstream::binary);
        ss.write((char*)data, size);
        loadBinFile(ss);
    }

    void LinearCode::writeTextFile(const std::string & fileName)
    {
        std::fstream out;
        out.open(fileName, std::ios::out | std::ios::binary | std::ios::trunc);

        writeTextFile(out);
    }

    void LinearCode::writeTextFile(std::ostream & out)
    {
        out << plaintextBitSize() << " " << codewordBitSize() << "\n";


        for (u64 row = 0; row < plaintextBitSize(); ++row)
        {
            BitIterator iter((u8*)(mG.data() + row * codewordBlkSize()), 0);

            for (u64 col = 0; col < codewordBitSize() - 1; ++col)
            {
                out << *iter++ << " ";
            }

            if (iter.mByte > (u8*)(mG.data() + mG.size()))
                throw std::runtime_error(LOCATION);

            out << *iter << "\n";
        }
    }

    void LinearCode::loadBinFile(const std::string & fileName)
    {
        std::fstream in;
        in.open(fileName, std::ios::in | std::ios::binary);


        if (in.is_open() == false)
        {
            std::cout << "failed to open:\n     " << fileName << std::endl;
            throw std::runtime_error(LOCATION);
        }

        loadBinFile(in);

    }
    void LinearCode::loadBinFile(std::istream & out)
    {

        u64 size = 0;

        out.read((char *)&size, sizeof(u64));
        out.read((char *)&mCodewordBitSize, sizeof(u64));

        if (mCodewordBitSize == 0)
        {
            std::cout << "bad code " << std::endl;
            throw std::runtime_error(LOCATION);
        }

        mG.resize(size);

        out.read((char *)mG.data(), mG.size() * sizeof(block));

        generateMod8Table();

    }

    void LinearCode::writeBinFile(const std::string & fileName)
    {
        std::fstream out;
        out.open(fileName, std::ios::out | std::ios::binary | std::ios::trunc);

        writeBinFile(out);
    }

    void LinearCode::writeBinCppFile(const std::string & fileName, const std::string & name)
    {
        std::stringstream out(std::ios::out | std::ios::in | std::ios::binary);
        writeBinFile(out);

        std::fstream fOut;
        fOut.open(fileName, std::ios::out | std::ios::trunc);

        int c = 0;
        out.read((char*)&c, 1);
        fOut << "static unsigned char "<< name << "[] = { 0x" << std::hex << std::setw(2) << std::setfill('0') << c;

        while (true)
        {
            out.read((char*)&c, 1);

            if (out.eof() == false)
                fOut << ", 0x" << std::hex << std::setw(2) << std::setfill('0') << c;
            else
                break;
        }

        fOut << " };";
    }
    void LinearCode::writeBinFile(std::ostream & out)
    {
        u64 size = mG.size();
        out.write((const char *)&size, sizeof(u64));
        out.write((const char *)&mCodewordBitSize, sizeof(u64));

        out.write((const char *)mG.data(), mG.size() * sizeof(block));
    }



    void LinearCode::random(PRNG & prng, u64 inputSize, u64 outputSize)
    {
        mCodewordBitSize = outputSize;
        mG.resize(inputSize * codewordBlkSize());

        prng.get(mG.data(), mG.size());

        generateMod8Table();

    }

    void LinearCode::generateMod8Table()
    {
        mPlaintextU8Size = (plaintextBitSize() + 7) / 8;

        if (plaintextU8Size() > sLinearCodePlainTextMaxSize)
        {
            std::cout << "The encode function assumes that the plaintext word"
                " size is less than " << sLinearCodePlainTextMaxSize << ". If"
                " this is not the case, raise the limit" << std::endl;
            throw std::runtime_error(LOCATION);
        }

        auto singleRowCount = plaintextBitSize();
        auto mod8RowCount = (singleRowCount + 7) / 8;
        auto pipelinedMod8RowCount = roundUpTo(mod8RowCount, 8);

        switch (codewordBlkSize())
        {
        case 3:
            mPow2CodeSize = 4;
            break;
        case 5:
        case 6:
        case 7:
            mPow2CodeSize = 8;
            break;
        default:
            // after size 8, we just go back to the general algorithm
            mPow2CodeSize = codewordBlkSize();
            break;
        }

        auto sizePerMod8Row = mPow2CodeSize * 256;

        auto yy = pipelinedMod8RowCount * sizePerMod8Row;

        mG8.resize(yy);


        mU8RowCount = (plaintextBitSize() + 7) / 8;
        //mC.resize(8 * codewordBlkSize());

        memset(mG8.data(), 0, mG8.size() * sizeof(block));

        MatrixView<block> g(mG.begin(), mG.end(), codewordBlkSize());
        MatrixView<block> g8(mG8.begin(), mG8.end(), mPow2CodeSize * 256);


        for (u64 i = 0; i < g8.bounds()[0]; ++i)
        {
            auto vv = g8[i];
            MatrixView<block> g8Block(vv.begin(), vv.end(), mPow2CodeSize);

            for (u64 gRow = 0; gRow < 8; ++gRow)
            {
                u64 g8Row = (u64(1) << gRow);
                u64 stride = g8Row;

                while (g8Row < 256)
                {
                    do
                    {
                        if (i * 8 + gRow < g.bounds()[0])
                        {

                            for (u64 wordIdx = 0; wordIdx < codewordBlkSize(); ++wordIdx)
                            {
                                g8Block[g8Row][wordIdx]
                                    = g8Block[g8Row][wordIdx]
                                    ^ g[i * 8 + gRow][wordIdx];
                            }
                        }

                        ++g8Row;
                    } while (g8Row % stride);

                    g8Row += stride;
                }
            }
        }
    }



    static std::array<block, 2> sBlockMasks{ { ZeroBlock, AllOneBlock } };

    void LinearCode::encode(
        const span<block>& plaintxt,
        const span<block>& codeword)
    {
#ifndef NDEBUG
        if (static_cast<u64>(plaintxt.size()) != plaintextBlkSize() ||
            static_cast<u64>(codeword.size()) < codewordBlkSize())
            throw std::runtime_error(LOCATION);
#endif

        //span<u8> pp((u8*)plaintxt.data(), plaintextU8Size(), false);
        //span<u8> cc((u8*)codeword.data(), codewordU8Size(), false);
        //encode(pp, cc);
        encode((u8*)plaintxt.data(), (u8*)codeword.data());
        //
        //        std::array<block, 8>
        //            c{ ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock,ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock };
        //
        //
        //        // highlevel idea: For each byte of the input, we have preprocessed 
        //        // the corresponding partial code. That is, we have many sub-codes
        //        // each with input size 8. And these subcodes are precomputed
        //        // in a lookup table called mG8. Each sub-code takes up 256 * codeSize;
        //
        //        u64 codeSize = codewordBlkSize();
        //        u64 rowSize = 256 * codeSize;
        //        u8* byteView = (u8*)plaintxt.data();
        //
        //        if (codeSize == 4)
        //        {
        //            u64 kStop = (mG8.size() / 8) * 8,
        //                k = 0,
        //                i = 0;
        //
        //            // this case has been optimized and we lookup two sub-codes at a time.
        //            u64 byteStep = 2;
        //            u64 kStep = rowSize * byteStep;
        //            for (; k < kStop; i += byteStep, k += kStep)
        //            {
        //                block* g0 = mG8.data() + k + byteView[i] * codeSize;
        //                block* g1 = mG8.data() + k + byteView[i + 1] * codeSize + rowSize;
        //#ifndef NDEBUG
        //                if (g1 >= mG8.data() + mG8.size())throw std::runtime_error("");
        //#endif
        //                c[0] = c[0] ^ g0[0];
        //                c[1] = c[1] ^ g0[1];
        //                c[2] = c[2] ^ g0[2];
        //                c[3] = c[3] ^ g0[3];
        //
        //                c[4] = c[4] ^ g1[0];
        //                c[5] = c[5] ^ g1[1];
        //                c[6] = c[6] ^ g1[2];
        //                c[7] = c[7] ^ g1[3];
        //            }
        //
        //            codeword[0] = c[0] ^ c[4];
        //            codeword[1] = c[1] ^ c[5];
        //            codeword[2] = c[2] ^ c[6];
        //            codeword[3] = c[3] ^ c[7];
        //
        //        }
        //        else
        //        {
        //            u64 rowCount = (plaintextBitSize() + 7) / 8;
        //            u64 superRowCount = rowCount / 8;
        //
        //            for (u64 j = 0; j < codeSize; ++j)
        //            {
        //                for (u64 i = 0; i < 8; ++i)
        //                    c[i] = ZeroBlock;
        //
        //                for (u64 i = 0; i < superRowCount; ++i)
        //                {
        //
        //                    block* g0 = mG8.data() + j + byteView[i + 0] * codeSize + rowSize * 0;
        //                    block* g1 = mG8.data() + j + byteView[i + 1] * codeSize + rowSize * 1;
        //                    block* g2 = mG8.data() + j + byteView[i + 2] * codeSize + rowSize * 2;
        //                    block* g3 = mG8.data() + j + byteView[i + 3] * codeSize + rowSize * 3;
        //                    block* g4 = mG8.data() + j + byteView[i + 4] * codeSize + rowSize * 4;
        //                    block* g5 = mG8.data() + j + byteView[i + 5] * codeSize + rowSize * 5;
        //                    block* g6 = mG8.data() + j + byteView[i + 6] * codeSize + rowSize * 6;
        //                    block* g7 = mG8.data() + j + byteView[i + 7] * codeSize + rowSize * 7;
        //#ifndef NDEBUG
        //                    if (g7 >= mG8.data() + mG8.size())throw std::runtime_error("");
        //#endif
        //
        //                    c[0] = c[0] ^ *g0;
        //                    c[1] = c[1] ^ *g1;
        //                    c[2] = c[2] ^ *g2;
        //                    c[3] = c[3] ^ *g3;
        //                    c[4] = c[4] ^ *g4;
        //                    c[5] = c[5] ^ *g5;
        //                    c[6] = c[6] ^ *g6;
        //                    c[7] = c[7] ^ *g7;
        //                }     
        //
        //                codeword[j] = ZeroBlock;
        //                for (u64 i = 0; i < 8; ++i)
        //                    codeword[j] = codeword[j] ^ c[i];
        //            }
        //      
        //
        //
        //        }
        //
        //
    }


    void LinearCode::encode(
        const span<u8>& plaintxt,
        const span<u8>& codeword)
    {
#ifndef NDEBUG
        if (static_cast<u64>(plaintxt.size()) != plaintextU8Size() ||
            static_cast<u64>(codeword.size()) < codewordU8Size())
            throw std::runtime_error(LOCATION);
#endif
        encode(plaintxt.data(), codeword.data());
    }

    void LinearCode::encode(u8 * input, u8 * codeword)
    {

        // highlevel idea: For each byte of the input, we have preprocessed 
        // the corresponding partial code. That is, we have many sub-codes
        // each with input size 8. And these subcodes are precomputed
        // in a lookup table called mG8. Each sub-code takes up 256 * codeSize;

        const u64& codeSize = mPow2CodeSize;
        const u64 rowSize = 256 * codeSize;
        const u64 rowSize8 = rowSize * 8;
        const u64 superRowCount = (mU8RowCount + 7) / 8;

        // in some cases below, the input array must be a
        // multiple of 8 in length...
        u8 _byteView[sLinearCodePlainTextMaxSize];
        u8* byteView = _byteView;
        memcpy(byteView, input, mPlaintextU8Size);


        // create a local to store the partial codeword
        // and zero it out.
        block c[8];
        c[0] = c[0] ^ c[0];
        c[1] = c[1] ^ c[1];
        c[2] = c[2] ^ c[2];
        c[3] = c[3] ^ c[3];
        c[4] = c[4] ^ c[4];
        c[5] = c[5] ^ c[5];
        c[6] = c[6] ^ c[6];
        c[7] = c[7] ^ c[7];

        // for performance reasons, we have multiplt implementations, one for
        // each size under 9 blocks wide. There is a general case at the end.
        switch (codeSize)
        {
        case 1:
        {
            // this case has been optimized and we lookup 8 sub-codes at a time.
            static const u64 byteStep = 8;
            block* g0 = mG8.data() + rowSize * 0;// + k + byteView[i + 0] * codeSize + rowSize * 0;
            block* g1 = mG8.data() + rowSize * 1;// + k + byteView[i + 1] * codeSize + rowSize * 1;
            block* g2 = mG8.data() + rowSize * 2;// + k + byteView[i + 2] * codeSize + rowSize * 2;
            block* g3 = mG8.data() + rowSize * 3;// + k + byteView[i + 3] * codeSize + rowSize * 3;
            block* g4 = mG8.data() + rowSize * 4;// + k + byteView[i + 4] * codeSize + rowSize * 4;
            block* g5 = mG8.data() + rowSize * 5;// + k + byteView[i + 5] * codeSize + rowSize * 5;
            block* g6 = mG8.data() + rowSize * 6;// + k + byteView[i + 6] * codeSize + rowSize * 6;
            block* g7 = mG8.data() + rowSize * 7;// + k + byteView[i + 7] * codeSize + rowSize * 7;

            u64 kStep = rowSize * byteStep;
            for (u64 i = 0; i < mPlaintextU8Size; i += byteStep)
            {
                c[0] = c[0] ^ g0[byteView[i + 0] * codeSize];
                c[1] = c[1] ^ g1[byteView[i + 1] * codeSize];
                c[2] = c[2] ^ g2[byteView[i + 2] * codeSize];
                c[3] = c[3] ^ g3[byteView[i + 3] * codeSize];
                c[4] = c[4] ^ g4[byteView[i + 4] * codeSize];
                c[5] = c[5] ^ g5[byteView[i + 5] * codeSize];
                c[6] = c[6] ^ g6[byteView[i + 6] * codeSize];
                c[7] = c[7] ^ g7[byteView[i + 7] * codeSize];

                g0 += kStep;
                g1 += kStep;
                g2 += kStep;
                g3 += kStep;
                g4 += kStep;
                g5 += kStep;
                g6 += kStep;
                g7 += kStep;
            }

            c[0] = c[0] ^ c[4];
            c[1] = c[1] ^ c[5];
            c[2] = c[2] ^ c[6];
            c[3] = c[3] ^ c[7];

            c[0] = c[0] ^ c[2];
            c[1] = c[1] ^ c[3];

            c[0] = c[0] ^ c[1];

            memcpy(codeword, c, codewordU8Size());

            break;
        }
        case 2:
        {
            // this case has been optimized and we lookup 4 sub-codes at a time.
            static const u64 byteStep = 4;

            u64 kStop = (mG8.size() / 8) * 8;
            u64 kStep = rowSize * byteStep;
            for (u64 k = 0, i = 0; k < kStop; i += byteStep, k += kStep)
            {
                block* g0 = mG8.data() + k + byteView[i + 0] * codeSize + rowSize * 0;
                block* g1 = mG8.data() + k + byteView[i + 1] * codeSize + rowSize * 1;
                block* g2 = mG8.data() + k + byteView[i + 2] * codeSize + rowSize * 2;
                block* g3 = mG8.data() + k + byteView[i + 3] * codeSize + rowSize * 3;

                c[0] = c[0] ^ g0[0];
                c[1] = c[1] ^ g0[1];

                c[2] = c[2] ^ g1[0];
                c[3] = c[3] ^ g1[1];

                c[4] = c[4] ^ g2[0];
                c[5] = c[5] ^ g2[1];

                c[6] = c[6] ^ g3[0];
                c[7] = c[7] ^ g3[1];
            }

            c[0] = c[0] ^ c[4];
            c[1] = c[1] ^ c[5];
            c[2] = c[2] ^ c[6];
            c[3] = c[3] ^ c[7];

            c[0] = c[0] ^ c[2];
            c[1] = c[1] ^ c[3];

            memcpy(codeword, c, codewordU8Size());

            break;
        }
        case 3:
        case 4:
        {

            // this case has been optimized and we lookup 2 sub-codes at a time.
            static const u64 byteStep = 2;

            i32 kStop = static_cast<i32>(mG8.size() / 8) * 8;
            i32 kStep = static_cast<i32>(rowSize * byteStep);

            block* gg0 = mG8.data();
            block* gg1 = mG8.data() + rowSize;
            for (i32 k = 0; k < kStop; byteView += byteStep, k += kStep)
            {
                auto g0 = gg0 + byteView[0] * 4;
                auto g1 = gg1 + byteView[1] * 4;
                gg0 += kStep;
                gg1 += kStep;

                c[0] = c[0] ^ g0[0];
                c[1] = c[1] ^ g0[1];
                c[2] = c[2] ^ g0[2];
                c[3] = c[3] ^ g0[3];

                c[4] = c[4] ^ g1[0];
                c[5] = c[5] ^ g1[1];
                c[6] = c[6] ^ g1[2];
                c[7] = c[7] ^ g1[3];
            }

            c[0] = c[0] ^ c[4];
            c[1] = c[1] ^ c[5];
            c[2] = c[2] ^ c[6];
            c[3] = c[3] ^ c[7];

            memcpy(codeword, c, codewordU8Size());


            break;
        }
        case 5:
        case 6:
        case 7:
        case 8:
        {

            // this case has been optimized and we lookup 1 sub-codes at a time.
            static const u64 byteStep = 1;

            u64 kStop = (mG8.size() / 8) * 8;
            u64 kStep = rowSize * byteStep;

            for (u64 k = 0, i = 0; k < kStop; i += byteStep, k += kStep)
            {
                block* g0 = mG8.data() + k + byteView[i] * codeSize;

                c[0] = c[0] ^ g0[0];
                c[1] = c[1] ^ g0[1];
                c[2] = c[2] ^ g0[2];
                c[3] = c[3] ^ g0[3];
                c[4] = c[4] ^ g0[4];
                c[5] = c[5] ^ g0[5];
                c[6] = c[6] ^ g0[6];
                c[7] = c[7] ^ g0[7];
            }

            memcpy(codeword, c, codewordU8Size());


            break;
        }
        default:
        {

            // general case when the code word is wide than 8;

            block* g0 = mG8.data() + rowSize * 0;
            block* g1 = mG8.data() + rowSize * 1;
            block* g2 = mG8.data() + rowSize * 2;
            block* g3 = mG8.data() + rowSize * 3;
            block* g4 = mG8.data() + rowSize * 4;
            block* g5 = mG8.data() + rowSize * 5;
            block* g6 = mG8.data() + rowSize * 6;
            block* g7 = mG8.data() + rowSize * 7;

            for (u64 j = 0; j < codeSize; ++j)
            {
                c[0] = c[0] ^ c[0];
                c[1] = c[1] ^ c[1];
                c[2] = c[2] ^ c[2];
                c[3] = c[3] ^ c[3];
                c[4] = c[4] ^ c[4];
                c[5] = c[5] ^ c[5];
                c[6] = c[6] ^ c[6];
                c[7] = c[7] ^ c[7];

                auto bv = byteView;

                auto gg0 = g0;
                auto gg1 = g1;
                auto gg2 = g2;
                auto gg3 = g3;
                auto gg4 = g4;
                auto gg5 = g5;
                auto gg6 = g6;
                auto gg7 = g7;

                for (u64 i = 0; i < superRowCount; ++i, bv += 8)
                {
                    c[0] = c[0] ^ gg0[bv[0] * codeSize];
                    c[1] = c[1] ^ gg1[bv[1] * codeSize];
                    c[2] = c[2] ^ gg2[bv[2] * codeSize];
                    c[3] = c[3] ^ gg3[bv[3] * codeSize];
                    c[4] = c[4] ^ gg4[bv[4] * codeSize];
                    c[5] = c[5] ^ gg5[bv[5] * codeSize];
                    c[6] = c[6] ^ gg6[bv[6] * codeSize];
                    c[7] = c[7] ^ gg7[bv[7] * codeSize];

                    gg0 += rowSize8;
                    gg1 += rowSize8;
                    gg2 += rowSize8;
                    gg3 += rowSize8;
                    gg4 += rowSize8;
                    gg5 += rowSize8;
                    gg6 += rowSize8;
                    gg7 += rowSize8;

                }

                c[0] = c[0] ^ c[1];
                c[2] = c[2] ^ c[3];
                c[4] = c[4] ^ c[5];
                c[6] = c[6] ^ c[7];
                c[0] = c[0] ^ c[2];
                c[4] = c[4] ^ c[6];
                c[0] = c[0] ^ c[4];

                memcpy(
                    (codeword + sizeof(block) * j),
                    c,
                    std::min<u64>(sizeof(block), codewordU8Size() - j * sizeof(block)));

                ++g0;
                ++g1;
                ++g2;
                ++g3;
                ++g4;
                ++g5;
                ++g6;
                ++g7;
            }
            break;
        }
        }
    }

    void LinearCode::encode_bch511(u8 * input, u8 * codeword)
    {
        Expects(mPlaintextU8Size == 10);
        Expects(mPow2CodeSize == 4);

        // The size of the bch 511 codewords in 128 bit units.
        const i32 codeSize = 4;

        // The size of each preprocessed chunk. Each chunk 
        // is for 8 bits which leads to 2^8=256 preprocessed
        // codewords for each input byte.
        const i32 rowSize = 256 * codeSize;

        // create a local to store the partial codeword
        // and zero it out.
        block c[8];
        c[0] = c[0] ^ c[0];
        c[1] = c[1] ^ c[1];
        c[2] = c[2] ^ c[2];
        c[3] = c[3] ^ c[3];
        c[4] = c[4] ^ c[4];
        c[5] = c[5] ^ c[5];
        c[6] = c[6] ^ c[6];
        c[7] = c[7] ^ c[7];

        block* g0 = mG8.data() + 0 * rowSize + input[0] * codeSize;
        block* g1 = mG8.data() + 1 * rowSize + input[1] * codeSize;
        block* g2 = mG8.data() + 2 * rowSize + input[2] * codeSize;
        block* g3 = mG8.data() + 3 * rowSize + input[3] * codeSize;
        block* g4 = mG8.data() + 4 * rowSize + input[4] * codeSize;
        block* g5 = mG8.data() + 5 * rowSize + input[5] * codeSize;
        block* g6 = mG8.data() + 6 * rowSize + input[6] * codeSize;
        block* g7 = mG8.data() + 7 * rowSize + input[7] * codeSize;
        block* g8 = mG8.data() + 8 * rowSize + input[8] * codeSize;
        block* g9 = mG8.data() + 9 * rowSize + input[9] * codeSize;


        c[0] = c[0] ^ g0[0];
        c[1] = c[1] ^ g0[1];
        c[2] = c[2] ^ g0[2];
        c[3] = c[3] ^ g0[3];

        c[4] = c[4] ^ g1[0];
        c[5] = c[5] ^ g1[1];
        c[6] = c[6] ^ g1[2];
        c[7] = c[7] ^ g1[3];

        c[0] = c[0] ^ g2[0];
        c[1] = c[1] ^ g2[1];
        c[2] = c[2] ^ g2[2];
        c[3] = c[3] ^ g2[3];

        c[4] = c[4] ^ g3[0];
        c[5] = c[5] ^ g3[1];
        c[6] = c[6] ^ g3[2];
        c[7] = c[7] ^ g3[3];

        c[0] = c[0] ^ g4[0];
        c[1] = c[1] ^ g4[1];
        c[2] = c[2] ^ g4[2];
        c[3] = c[3] ^ g4[3];

        c[4] = c[4] ^ g5[0];
        c[5] = c[5] ^ g5[1];
        c[6] = c[6] ^ g5[2];
        c[7] = c[7] ^ g5[3];

        c[0] = c[0] ^ g6[0];
        c[1] = c[1] ^ g6[1];
        c[2] = c[2] ^ g6[2];
        c[3] = c[3] ^ g6[3];

        c[4] = c[4] ^ g7[0];
        c[5] = c[5] ^ g7[1];
        c[6] = c[6] ^ g7[2];
        c[7] = c[7] ^ g7[3];

        c[0] = c[0] ^ g8[0];
        c[1] = c[1] ^ g8[1];
        c[2] = c[2] ^ g8[2];
        c[3] = c[3] ^ g8[3];

        c[4] = c[4] ^ g9[0];
        c[5] = c[5] ^ g9[1];
        c[6] = c[6] ^ g9[2];
        c[7] = c[7] ^ g9[3];


        c[0] = c[0] ^ c[4];
        c[1] = c[1] ^ c[5];
        c[2] = c[2] ^ c[6];
        c[3] = c[3] ^ c[7];

        memcpy(codeword, c, codewordU8Size());
    }

}