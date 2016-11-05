#include "BchCode.h"
#include <fstream>
#include "Common/BitVector.h"
#include "Common/Log.h"
#define BITSET
#include <bitset>

#include "Common/MatrixView.h"
namespace osuCrypto
{

    BchCode::BchCode()
    {
    }

    BchCode::~BchCode()
    {
    }

    BchCode::BchCode(const BchCode &cp)
        :
        mCodewordBitSize(cp.mCodewordBitSize),
        mG(cp.mG),
        mG8(cp.mG8)
    {
    }

    void BchCode::loadTxtFile(const std::string & fileName)
    {
        std::ifstream in;
        in.open(fileName, std::ios::in);

        if (in.is_open() == false)
        {
            Log::out << "failed to open:\n     " << fileName << Log::endl;
            throw std::runtime_error("");
        }

        loadTxtFile(in);
    }

    void BchCode::loadTxtFile(std::istream & in)
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
    void BchCode::loadBinFile(const std::string & fileName)
    {
        std::fstream out;
        out.open(fileName, std::ios::in | std::ios::binary);

        loadBinFile(out);

    }
    void BchCode::loadBinFile(std::istream & out)
    {

        u64 size = 0;

        out.read((char *)&size, sizeof(u64));
        out.read((char *)&mCodewordBitSize, sizeof(u64));

        if (mCodewordBitSize == 0)
        {
            Log::out << "bad code " << Log::endl;
            throw std::runtime_error(LOCATION);
        }

        mG.resize(size);
        //mG1.resize(size);
        //mG2.resize(size / 2);

        out.read((char *)mG.data(), mG.size() * sizeof(block));

        generateMod8Table();
        //for (u64 i = 0; i < size; ++i)
        //{
        //    mG1[i][0] = ZeroBlock;
        //    mG1[i][1] = mG[i];
        //}
        //for (u64 i = 0; i < size / 2; ++i)
        //{
        //    mG2[i][0] = ZeroBlock;
        //    mG2[i][1] = mG[i];
        //}

    }

    void BchCode::writeBinFile(const std::string & fileName)
    {
        std::fstream out;
        out.open(fileName, std::ios::out | std::ios::binary | std::ios::trunc);

        writeBinFile(out);

    }
    void BchCode::writeBinFile(std::ostream & out)
    {
        u64 size = mG.size();
        out.write((const char *)&size, sizeof(u64));
        out.write((const char *)&mCodewordBitSize, sizeof(u64));

        out.write((const char *)mG.data(), mG.size() * sizeof(block));
    }

    void BchCode::generateMod8Table()
    {

        mG8.resize(roundUpTo((mG.size() + 7) / 8, 8) * 256);

        memset(mG8.data(), 0, mG8.size() * sizeof(block));

        MatrixView<block> g(mG.begin(), mG.end(), codewordBlkSize());
        MatrixView<block> g8(mG8.begin(), mG8.end(), codewordBlkSize() * 256);


        for (u64 i = 0; i < g8.size()[0]; ++i)
        {

            MatrixView<block> g8Block(g8[i].begin(), g8[i].end(), codewordBlkSize());

            for (u64 gRow = 0; gRow < 8; ++gRow)
            {
                u64 g8Row = (1 << gRow);
                u64 stride = g8Row;

                while (g8Row < 256)
                {
                    do
                    {
                        if (i * 8 + gRow < g.size()[0])
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

    u64 BchCode::plaintextBlkSize() const
    {
        return (plaintextBitSize() + 127) / 128;
    }

    u64 BchCode::plaintextBitSize() const
    {
        return mG.size() / codewordBlkSize();
    }

    u64 BchCode::codewordBlkSize() const
    {
        return (codewordBitSize() + 127) / 128;
    }

    u64 BchCode::codewordBitSize() const
    {
        return mCodewordBitSize;
    }


    static std::array<block, 2> sBlockMasks{ { ZeroBlock, AllOneBlock } };

    void BchCode::encode(
        ArrayView<block> plaintxt,
        ArrayView<block> codeword)
    {
#ifndef NDEBUG
        if (plaintxt.size() != plaintextBlkSize() ||
            codeword.size() < codewordBlkSize())
            throw std::runtime_error("");

        if (codewordBlkSize() != 4 || plaintextBitSize() != 76)
            throw std::runtime_error("generalize this code. a naive version is below but realize this is significantly slower " LOCATION);

        ////A general for loop, slower...
        //for (u64 i = 0, k = 0; i < cnt; ++i)
        //{
        //    for (u64 j = 0; j < codeword.size(); ++j, ++k)
        //    {
        //        // sBlock works as an if statment, but its faster...
        //        codeword[j] = codeword[j] ^ (mG[k] & sBlockMasks[*bitIter++]);
        //    }
        //}
#endif
        std::array<block, 8>
            c{ ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock,ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock };

        u8* byteView = (u8*)plaintxt.data();
        u64 kStop = (mG8.size() / 8) * 8,
            k = 0,
            i = 0;

        u64 byteStep = 2;
        u64 codeSize = 4;
        u64 rowSize = 256 * codeSize;
        u64 kStep = rowSize * byteStep;

        for (; k < kStop; i += byteStep, k += kStep)
        {
            block* g0 = mG8.data() + k + byteView[i] * codeSize;
            block* g1 = mG8.data() + k + byteView[i + 1] * codeSize + rowSize;

#ifndef NDEBUG
            if (g1 >= mG8.data() + mG8.size() + 4)throw std::runtime_error("bad indexing");
#endif


            c[0] = c[0] ^ g0[0];
            c[1] = c[1] ^ g0[1];
            c[2] = c[2] ^ g0[2];
            c[3] = c[3] ^ g0[3];

            c[4] = c[4] ^ g1[0];
            c[5] = c[5] ^ g1[1];
            c[6] = c[6] ^ g1[2];
            c[7] = c[7] ^ g1[3];
        }

        codeword[0] = c[0] ^ c[4];
        codeword[1] = c[1] ^ c[5];
        codeword[2] = c[2] ^ c[6];
        codeword[3] = c[3] ^ c[7];



    }
}