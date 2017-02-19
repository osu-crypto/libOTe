#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/ArrayView.h>
#include <string>
namespace osuCrypto
{

    class PRNG;
    class LinearCode
    {
    public:
        static const u16 sLinearCodePlainTextMaxSize;

        LinearCode();
        ~LinearCode();
        LinearCode(const LinearCode& cp);


        void loadTxtFile(const std::string& fileName);
        void loadTxtFile(std::istream& in);



        void loadBinFile(const std::string& fileName);
        void loadBinFile(std::istream& in);

        void writeBinFile(const std::string& fileName);
        void writeBinFile(std::ostream& out);

        void writeTextFile(const std::string& fileName);
        void writeTextFile(std::ostream& out);



        void random(PRNG& prng, u64 inputSize, u64 outputSize);

        void generateMod8Table();

        u64 mU8RowCount, mPow2CodeSize, mPlaintextU8Size;
        u64 mCodewordBitSize;
        std::vector<block> mG;
        std::vector<block> mG8;

        inline u64 codewordBitSize() const
        {
            return mCodewordBitSize;
        }

        inline u64 codewordBlkSize() const
        {
            return (codewordBitSize() + 127) / 128;
        }
        inline u64 plaintextBitSize() const
        {
            return mG.size() / codewordBlkSize();
        }
        inline u64 plaintextBlkSize() const
        {
            return (plaintextBitSize() + 127) / 128;
        }

        inline u64 plaintextU8Size() const
        {
            return mPlaintextU8Size;
        }

        inline u64 codewordU8Size() const
        {
            return (codewordBitSize() + 7) / 8;
        }



        void encode(const ArrayView<block>& plaintext,const ArrayView<block>& codeword);
        void encode(const ArrayView<u8>& plaintext, const ArrayView<u8>& codeword);
        void encode(u8* plaintext, u8* codeword);

    };

}
