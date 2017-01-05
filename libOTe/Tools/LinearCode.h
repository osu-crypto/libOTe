#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/ArrayView.h"
#include <string>
namespace osuCrypto
{

    class PRNG;
    class LinearCode
    {
    public:
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

        u64 mCodewordBitSize;
        std::vector<block> mG;
        std::vector<block> mG8;

        u64 plaintextBlkSize()const;
        u64 codewordBlkSize()const;

        u64 plaintextU8Size()const;
        u64 codewordU8Size()const;

        u64 plaintextBitSize()const;
        u64 codewordBitSize()const;


        void encode(ArrayView<block> plaintext, ArrayView<block> codeword);
        void encode(ArrayView<u8> plaintext, ArrayView<u8> codeword);
        void encode(u8* plaintext, u8* codeword);

    };

}
