#pragma once
// © 2016 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Defines.h>
#include <string>
#include <vector>

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

        void load(const unsigned char* data, u64 size);

        void loadBinFile(const std::string& fileName);
        void loadBinFile(std::istream& in);

        // outputs a c file contains an char array containing the binary data. e.g. bch511.h
        void writeBinCppFile(const std::string& fileName, const std::string & name);

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



        void encode(const span<const block>& plaintext,const span<block>& codeword);
        void encode(const span<const u8>& plaintext, const span<u8>& codeword);
        void encode(const u8* plaintext, u8* codeword);

        void encode_bch511(u8* plaintext, u8* codeword);

    };

}
