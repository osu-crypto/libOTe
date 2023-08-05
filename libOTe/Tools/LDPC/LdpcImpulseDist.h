#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// This code implements features described in [Silver: Silent VOLE and Oblivious Transfer from Hardness of Decoding Structured LDPC Codes, https://eprint.iacr.org/2021/1150]; the paper is licensed under Creative Commons Attribution 4.0 International Public License (https://creativecommons.org/licenses/by/4.0/legalcode).
#include "libOTe/config.h"
#ifdef ENABLE_LDPC

#include "Mtx.h"
#include "LdpcDecoder.h"

namespace osuCrypto
{


    enum class BPAlgo
    {
        LogBP = 0,
        AltLogBP = 1,
        MinSum = 2
    };

    enum class ListDecoder
    {
        Chase = 0 ,
        OSD = 1
    };

    //extern std::vector<u8> minCW;
    
    void LdpcDecode_impulse(const oc::CLP& cmd);

    //u64 impulseDist(LdpcDecoder& D, u64 i, u64 n, u64 k, u64 Ne, u64 maxIter);
    //u64 impulseDist(SparseMtx& mH, u64 Ne, u64 w, u64 maxIter, u64 numThreads, bool randImpulse, u64 trials, BPAlgo algo, bool verbose);
}
#endif