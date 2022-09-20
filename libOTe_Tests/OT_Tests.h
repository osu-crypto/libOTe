#pragma once
// © 2016 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/block.h"
namespace tests_libOTe
{

    void Tools_Transpose_Test();
    void Tools_Transpose_View_Test();
    void Tools_Transpose_Bench();


    void OtExt_Kos_Test();
    void OtExt_Kos_fs_Test();
    void OtExt_Kos_ro_Test();
    void DotExt_Kos_Test();
    void OtExt_genBaseOts_Test();
    void OtExt_Chosen_Test();
        //void LzOtExt_Kos_Test();
    //void Kos2OtExt_100Receive_Test();
    void OtExt_Iknp_Test();
    void DotExt_Iknp_Test();



    void OT_100Receive_Test(
        osuCrypto::BitVector& choiceBits,
        osuCrypto::span<osuCrypto::block> recv,
        osuCrypto::span<std::array<osuCrypto::block, 2>>  sender);

}
