#pragma once
// © 2020 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <cryptoTools/Common/CLP.h>

void Tools_Pprf_expandOne_test(const oc::CLP& cmd);
void Tools_Pprf_test(const oc::CLP& cmd);
void Tools_Pprf_trans_test(const oc::CLP& cmd);
void Tools_Pprf_inter_test(const oc::CLP& cmd);
void Tools_Pprf_blockTrans_test(const oc::CLP& cmd);
void Tools_Pprf_callback_test(const oc::CLP& cmd);

void OtExt_Silent_random_Test(const oc::CLP& cmd);
void OtExt_Silent_correlated_Test(const oc::CLP& cmd);
void OtExt_Silent_inplace_Test(const oc::CLP& cmd);
void OtExt_Silent_paramSweep_Test(const oc::CLP& cmd);
void OtExt_Silent_QuasiCyclic_Test(const oc::CLP& cmd);
void OtExt_Silent_Silver_Test(const oc::CLP& cmd);
void OtExt_Silent_baseOT_Test(const oc::CLP& cmd);
void OtExt_Silent_mal_Test(const oc::CLP& cmd);

void Tools_bitShift_test(const oc::CLP& cmd);
void Tools_modp_test(const oc::CLP& cmd);
void Tools_quasiCyclic_test(const oc::CLP& cmd);

void SilentOT_mul_Test(const oc::CLP& cmd);
