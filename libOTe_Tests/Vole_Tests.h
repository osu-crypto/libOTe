#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <cryptoTools/Common/CLP.h>

void Vole_Noisy_test(const oc::CLP& cmd);
void Vole_Silent_QuasiCyclic_test(const oc::CLP& cmd);
void Vole_Silent_Silver_test(const oc::CLP& cmd);
void Vole_Silent_paramSweep_test(const oc::CLP& cmd);
void Vole_Noisy_test(const oc::CLP& cmd);
void Vole_Silent_baseOT_test(const oc::CLP& cmd);
void Vole_Silent_mal_test(const oc::CLP& cmd);
void Vole_Silent_Rounds_test(const oc::CLP& cmd);
