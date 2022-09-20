#pragma once
// © 2016 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <string>
#include "cryptoTools/Common/TestCollection.h"
#include "macoro/when_all.h"
#include "macoro/sync_wait.h"
#include "macoro/task.h"
namespace tests_libOTe
{
    //
    void InitDebugPrinting(std::string file = "../../testout.txt");
    //
    extern std::string SolutionDir;

    inline auto eval(macoro::task<>& t0, macoro::task<>& t1)
    {
        auto r = macoro::sync_wait(macoro::when_all_ready(std::move(t0), std::move(t1)));
        std::get<0>(r).result();
        std::get<1>(r).result();
    }

}