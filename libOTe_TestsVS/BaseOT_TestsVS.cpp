#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"
#include "BaseOT_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace tests_libOTe
{
    TEST_CLASS(BaseOT_Tests)
    {
    public:
    
        TEST_METHOD(NaorPinkasOt_TestVS)
        {
            InitDebugPrinting();
            NaorPinkasOt_Test_Impl();
        } 

    };
}
#endif