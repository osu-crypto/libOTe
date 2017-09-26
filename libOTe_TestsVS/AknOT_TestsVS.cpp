#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"
#include "AknOt_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
//
//void BitVector_Indexing_Test_Impl();
//void BitVector_Parity_Test_Impl();
//void BitVector_Append_Test_Impl();
//void BitVector_Copy_Test_Impl();
//
//void Transpose_Test_Impl();
//
//
//
//void OTExt_100Receive_Test_Impl();
//void KosOtExt_Setup_Test_Impl();



namespace tests_libOTe
{
    TEST_CLASS(AknOtTests)
    {
    public:

        TEST_METHOD(AknOt_sendRecv_TestVS)
        {
            InitDebugPrinting();
            AknOt_sendRecv1000_Test();
        }

    };
}
#endif