#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"

#include "Ecc_Tests.h"
#include "Common.h"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace osuCrypto_tests
{
    TEST_CLASS(LocalChannel_Tests)
    {
    public:

        TEST_METHOD(Eccp_Number_TestVS)
        {
            InitDebugPrinting();
            EccpNumber_Test();
        }

        TEST_METHOD(Eccp_Point_TestVS)
        {
            InitDebugPrinting();
            EccpPoint_Test();
        }

        TEST_METHOD(Ecc2m_Number_TestVS)
        {
            InitDebugPrinting();
            Ecc2mNumber_Test();
        }

        TEST_METHOD(Ecc2m_Point_TestVS)
        {
            InitDebugPrinting();
            Ecc2mPoint_Test();
        }
    };
}
#endif
