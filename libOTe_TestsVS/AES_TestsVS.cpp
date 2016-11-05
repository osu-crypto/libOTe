#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"

#include "AES_Tests.h"



using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace osuCrypto_tests
{
    TEST_CLASS(LocalChannel_Tests)
    {
    public:

        TEST_METHOD(AES_EncDec_TestVS)
        {
            AES_EncDec_Test();
        }

    };
}
#endif
