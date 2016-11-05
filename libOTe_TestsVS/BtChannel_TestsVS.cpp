#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"

#include "Common.h"
#include "BtChannel_Tests.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace osuCrypto_tests
{
    TEST_CLASS(BtNetworking_Tests)
    {
    public:

        TEST_METHOD(BtNetwork_Connect1_Boost_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_Connect1_Boost_Test();
        }


        TEST_METHOD(BtNetwork_OneMegabyteSend_Boost_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_OneMegabyteSend_Boost_Test();
        }


        TEST_METHOD(BtNetwork_ConnectMany_Boost_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_ConnectMany_Boost_Test();
        }


        TEST_METHOD(BtNetwork_CrossConnect_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_CrossConnect_Test();
        }


        TEST_METHOD(BtNetwork_ManyEndpoints_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_ManyEndpoints_Test();
        }
    };
}
#endif