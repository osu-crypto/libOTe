#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"
#include "OT_Tests.h"
#include "NcoOT_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace tests_libOTe
{
    TEST_CLASS(OT_Tests)
    {
    public:

        TEST_METHOD(Transpose_TestVS)
        {
            InitDebugPrinting();
            Transpose_Test_Impl();
        }

        TEST_METHOD(TransposeMatrixView_TestVS)
        {
            InitDebugPrinting();
            TransposeMatrixView_Test_Impl();
        }

        TEST_METHOD(Iknp_200Receive_TestVS)
        {
            InitDebugPrinting();
            IknpOtExt_100Receive_Test_Impl();
        }



        TEST_METHOD(Kos_200Receive_TestVS)
        {
            InitDebugPrinting();
            KosOtExt_100Receive_Test_Impl();
        }

        TEST_METHOD(OtExt_genBaseOts_TestVS)
        {
            InitDebugPrinting();
            OtExt_genBaseOts_Test_Impl();
        }

        TEST_METHOD(OtExt_chosen_TestVS)
        {
            InitDebugPrinting();
            OtExt_Chosen_Test_Impl();
        }

        TEST_METHOD(KosDot_200Receive_TestVS)
        {
            InitDebugPrinting();
            KosDotExt_100Receive_Test_Impl();
        }


		TEST_METHOD(IknpDot_200Receive_TestVS)
		{
			InitDebugPrinting();
			IknpDotExt_100Receive_Test_Impl();
		}

        TEST_METHOD(Kkrt_200Receive_TestVS)
        {
            InitDebugPrinting();
            KkrtNcoOt_Test_Impl();
        }

        TEST_METHOD(Oos_200Receive_TestVS)
        {
            InitDebugPrinting(); 
            OosNcoOt_Test_Impl();
        }

        TEST_METHOD(NcoOt_genBaseOts_TestVS)
        {
            InitDebugPrinting();
            NcoOt_genBaseOts_Test_Impl();
        }

        TEST_METHOD(NcoOt_chosen_TestVS)
        {
            InitDebugPrinting();
            NcoOt_chosen_Impl();
        }
        TEST_METHOD(Rr17_200Receive_TestVS)
        {
            InitDebugPrinting();
            Rr17NcoOt_Test_Impl();
        }

        TEST_METHOD(LinearCode_TestVS)
        {
            InitDebugPrinting();
            LinearCode_Test_Impl();
        }


        TEST_METHOD(LinearCode_subBlock_TestVS)
        {
            InitDebugPrinting();
            LinearCode_subBlock_Test_Impl();
        }

        TEST_METHOD(LinearCode_repetition_TestVS)
        {
            InitDebugPrinting();
            LinearCode_repetition_Test_Impl();
        }




        //TEST_METHOD(LinearCode_rand134_TestVS)
        //{
        //    InitDebugPrinting();
        //    LinearCode_rand134_Test_Impl();
        //}



        //TEST_METHOD(Kos2_200Receive_TestVS)
        //{
        //    InitDebugPrinting();
        //    Kos2OtExt_100Receive_Test_Impl();
        //}

    };
}
#endif