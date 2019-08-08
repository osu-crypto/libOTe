#include "UnitTests.h"

#include <cryptoTools/Common/Log.h>
#include <functional>


#include "libOTe_Tests/AknOt_Tests.h"
#include "libOTe_Tests/BaseOT_Tests.h"
#include "libOTe_Tests/OT_Tests.h"
#include "libOTe_Tests/NcoOT_Tests.h"
#include "libOTe_Tests/AknOt_Tests.h"
#include "libOTe_Tests/BgiTests.h"
#include "libOTe_Tests/BgciksOT_Tests.h"
#include "libOTe_Tests/bitpolymul_Tests.h"

using namespace osuCrypto;
namespace tests_libOTe
{
    TestCollection Tests([](TestCollection& tc)
    {
        //void OtExt_genBaseOts_Test_Impl()


        tc.add("TransposeMatrixView_Test_Impl           ", TransposeMatrixView_Test_Impl);
        tc.add("Transpose_Test_Impl                     ", Transpose_Test_Impl);
        tc.add("OtExt_genBaseOts_Test_Impl              ", OtExt_genBaseOts_Test_Impl);
        tc.add("OtExt_Chosen_Test_Impl                  ", OtExt_Chosen_Test_Impl);
        tc.add("KosOtExt_100Receive_Test_Impl           ", KosOtExt_100Receive_Test_Impl);
        tc.add("KosDotExt_100Receive_Test_Impl          ", KosDotExt_100Receive_Test_Impl);
        tc.add("IknpOtExt_100Receive_Test_Impl          ", IknpOtExt_100Receive_Test_Impl);
        tc.add("IknpDotExt_100Receive_Test_Impl         ", IknpDotExt_100Receive_Test_Impl);
        tc.add("AknOt_sendRecv1000_Test                 ", AknOt_sendRecv1000_Test);
        tc.add("KkrtNcoOt_Test                          ", KkrtNcoOt_Test_Impl);
        tc.add("OosNcoOt_Test_Impl                      ", OosNcoOt_Test_Impl);
        tc.add("Rr17NcoOt_Test_Impl                     ", Rr17NcoOt_Test_Impl);
        tc.add("NcoOt_genBaseOts_Test_Impl              ", NcoOt_genBaseOts_Test_Impl);
        tc.add("LinearCode_Test_Impl                    ", LinearCode_Test_Impl);
        tc.add("LinearCode_subBlock_Test_Impl           ", LinearCode_subBlock_Test_Impl);
        tc.add("LinearCode_repetition_Test_Impl         ", LinearCode_repetition_Test_Impl);
        tc.add("NaorPinkasOt_Test                       ", NaorPinkasOt_Test_Impl);
        tc.add("SimplestOT_Test_Impl                    ", SimplestOT_Test_Impl);


        tc.add("Bgi_keyGen_128_test                     " , Bgi_keyGen_128_test);               
        tc.add("Bgi_keyGen_test                         " , Bgi_keyGen_test);                   
        tc.add("bitpolymul_test                         " , bitpolymul_test);
        //tc.add("Bgi_FullDomain_test                     " , Bgi_FullDomain_test);               
        //tc.add("Bgi_FullDomain_iterator_test            " , Bgi_FullDomain_iterator_test);      
        tc.add("Bgi_FullDomain_multikey_test            " , Bgi_FullDomain_multikey_test);   
        tc.add("bitShift_test                           ", bitShift_test);
        tc.add("modp_test                               ", modp_test);
                                                       
        tc.add("BgciksOT_Test                           ", BgciksOT_Test);
        tc.add("BgciksPprf_Test                         ", BgciksPprf_Test);
        tc.add("BgciksPprf_trans_Test                   ", BgciksPprf_trans_Test);
                                                       
    });



}
