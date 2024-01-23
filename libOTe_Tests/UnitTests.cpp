#include "UnitTests.h"

#include <cryptoTools/Common/Log.h>
#include <functional>


#include "libOTe_Tests/BaseOT_Tests.h"
#include "libOTe_Tests/OT_Tests.h"
#include "libOTe_Tests/NcoOT_Tests.h"
#include "libOTe_Tests/SilentOT_Tests.h"
#include "libOTe_Tests/SoftSpoken_Tests.h"
#include "libOTe_Tests/bitpolymul_Tests.h"
#include "libOTe_Tests/Vole_Tests.h"
#include "libOTe/Tools/LDPC/LdpcDecoder.h"
#include "libOTe/Tools/LDPC/LdpcEncoder.h"
#include "libOTe_Tests/ExConvCode_Tests.h"
#include "libOTe_Tests/EACode_Tests.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include "libOTe_Tests/Field_Tests.h"
#include "libOTe_Tests/Poly_Tests.h"
#include "libOTe_Tests/Ntt_Tests.h"


using namespace osuCrypto;
namespace tests_libOTe
{
    TestCollection Tests([](TestCollection& tc)
        {


            tc.add("Tools_Transpose_Test                    ", Tools_Transpose_Test);
            tc.add("Tools_Transpose_View_Test               ", Tools_Transpose_View_Test);
            tc.add("Tools_Transpose_Bench                   ", Tools_Transpose_Bench);

            tc.add("Tools_LinearCode_Test                   ", Tools_LinearCode_Test);
            tc.add("Tools_LinearCode_sub_Test               ", Tools_LinearCode_sub_Test);
            tc.add("Tools_LinearCode_rep_Test               ", Tools_LinearCode_rep_Test);

            tc.add("Tools_bitShift_test                     ", Tools_bitShift_test);
            tc.add("Tools_modp_test                         ", Tools_modp_test);
            tc.add("Tools_bitpolymul_test                   ", Tools_bitpolymul_test);
            tc.add("Tools_quasiCyclic_test                  ", Tools_quasiCyclic_test);

            tc.add("Mtx_make_test                           ", tests::Mtx_make_test);
            tc.add("Mtx_add_test                            ", tests::Mtx_add_test);
            tc.add("Mtx_mult_test                           ", tests::Mtx_mult_test);
            tc.add("Mtx_invert_test                         ", tests::Mtx_invert_test);
#ifdef ENABLE_LDPC
            tc.add("ldpc_Mtx_block_test                     ", tests::Mtx_block_test);
            tc.add("LdpcDecode_pb_test                      ", tests::LdpcDecode_pb_test);
            tc.add("LdpcEncoder_diagonalSolver_test         ", tests::LdpcEncoder_diagonalSolver_test);
            tc.add("LdpcEncoder_encode_test                 ", tests::LdpcEncoder_encode_test);
            tc.add("LdpcEncoder_encode_g0_test              ", tests::LdpcEncoder_encode_g0_test);
            tc.add("LdpcS1Encoder_encode_test               ", tests::LdpcS1Encoder_encode_test);
            tc.add("LdpcS1Encoder_encode_Trans_test         ", tests::LdpcS1Encoder_encode_Trans_test);
            tc.add("LdpcComposit_RegRepDiagBand_encode_test ", tests::LdpcComposit_RegRepDiagBand_encode_test);
            tc.add("LdpcComposit_RegRepDiagBand_Trans_test  ", tests::LdpcComposit_RegRepDiagBand_Trans_test);
#endif


            tc.add("EACode_encode_basic_test                ", EACode_encode_basic_test);
            tc.add("ExConvCode_encode_basic_test            ", ExConvCode_encode_basic_test);
            
            tc.add("Tools_Pprf_expandOne_test               ", Tools_Pprf_expandOne_test);
            tc.add("Tools_Pprf_test                         ", Tools_Pprf_test);
            tc.add("Tools_Pprf_inter_test                   ", Tools_Pprf_inter_test);
            tc.add("Tools_Pprf_blockTrans_test              ", Tools_Pprf_blockTrans_test);
            tc.add("Tools_Pprf_callback_test                ", Tools_Pprf_callback_test);

            tc.add("Field_F7681_Test                        ", Field_F7681_Test);
            tc.add("Field_F12289_Test                       ", Field_F12289_Test);
            tc.add("Poly_basics_Tests                       ", Poly_basics_Tests);
            tc.add("Ntt_nttNegWrapMatrix_Test               ", Ntt_nttNegWrapMatrix_Test);
            
            tc.add("Bot_Simplest_Test                       ", Bot_Simplest_Test);
            tc.add("Bot_Simplest_asm_Test                   ", Bot_Simplest_asm_Test);

            tc.add("Bot_McQuoidRR_Moeller_EKE_Test          ", Bot_McQuoidRR_Moeller_EKE_Test);
            tc.add("Bot_McQuoidRR_Moeller_MR_Test           ", Bot_McQuoidRR_Moeller_MR_Test);
            tc.add("Bot_McQuoidRR_Moeller_F_Test            ", Bot_McQuoidRR_Moeller_F_Test);
            tc.add("Bot_McQuoidRR_Moeller_FM_Test           ", Bot_McQuoidRR_Moeller_FM_Test);

            tc.add("Bot_McQuoidRR_Ristrestto_F_Test         ", Bot_McQuoidRR_Ristrestto_F_Test);
            tc.add("Bot_McQuoidRR_Ristrestto_FM_Test        ", Bot_McQuoidRR_Ristrestto_FM_Test);

            tc.add("Bot_MasnyRindal_Test                    ", Bot_MasnyRindal_Test);
            tc.add("Bot_MasnyRindal_Kyber_Test              ", Bot_MasnyRindal_Kyber_Test);

            tc.add("Vole_SoftSpokenSmall_Test               ", Vole_SoftSpokenSmall_Test);
            tc.add("DotExt_Kos_Test                         ", DotExt_Kos_Test);
            tc.add("DotExt_Iknp_Test                        ", DotExt_Iknp_Test);


            tc.add("OtExt_genBaseOts_Test                   ", OtExt_genBaseOts_Test);
            tc.add("OtExt_Chosen_Test                       ", OtExt_Chosen_Test);
            tc.add("OtExt_Iknp_Test                         ", OtExt_Iknp_Test);
            tc.add("OtExt_Kos_Test                          ", OtExt_Kos_Test);
            tc.add("OtExt_Kos_fs_Test                       ", OtExt_Kos_fs_Test);
            tc.add("OtExt_Kos_ro_Test                       ", OtExt_Kos_ro_Test);
            tc.add("OtExt_Silent_random_Test                ", OtExt_Silent_random_Test);
            tc.add("OtExt_Silent_correlated_Test            ", OtExt_Silent_correlated_Test);
            tc.add("OtExt_Silent_inplace_Test               ", OtExt_Silent_inplace_Test);
            tc.add("OtExt_Silent_paramSweep_Test            ", OtExt_Silent_paramSweep_Test);
            tc.add("OtExt_Silent_QuasiCyclic_Test           ", OtExt_Silent_QuasiCyclic_Test);
            tc.add("OtExt_Silent_Silver_Test                ", OtExt_Silent_Silver_Test);
            tc.add("OtExt_Silent_baseOT_Test                ", OtExt_Silent_baseOT_Test);
            tc.add("OtExt_Silent_mal_Test                   ", OtExt_Silent_mal_Test);

            tc.add("OtExt_SoftSpokenSemiHonest_Test         ", OtExt_SoftSpokenSemiHonest_Test);
            tc.add("OtExt_SoftSpokenSemiHonest_Split_Test   ", OtExt_SoftSpokenSemiHonest_Split_Test);
            //tc.add("OtExt_SoftSpokenSemiHonest21_Test       ", OtExt_SoftSpokenSemiHonest21_Test);
            tc.add("OtExt_SoftSpokenMalicious21_Test        ", OtExt_SoftSpokenMalicious21_Test);
            tc.add("OtExt_SoftSpokenMalicious21_Split_Test  ", OtExt_SoftSpokenMalicious21_Split_Test);
            tc.add("DotExt_SoftSpokenMaliciousLeaky_Test    ", DotExt_SoftSpokenMaliciousLeaky_Test);

            tc.add("Vole_Noisy_test                         ", Vole_Noisy_test);
            tc.add("Vole_Silent_QuasiCyclic_test            ", Vole_Silent_QuasiCyclic_test);
            tc.add("Vole_Silent_Silver_test                 ", Vole_Silent_Silver_test);
            tc.add("Vole_Silent_paramSweep_test             ", Vole_Silent_paramSweep_test);
            tc.add("Vole_Silent_baseOT_test                 ", Vole_Silent_baseOT_test);
            tc.add("Vole_Silent_mal_test                    ", Vole_Silent_mal_test);
            tc.add("Vole_Silent_Rounds_test                 ", Vole_Silent_Rounds_test);

            tc.add("NcoOt_Kkrt_Test                         ", NcoOt_Kkrt_Test);
            tc.add("NcoOt_Oos_Test                          ", NcoOt_Oos_Test);
            tc.add("NcoOt_genBaseOts_Test                   ", NcoOt_genBaseOts_Test);

        });
}
