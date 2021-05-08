#pragma once
#include <cryptoTools/Common/CLP.h>

void Tools_Pprf_test(const oc::CLP& cmd);
void Tools_Pprf_trans_test(const oc::CLP& cmd);
void Tools_Pprf_inter_test(const oc::CLP& cmd);
void OtExt_Silent_random_Test(const oc::CLP& cmd);
void OtExt_Silent_correlated_Test(const oc::CLP& cmd);
void OtExt_Silent_inplace_Test(const oc::CLP& cmd);
void OtExt_Silent_paramSweep_Test(const oc::CLP& cmd);
void OtExt_Silent_QuasiCyclic_Test(const oc::CLP& cmd);
void OtExt_Silent_baseOT_Test(const oc::CLP& cmd);
void OtExt_Silent_mal_Test(const oc::CLP& cmd);

void Tools_bitShift_test(const oc::CLP& cmd);
void Tools_modp_test(const oc::CLP& cmd);

void SilentOT_mul_Test(const oc::CLP& cmd);
