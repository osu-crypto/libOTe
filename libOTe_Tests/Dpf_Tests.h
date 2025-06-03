
#pragma once
#include "cryptoTools/Common/CLP.h"

void RegularDpf_Multiply_Test(const oc::CLP& cmd);
void RegularDpf_MultByte_Test(const oc::CLP& cmd);
void RegularDpf_MultBit_Test(const oc::CLP& cmd);

void RegularDpf_Proto_Test(const oc::CLP& cmd);
void RegularDpf_Puncture_Test(const oc::CLP& cmd);
void RegularDpf_keyGen_Test(const oc::CLP& cmd);
void SparseDpf_Proto_Test(const oc::CLP& cmd);
void TritDpf_Proto_Test(const oc::CLP& cmd);

void MtxDpf_Proto_Test(const oc::CLP& cmd); 
void Goldreich_Proto_Test(const oc::CLP& cmd);
void Goldreich_stat_Test(const oc::CLP& cmd);

