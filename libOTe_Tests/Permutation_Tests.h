#pragma once

#include "cryptoTools/Common/CLP.h"

namespace tests_libOTe
{
    void Permutation_bijection_test(const osuCrypto::CLP& cmd);
    void Permutation_data_test(const osuCrypto::CLP& cmd);
    void Permutation_chunk_test(const osuCrypto::CLP& cmd);
    void Permutation_performance_test(const osuCrypto::CLP& cmd);
}