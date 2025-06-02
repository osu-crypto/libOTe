#pragma once
#include "cryptoTools/Common/CLP.h"
namespace osuCrypto
{
	void BitInject_basic_test(const CLP& cmd);

	void OtEquality_basic_Test(const CLP& cmd);
	void HybEquality_basic_Test(const CLP& cmd);
	void Dedup_orTree_test(const CLP& cmd);
	void Dedup_protocol_test(const CLP& cmd);
}