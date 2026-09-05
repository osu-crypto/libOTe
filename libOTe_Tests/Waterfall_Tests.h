#pragma once

#include "cryptoTools/Common/CLP.h"

namespace osuCrypto
{
	void Waterfall_config_Test(const oc::CLP& cmd);
	void Waterfall_validation_Test(const oc::CLP& cmd);
	void Waterfall_emptySparseColumn_Test(const oc::CLP& cmd);
	void Waterfall_placement_Test(const oc::CLP& cmd);
	void Waterfall_hash_Test(const oc::CLP& cmd);
	void Waterfall_candidates_Test(const oc::CLP& cmd);
	void Waterfall_basicMpc_Test(const oc::CLP& cmd);
	void Waterfall_reachabilityMpc_Test(const oc::CLP& cmd);
	void Waterfall_scatterMpc_Test(const oc::CLP& cmd);
	void Waterfall_dmpfEndToEnd_Test(const oc::CLP& cmd);
}
