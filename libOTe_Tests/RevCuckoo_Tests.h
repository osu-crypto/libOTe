#include "cryptoTools/Common/CLP.h"



namespace osuCrypto
{
	void Goldreich_Proto_Test(const oc::CLP& cmd);
	void Goldreich_stat_Test(const oc::CLP& cmd);

	void RevCuckoo_baseOtSlicing_Test(const oc::CLP& cmd);
	void RevCuckoo_iterative_Test(const oc::CLP& cmd);
	void RevCuckoo_singlePoint_Test(const oc::CLP& cmd);
	void RevCuckoo_robustness_Test(const oc::CLP& cmd);
	void RevCuckoo_failurePropagation_Test(const oc::CLP& cmd);

}
