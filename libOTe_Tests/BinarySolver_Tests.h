#include "cryptoTools/Common/CLP.h"


namespace osuCrypto
{

	void BinSolver_multiply_test(const oc::CLP& cmd);
	void BinSolver_multiplyMtx_test(const oc::CLP& cmd);
	void BinSolver_firstOneBit_test(const oc::CLP& cmd);
	void BinSolver_solve_test(const oc::CLP& cmd);

	// New batched tests
	void BinSolver_firstOneBitMany_test(const oc::CLP& cmd);
	void BinSolver_multiplyMany_test(const oc::CLP& cmd);
	void BinSolver_multiplyMtxMany_test(const oc::CLP& cmd);
	void BinSolver_solveMany_test(const oc::CLP& cmd);

}