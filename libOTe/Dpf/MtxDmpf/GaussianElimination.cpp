#include "GaussianElimination.h"
#include "cryptoTools/Circuit/MxTypes.h"

namespace osuCrypto
{

	Mx::Circuit gaussianElimination(u64 rows, u64 cols)
	{
		Mx::Circuit r;

		auto x = r.input<Mx::BVector>(cols);
		auto M = r.input<Mx::BVector>(cols * rows);
		auto y = r.input<Mx::BVector>(cols);
	}

}