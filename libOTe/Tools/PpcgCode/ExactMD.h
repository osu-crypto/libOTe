#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/CLP.h"
#include "Subcode.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include <thread>

namespace osuCrypto
{




	inline double exactMD(span<Subcode> iters, u64 k, u64 n, u64 sigma, PRNG& prng)
	{
		if (k == 0 || n == 0)
			return 0;
		if (k == n)
			return sigma;
		if (k > n)
			throw RTE_LOC;


		DenseMtx G(k, n);

		if ((n - k) % sigma)
			throw RTE_LOC;
		auto q = (n - k) / sigma;

		DenseMtx Gi;
		for (u64 i = 0; i < k; i++)
		{
			G(i, i) = 1;


			auto b = k + (i / sigma) * sigma;
			auto e = b + sigma;
			for (u64 j = b; j < e; j++)
			{
				G(i, j) = prng.getBit();
			}
		}

		std::cout << G << std::endl;
		return minDist(G, std::thread::hardware_concurrency(), 1);
		//minDist(G,)
		return 0;
	}

}