#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"

namespace osuCrypto
{
	/// Enumerator interface
	///
	/// 
	template<typename R>
	struct Enumerator
	{
		Enumerator() = default;
		Enumerator(u64 k, u64 n) : mK(k), mN(n) {}
		Enumerator(const Enumerator&) = default;

		u64 mK = 0;
		u64 mN = 0;

		virtual void enumerate(
			span<const R> inDist,
			span<R> outDist) = 0;

		virtual void enumerate(
			span<const R> inDist,
			span<R> outDist,
			MatrixView<R> full) = 0;

	};
}