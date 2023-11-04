#pragma once
// © 2016 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <cryptoTools/Common/Defines.h>
#include "libOTe/config.h"
#include <cassert>
#include <iostream>
#include "libOTe/TwoChooseOne/ConfigureCode.h"

//#define OTE_KOS_HASH
//#define IKNP_SHA_HASH
//#define OTE_KOS_FIAT_SHAMIR

namespace osuCrypto
{
	const u64 commStepSize(512); // TODO: try increasing this for optimization.
	const u64 superBlkShift(3);
	const u64 superBlkSize(1 << superBlkShift);

	enum class SilentBaseType {
		// Use a standalone base OT protocol to generate the required base OTs
		// This will result in fewer rounds but more computation
		Base, 

		// Use base OTs and OT Extension to generate the required base OTs.
		// Only 128 base OTs will be performed while the rest use OT extension.
		// This will result in more rounds but less computation.
		BaseExtend
	};

//#ifdef ENABLE_BITPOLYMUL
//	constexpr MultType DefaultMultType = MultType::QuasiCyclic;
//#else
//	constexpr MultType DefaultMultType = MultType::slv5;
//#endif

	

	template<typename S, typename TSpan>
		span<S> spanCast(TSpan& src)
	{
		using T = typename TSpan::value_type;
		static_assert(
			std::is_pod<T>::value &&
			std::is_pod<S>::value &&
			((sizeof(T) % sizeof(S) == 0) ||
			(sizeof(S) % sizeof(T) == 0)), " types must be POD and a multiple of each other.");

		assert(u64(src.data()) % sizeof(S) == 0);

		auto r = span<S>((S*)src.data(), src.size() * sizeof(T) / sizeof(S));

		assert((void*)r.data() == (void*)src.data());

		return r;

	}
}
