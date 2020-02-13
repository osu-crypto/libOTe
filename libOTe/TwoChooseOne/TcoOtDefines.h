#pragma once
#include <cryptoTools/Common/Defines.h>

//#define OTE_KOS_HASH
//#define IKNP_SHA_HASH
//#define OTE_KOS_FIAT_SHAMIR

namespace osuCrypto
{ 
     const u64 commStepSize(512);
     const u64 superBlkSize(8);

	enum class SilentBaseType {Base, BaseExtend};

	template<typename S, typename TSpan,
		typename enabled = typename std::enable_if<
		std::is_convertible<
		TSpan,
		span<typename TSpan::value_type>
	>::value>::type>
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
