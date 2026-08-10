#pragma once

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#include <array>
#include <cstddef>

namespace osuCrypto
{
	namespace details
	{
		namespace mrr
		{
			// Fixed-width transcript fields. The field tags make concatenations
			// unambiguous, while the explicit encodings keep peers independent of
			// host endianness and C++ object representation.
			constexpr u8 domainField = 0;
			constexpr u8 indexField = 1;
			constexpr u8 branchField = 2;

			template<std::size_t N>
			inline void updateDomain(RandomOracle& ro, const char (&domain)[N])
			{
				static_assert(N > 1, "MRR transcript domains must not be empty");
				static_assert(N - 1 <= 255, "MRR transcript domain is too long");
				const std::array<u8, 2> header{
					domainField, static_cast<u8>(N - 1) };
				ro.Update(header.data(), header.size());
				ro.Update(domain, N - 1);
			}

			inline void updateIndex(RandomOracle& ro, u64 index)
			{
				std::array<u8, 1 + sizeof(u64)> encoded{};
				encoded[0] = indexField;
				for (u64 i = 0; i != sizeof(u64); ++i)
					encoded[1 + i] = static_cast<u8>(index >> (8 * i));
				ro.Update(encoded.data(), encoded.size());
			}

			inline void updateBranch(RandomOracle& ro, bool branch)
			{
				const std::array<u8, 2> encoded{
					branchField, static_cast<u8>(branch) };
				ro.Update(encoded.data(), encoded.size());
			}
		}
	}
}
