// © 2026 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#pragma once

#include "libOTe/Tools/Tools.h"
#include "libOTe/TwoChooseOne/TcoOtDefines.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <algorithm>
#include <array>
#include <stdexcept>

namespace osuCrypto::details
{
	constexpr u64 KosDotCheckColumns = gOtExtBaseOtCount + 40;
	using KosDotCheckRow = std::array<block, 2>;
	using KosDotColumnCheck = std::array<block, KosDotCheckColumns>;
	using KosDotProof = std::array<block, KosDotCheckColumns + 1>;

	inline KosDotColumnCheck kosDotTransposeCheckChunk(
		span<const KosDotCheckRow> rows)
	{
		if (rows.size() > 128)
			throw std::runtime_error("KOS-Dot check chunk exceeds 128 rows. " LOCATION);

		std::array<block, 128> low;
		std::array<block, 128> high;
		low.fill(ZeroBlock);
		high.fill(ZeroBlock);
		for (u64 i = 0; i < rows.size(); ++i)
		{
			low[i] = rows[i][0];
			high[i] = rows[i][1];
		}

		transpose128(low.data());
		transpose128(high.data());

		KosDotColumnCheck columns;
		for (u64 i = 0; i < 128; ++i)
			columns[i] = low[i];
		for (u64 i = 128; i < KosDotCheckColumns; ++i)
			columns[i] = high[i - 128];
		return columns;
	}

	inline KosDotColumnCheck kosDotColumnCheck(
		span<const KosDotCheckRow> rows,
		span<const KosDotCheckRow> extraRows,
		block seed)
	{
		if (extraRows.size() != 128)
			throw std::runtime_error("KOS-Dot check requires 128 extra rows. " LOCATION);

		auto low = kosDotTransposeCheckChunk(extraRows);
		KosDotColumnCheck high;
		high.fill(ZeroBlock);
		PRNG commonPrng(seed, 128);

		for (u64 offset = 0; offset < rows.size(); offset += 128)
		{
			auto count = std::min<u64>(128, rows.size() - offset);
			auto columns = kosDotTransposeCheckChunk(
				span<const KosDotCheckRow>(rows.data() + offset, count));
			auto challenge = commonPrng.get<block>();

			for (u64 i = 0; i < KosDotCheckColumns; ++i)
			{
				block productLow, productHigh;
				columns[i].gf128Mul(challenge, productLow, productHigh);
				low[i] ^= productLow;
				high[i] ^= productHigh;
			}
		}

		for (u64 i = 0; i < KosDotCheckColumns; ++i)
			low[i] = low[i].gf128Reduce(high[i]);
		return low;
	}

	inline block kosDotChoiceCheck(
		const BitVector& choices,
		block extraChoices,
		block seed)
	{
		auto low = extraChoices;
		auto high = ZeroBlock;
		PRNG commonPrng(seed, 128);

		for (u64 offset = 0; offset < choices.size(); offset += 128)
		{
			auto count = std::min<u64>(128, choices.size() - offset);
			block packedChoices = ZeroBlock;
			if (count == 128)
			{
				packedChoices = choices.blocks()[offset / 128];
			}
			else
			{
				auto bytes = reinterpret_cast<u8*>(&packedChoices);
				for (u64 i = 0; i < count; ++i)
					bytes[i / 8] |= static_cast<u8>(choices[offset + i]) << (i % 8);
			}

			block productLow, productHigh;
			packedChoices.gf128Mul(
				commonPrng.get<block>(), productLow, productHigh);
			low ^= productLow;
			high ^= productHigh;
		}

		return low.gf128Reduce(high);
	}
}
