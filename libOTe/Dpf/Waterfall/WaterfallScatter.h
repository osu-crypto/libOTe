#pragma once

#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include "libOTe/Dpf/DpfMult.h"
#include "libOTe/Dpf/Waterfall/SerialWaksmanPermute.h"

#include <algorithm>
#include <stdexcept>
#include <vector>

namespace osuCrypto
{
	/// Permutation-assisted scatter for Waterfall placement records.
	///
	/// The hidden permutation is exactly uniform: each party privately samples
	/// one Waksman pass and the two passes are applied serially.
	class WaterfallScatter
	{
		u64 mPartyIdx = 0;
		u64 mRowsPerSet = 0;
		u64 mNumSets = 0;
		u64 mNumRows = 0;
		u64 mColumns = 0;
	public:
		struct Result
		{
			BitVector mActivity;
			Matrix<u8> mAddresses;
			// XOR shares of the original column selected by every input row.
			std::vector<u64> mDestinations;
		};

		SerialWaksmanPermute mPermutation;

		void init(
			u64 partyIdx,
			u64 rowsPerSet,
			u64 numSets,
			u64 columns)
		{
			if (partyIdx > 1 || rowsPerSet == 0 || numSets == 0 || columns == 0)
				throw std::invalid_argument("Invalid Waterfall scatter parameters. " LOCATION);
			mPartyIdx = partyIdx;
			mRowsPerSet = rowsPerSet;
			mNumSets = numSets;
			mNumRows = rowsPerSet * numSets;
			mColumns = columns;
			mPermutation.init(partyIdx, columns, numSets);
		}

		auto baseOtCount() const
		{
			return mPermutation.baseOtCount();
		}

		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const BitVector& baseChoices)
		{
			mPermutation.setBaseOts(baseSendOts, recvBaseOts, baseChoices);
		}

		macoro::task<Result> scatterAddresses(
			MatrixView<const u8> maskedAddresses,
			const BitVector& activity,
			const BitVector& placement,
			MatrixView<const u32> representatives,
			PRNG& prng,
			coproto::Socket& socket)
		{
			if (maskedAddresses.rows() != mNumRows || activity.size() != mNumRows ||
				placement.size() != mNumRows * mColumns ||
				representatives.rows() != mNumSets || representatives.cols() != mColumns)
				throw std::invalid_argument("Waterfall scatter input dimensions do not match init. " LOCATION);
			mPermutation.sample(prng);

			const auto placementBytes = divCeil(mRowsPerSet, 8);
			std::vector<Matrix<u8>> hiddenPlacement(
				mNumSets,
				Matrix<u8>(mColumns, placementBytes));
			for (auto& set : hiddenPlacement)
				std::fill(set.begin(), set.end(), 0);
			for (u64 set = 0; set < mNumSets; ++set)
				for (u64 column = 0; column < mColumns; ++column)
					for (u64 row = 0; row < mRowsPerSet; ++row)
						*BitIterator(hiddenPlacement[set].data(column), row) =
							placement[(set * mRowsPerSet + row) * mColumns + column];

			auto placementContext = DpfMult::BitMatrixCoeffCtx(mRowsPerSet);
			using PlacementView = DpfMult::BitMatrixCoeffCtx::View<u8>;
			std::vector<PlacementView> placementView;
			placementView.reserve(mNumSets);
			for (auto& set : hiddenPlacement)
				placementView.emplace_back(set);
			co_await mPermutation.applyMany<u8, PlacementView>(
				placementView,
				socket,
				placementContext);

			// The exact uniform permutation hides which original row owns each
			// placement vector. Opening the permuted vectors therefore exposes only
			// the shuffled records needed to construct the inverse-routed payload.
			std::vector<Matrix<u8>> openedPlacement;
			openedPlacement.reserve(mNumSets);
			for (u64 set = 0; set < mNumSets; ++set)
				co_await socket.send(coproto::copy(hiddenPlacement[set]));
			for (u64 set = 0; set < mNumSets; ++set)
			{
				Matrix<u8> remote(mColumns, placementBytes);
				co_await socket.recv(remote);
				for (u64 i = 0; i < remote.size(); ++i)
					remote(i) ^= hiddenPlacement[set](i);
				openedPlacement.emplace_back(std::move(remote));
			}
			const auto addressBytes = maskedAddresses.cols();
			const auto rowBytes = divCeil(mRowsPerSet, 8);
			const auto recordBytes = 1 + addressBytes + rowBytes;
			std::vector<Matrix<u8>> records(
				mNumSets,
				Matrix<u8>(mColumns, recordBytes));
			for (auto& set : records)
				std::fill(set.begin(), set.end(), 0);
			for (u64 set = 0; set < mNumSets; ++set)
				for (u64 column = 0; column < mColumns; ++column)
					for (u64 row = 0; row < mRowsPerSet; ++row)
						if (bit(openedPlacement[set][column], row))
						{
							const auto globalRow = set * mRowsPerSet + row;
							records[set](column, 0) ^= activity[globalRow];
							for (u64 byte = 0; byte < addressBytes; ++byte)
								records[set](column, 1 + byte) ^=
									maskedAddresses(globalRow, byte);
							if (mPartyIdx == 0)
								*BitIterator(
									records[set].data(column) + 1 + addressBytes,
									row) = 1;
						}
			auto recordContext = DpfMult::BitMatrixCoeffCtx(recordBytes * 8);
			using RecordView = DpfMult::BitMatrixCoeffCtx::View<u8>;
			std::vector<RecordView> recordView;
			recordView.reserve(mNumSets);
			for (auto& set : records)
				recordView.emplace_back(set);
			co_await mPermutation.applyManyInverse<u8, RecordView>(
				recordView,
				socket,
				recordContext);
			Result result;
			result.mActivity.resize(mNumSets * mColumns);
			result.mAddresses.resize(mNumSets * mColumns, addressBytes);
			result.mDestinations.resize(mNumRows);
			for (u64 set = 0; set < mNumSets; ++set)
				for (u64 column = 0; column < mColumns; ++column)
				{
					const auto output = set * mColumns + column;
					result.mActivity[output] = records[set](column, 0) & 1;
					for (u64 byte = 0; byte < addressBytes; ++byte)
						result.mAddresses(output, byte) = records[set](column, 1 + byte);
					for (u64 row = 0; row < mRowsPerSet; ++row)
						if (bit(span<const u8>(
							records[set].data(column) + 1 + addressBytes,
							rowBytes), row))
							result.mDestinations[set * mRowsPerSet + row] ^= column;

					const auto inactive = result.mActivity[output] ^ mPartyIdx;
					const auto representative = representatives(set, column);
					for (u64 bitIndex = 0; bitIndex < std::min<u64>(32, addressBytes * 8); ++bitIndex)
						if ((representative >> bitIndex) & 1)
							*BitIterator(result.mAddresses.data(output), bitIndex) ^= inactive;
				}
			co_return result;
		}

		void clear()
		{
			mPermutation.clear();
			mPartyIdx = 0;
			mRowsPerSet = 0;
			mNumSets = 0;
			mNumRows = 0;
			mColumns = 0;
		}
	};
}
