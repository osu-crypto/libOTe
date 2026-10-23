#pragma once

#include "WaterfallConfig.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <vector>

namespace osuCrypto
{
	/// Cleartext reference for the Waterfall placement generator.
	///
	/// This is a correctness oracle for the fixed-size MPC circuit. It first
	/// scans partitions in order, then applies deterministic augmenting-path
	/// repairs to the earliest unplaced row. Candidate bins are partition-local
	/// and stored row-major as candidates[row * w + partition].
	struct WaterfallPlacement
	{
		static constexpr u32 NoIndex = std::numeric_limits<u32>::max();

		struct Result
		{
			bool mSuccess = false;
			u64 mRepairs = 0;
			std::vector<u32> mPartitionByRow;
			std::vector<u32> mColumnByRow;
		};

	private:
		struct AugmentState
		{
			const WaterfallConfig& mConfig;
			span<const u32> mCandidates;
			span<const u32> mOffsets;
			span<u32> mOwner;
			span<u32> mPartitionByRow;
			span<u32> mColumnByRow;
			span<u8> mSeenRows;
			span<u8> mSeenColumns;

			bool augment(u32 row)
			{
				if (mSeenRows[row])
					return false;
				mSeenRows[row] = 1;

				const auto w = mConfig.numPartitions();
				for (u64 s = 0; s < w; ++s)
				{
					const auto column = mOffsets[s] + mCandidates[row * w + s];
					if (mSeenColumns[column])
						continue;
					mSeenColumns[column] = 1;

					const auto victim = mOwner[column];
					if (victim == NoIndex || augment(victim))
					{
						mOwner[column] = row;
						mPartitionByRow[row] = static_cast<u32>(s);
						mColumnByRow[row] = column;
						return true;
					}
				}
				return false;
			}
		};

	public:

		static Result generate(
			const WaterfallConfig& config,
			u64 numRows,
			span<const u32> candidates)
		{
			config.validate();
			const auto w = config.numPartitions();
			if (numRows > std::numeric_limits<u32>::max())
				throw std::invalid_argument("Waterfall row count exceeds its u32 representation. " LOCATION);
			if (candidates.size() != numRows * w)
				throw std::invalid_argument("Waterfall candidate matrix has the wrong size. " LOCATION);

			std::vector<u32> offsets(w);
			u64 columns64 = 0;
			for (u64 s = 0; s < w; ++s)
			{
				offsets[s] = static_cast<u32>(columns64);
				columns64 += config.mPartitionSizes[s];
			}
			const auto columns = static_cast<u32>(columns64);

			for (u64 row = 0; row < numRows; ++row)
				for (u64 s = 0; s < w; ++s)
					if (candidates[row * w + s] >= config.mPartitionSizes[s])
						throw std::invalid_argument("Waterfall candidate is outside its partition. " LOCATION);

			Result result;
			result.mPartitionByRow.assign(numRows, NoIndex);
			result.mColumnByRow.assign(numRows, NoIndex);
			std::vector<u32> owner(columns, NoIndex);

			// Basic Waterfall: each partition accepts the first currently unplaced
			// row at a bin. Later rows overflow to the next partition.
			for (u64 s = 0; s < w; ++s)
			{
				for (u64 row = 0; row < numRows; ++row)
				{
					if (result.mPartitionByRow[row] != NoIndex)
						continue;
					const auto column = offsets[s] + candidates[row * w + s];
					if (owner[column] == NoIndex)
					{
						owner[column] = row;
						result.mPartitionByRow[row] = static_cast<u32>(s);
						result.mColumnByRow[row] = column;
					}
				}
			}

			std::vector<u8> seenRows(numRows);
			std::vector<u8> seenColumns(columns);
			for (u64 repair = 0; repair < config.mRepairLimit; ++repair)
			{
				auto root = std::find(
					result.mPartitionByRow.begin(),
					result.mPartitionByRow.end(),
					NoIndex);
				if (root == result.mPartitionByRow.end())
					break;

				std::fill(seenRows.begin(), seenRows.end(), 0);
				std::fill(seenColumns.begin(), seenColumns.end(), 0);
				const auto rootRow = static_cast<u32>(root - result.mPartitionByRow.begin());

				AugmentState state{
					config,
					candidates,
					offsets,
					owner,
					result.mPartitionByRow,
					result.mColumnByRow,
					seenRows,
					seenColumns
				};
				if (!state.augment(rootRow))
					break;
				++result.mRepairs;
			}

			result.mSuccess = std::none_of(
				result.mPartitionByRow.begin(),
				result.mPartitionByRow.end(),
				[](u32 partition) { return partition == NoIndex; });
			return result;
		}
	};
}
