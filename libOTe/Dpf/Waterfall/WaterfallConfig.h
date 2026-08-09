#pragma once

#include "cryptoTools/Common/Defines.h"

#include <limits>
#include <stdexcept>
#include <vector>

namespace osuCrypto
{
	/// Public Waterfall table geometry.
	///
	/// Each real row has one candidate column in every partition. Repair performs
	/// at most mRepairLimit complete augmenting-path rounds. The concrete compact
	/// profiles below were generated for t=16; callers using another t should
	/// supply and validate a separately generated configuration.
	struct WaterfallConfig
	{
		std::vector<u64> mPartitionSizes;
		u64 mRepairLimit = 0;

		void validate() const
		{
			if (mPartitionSizes.empty())
				throw std::invalid_argument("Waterfall requires at least one partition. " LOCATION);

			u64 columns = 0;
			for (auto size : mPartitionSizes)
			{
				if (size == 0 || (size & (size - 1)) != 0)
					throw std::invalid_argument("Waterfall partition sizes must be powers of two. " LOCATION);
				if (size > std::numeric_limits<u32>::max() ||
					columns > std::numeric_limits<u32>::max() - size)
					throw std::invalid_argument("Waterfall column count exceeds the u32 sparse-set representation. " LOCATION);
				columns += size;
			}
		}

		u64 numPartitions() const
		{
			return mPartitionSizes.size();
		}

		u64 numColumns() const
		{
			u64 result = 0;
			for (auto size : mPartitionSizes)
				result += size;
			return result;
		}

		u64 expansionFactor() const
		{
			return numPartitions();
		}

		static WaterfallConfig compact4N()
		{
			// t=16, four 16-column partitions, expansion 4N.
			return { { 16, 16, 16, 16 }, 3 };
		}

		static WaterfallConfig compact3N()
		{
			// t=16, three partitions totaling 20t columns, expansion 3N.
			return { { 128, 128, 64 }, 2 };
		}
	};
}
