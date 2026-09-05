#pragma once

#include "WaterfallConfig.h"
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include "libOTe/Dpf/DpfMult.h"

#include <bit>
#include <stdexcept>
#include <utility>
#include <vector>

namespace osuCrypto
{
	/// OT-packed implementation of the ordered basic Waterfall scan.
	///
	/// Descriptors are processed in lockstep: each secret-index mux level and
	/// each unit-vector level uses one batched DpfMult call across all sets.
	/// The output is the compact row-to-partition matching and overflow vector.
	class WaterfallBasic
	{
		u64 mPartyIdx = 0;
		u64 mRowsPerSet = 0;
		u64 mNumSets = 0;
		u64 mNumRows = 0;
		WaterfallConfig mConfig;
		Matrix<u8> mWideInput;
		Matrix<u8> mWideOutput;

		macoro::task<> multiplyWide(
			const BitVector& control,
			span<const BitVector> input,
			span<BitVector> output,
			coproto::Socket& socket)
		{
			if (control.size() != mNumSets || input.size() != mNumSets || output.size() != mNumSets)
				throw RTE_LOC;
			const auto bits = input[0].size();
			const auto bytes = divCeil(bits, 8);
			mWideInput.resize(mNumSets, bytes);
			mWideOutput.resize(mNumSets, bytes);
			std::fill(mWideInput.begin(), mWideInput.end(), 0);
			for (u64 set = 0; set < mNumSets; ++set)
			{
				if (input[set].size() != bits)
					throw RTE_LOC;
				for (u64 i = 0; i < bits; ++i)
					*BitIterator(mWideInput[set].data(), i) = input[set][i];
			}

			co_await mMultiplier.multiply(
				bits,
				control.getSpan<const u8>(),
				mWideInput,
				mWideOutput,
				socket);
			for (u64 set = 0; set < mNumSets; ++set)
			{
				output[set].resize(bits);
				for (u64 i = 0; i < bits; ++i)
					output[set][i] = bit(mWideOutput[set], i);
			}
		}

		macoro::task<std::vector<u8>> multiplyBits(
			span<const u8> left,
			span<const u8> right,
			coproto::Socket& socket)
		{
			if (left.size() != mNumSets || right.size() != mNumSets)
				throw RTE_LOC;
			BitVector x(mNumSets), y(mNumSets), product(mNumSets);
			for (u64 set = 0; set < mNumSets; ++set)
			{
				x[set] = left[set];
				y[set] = right[set];
			}
			co_await mMultiplier.multiplyBits(x, y, product, socket);
			std::vector<u8> result(mNumSets);
			for (u64 set = 0; set < mNumSets; ++set)
				result[set] = product[set];
			co_return result;
		}

		macoro::task<std::vector<u8>> read(
			span<const BitVector> table,
			span<const u32> indexShare,
			coproto::Socket& socket)
		{
			if (table.size() != mNumSets || indexShare.size() != mNumSets)
				throw RTE_LOC;
			std::vector<BitVector> current(table.begin(), table.end());
			std::vector<BitVector> difference(mNumSets);
			std::vector<BitVector> selected(mNumSets);
			for (u64 level = 0; current[0].size() > 1; ++level)
			{
				const auto nextSize = current[0].size() / 2;
				BitVector control(mNumSets);
				for (u64 set = 0; set < mNumSets; ++set)
				{
					control[set] = (indexShare[set] >> level) & 1;
					difference[set].resize(nextSize);
					for (u64 i = 0; i < nextSize; ++i)
						difference[set][i] = current[set][2 * i] ^ current[set][2 * i + 1];
				}
				co_await multiplyWide(control, difference, selected, socket);
				for (u64 set = 0; set < mNumSets; ++set)
				{
					BitVector next(nextSize);
					for (u64 i = 0; i < nextSize; ++i)
						next[i] = current[set][2 * i] ^ selected[set][i];
					current[set] = std::move(next);
				}
			}

			std::vector<u8> result(mNumSets);
			for (u64 set = 0; set < mNumSets; ++set)
				result[set] = current[set][0];
			co_return result;
		}

		struct DecoderPair
		{
			std::vector<BitVector> mRaw;
			std::vector<BitVector> mGated;
		};

		macoro::task<DecoderPair> unitVectorPair(
			span<const u32> indexShare,
			span<const u8> valueShare,
			u64 size,
			coproto::Socket& socket)
		{
			if (indexShare.size() != mNumSets || valueShare.size() != mNumSets)
				throw RTE_LOC;
			DecoderPair result{
				std::vector<BitVector>(mNumSets, BitVector(1)),
				std::vector<BitVector>(mNumSets, BitVector(1))
			};
			for (u64 set = 0; set < mNumSets; ++set)
			{
				result.mRaw[set][0] = mPartyIdx;
				result.mGated[set][0] = valueShare[set];
			}

			const auto levels = std::bit_width(size - 1);
			for (u64 remaining = levels; remaining; --remaining)
			{
				const auto level = remaining - 1;
				BitVector control(mNumSets);
				std::vector<BitVector> packed(mNumSets);
				std::vector<BitVector> selected(mNumSets);
				for (u64 set = 0; set < mNumSets; ++set)
				{
					control[set] = (indexShare[set] >> level) & 1;
					const auto width = result.mRaw[set].size();
					packed[set].resize(2 * width);
					for (u64 i = 0; i < width; ++i)
					{
						packed[set][i] = result.mRaw[set][i];
						packed[set][width + i] = result.mGated[set][i];
					}
				}
				co_await multiplyWide(control, packed, selected, socket);
				for (u64 set = 0; set < mNumSets; ++set)
				{
					const auto width = result.mRaw[set].size();
					BitVector rawNext(2 * width);
					BitVector gatedNext(2 * width);
					for (u64 i = 0; i < width; ++i)
					{
						const auto rawRight = selected[set][i];
						const auto gatedRight = selected[set][width + i];
						rawNext[2 * i] = result.mRaw[set][i] ^ rawRight;
						rawNext[2 * i + 1] = rawRight;
						gatedNext[2 * i] = result.mGated[set][i] ^ gatedRight;
						gatedNext[2 * i + 1] = gatedRight;
					}
					result.mRaw[set] = std::move(rawNext);
					result.mGated[set] = std::move(gatedNext);
				}
			}
			co_return result;
		}

	public:
		struct Result
		{
			BitVector mMatching;
			BitVector mOverflow;
			std::vector<std::vector<BitVector>> mDecoder;
		};

		DpfMult mMultiplier;

		void init(u64 partyIdx, u64 rowsPerSet, WaterfallConfig config)
		{
			init(partyIdx, rowsPerSet, 1, std::move(config));
		}

		void init(
			u64 partyIdx,
			u64 rowsPerSet,
			u64 numSets,
			WaterfallConfig config)
		{
			config.validate();
			if (partyIdx > 1 || rowsPerSet == 0 || numSets == 0)
				throw std::invalid_argument("Invalid basic Waterfall parameters. " LOCATION);
			mPartyIdx = partyIdx;
			mRowsPerSet = rowsPerSet;
			mNumSets = numSets;
			mNumRows = rowsPerSet * numSets;
			mConfig = std::move(config);

			u64 productsPerRow = 0;
			u64 maxBytes = 1;
			for (auto size : mConfig.mPartitionSizes)
			{
				const auto bits = std::bit_width(size - 1);
				productsPerRow += 2 * bits + 1;
				maxBytes = std::max(maxBytes, divCeil(size, 8));
			}
			mMultiplier.init(mPartyIdx, mNumRows * productsPerRow);
			mWideInput.resize(mNumSets, maxBytes);
			mWideOutput.resize(mNumSets, maxBytes);
		}

		u64 baseOtCount() const
		{
			return mMultiplier.baseOtCount();
		}

		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const BitVector& baseChoices)
		{
			mMultiplier.setBaseOts(baseSendOts, recvBaseOts, baseChoices);
		}

		macoro::task<Result> place(
			MatrixView<const u32> candidates,
			coproto::Socket& socket)
		{
			const auto w = mConfig.numPartitions();
			if (candidates.rows() != mNumRows || candidates.cols() != w)
				throw RTE_LOC;

			Result result;
			result.mMatching.resize(mNumRows * w);
			result.mOverflow.resize(mNumRows);
			result.mDecoder.resize(w, std::vector<BitVector>(mNumRows));
			BitVector live(mNumRows);
			for (u64 row = 0; row < mNumRows; ++row)
				live[row] = mPartyIdx;

			std::vector<u32> candidateShare(mNumSets);
			std::vector<u8> liveShare(mNumSets);
			for (u64 partition = 0; partition < w; ++partition)
			{
				const auto size = mConfig.mPartitionSizes[partition];
				std::vector<BitVector> occupancy(mNumSets, BitVector(size));
				for (u64 row = 0; row < mRowsPerSet; ++row)
				{
					for (u64 set = 0; set < mNumSets; ++set)
					{
						const auto globalRow = set * mRowsPerSet + row;
						candidateShare[set] = candidates(globalRow, partition);
						liveShare[set] = live[globalRow];
					}

					auto occupied = co_await read(occupancy, candidateShare, socket);
					auto loss = co_await multiplyBits(liveShare, occupied, socket);
					std::vector<u8> winner(mNumSets);
					for (u64 set = 0; set < mNumSets; ++set)
						winner[set] = liveShare[set] ^ loss[set];
					auto decoder = co_await unitVectorPair(candidateShare, winner, size, socket);

					for (u64 set = 0; set < mNumSets; ++set)
					{
						const auto globalRow = set * mRowsPerSet + row;
						result.mMatching[globalRow * w + partition] = winner[set];
						occupancy[set] ^= decoder.mGated[set];
						result.mDecoder[partition][globalRow] = std::move(decoder.mRaw[set]);
						live[globalRow] = loss[set];
					}
				}
			}
			result.mOverflow = std::move(live);
			co_return result;
		}
	};
}
