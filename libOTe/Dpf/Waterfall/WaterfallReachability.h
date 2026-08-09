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
	/// Complete bounded augmenting-path repair for a compact Waterfall matching.
	///
	/// All descriptors are evaluated in lockstep. Occupancy is represented by
	/// an implicit owner table, so a DFS edge costs logarithmic rather than
	/// linear work in the number of rows.
	class WaterfallReachability
	{
		u64 mPartyIdx = 0;
		u64 mRowsPerSet = 0;
		u64 mNumSets = 0;
		u64 mNumRows = 0;
		u64 mRowBits = 0;
		WaterfallConfig mConfig;
		Matrix<u8> mWideInput;
		Matrix<u8> mWideOutput;

		macoro::task<> multiplyRecords(
			const BitVector& control,
			span<const BitVector> input,
			span<BitVector> output,
			coproto::Socket& socket)
		{
			const auto count = control.size();
			if (input.size() != count || output.size() != count || count == 0)
				throw RTE_LOC;
			const auto bits = input[0].size();
			const auto bytes = divCeil(bits, 8);
			mWideInput.resize(count, bytes);
			mWideOutput.resize(count, bytes);
			std::fill(mWideInput.begin(), mWideInput.end(), 0);
			for (u64 item = 0; item < count; ++item)
			{
				if (input[item].size() != bits)
					throw RTE_LOC;
				for (u64 i = 0; i < bits; ++i)
					*BitIterator(mWideInput[item].data(), i) = input[item][i];
			}
			co_await mMultiplier.multiply(
				bits,
				control.getSpan<const u8>(),
				mWideInput,
				mWideOutput,
				socket);
			for (u64 item = 0; item < count; ++item)
			{
				output[item].resize(bits);
				for (u64 i = 0; i < bits; ++i)
					output[item][i] = bit(mWideOutput[item], i);
			}
		}

		macoro::task<> multiplyRecords(
			DpfMult::MultSession& session,
			span<const BitVector> input,
			span<BitVector> output,
			coproto::Socket& socket)
		{
			const auto count = session.mX.size();
			if (input.size() != count || output.size() != count || count == 0)
				throw RTE_LOC;
			const auto bits = input[0].size();
			const auto bytes = divCeil(bits, 8);
			mWideInput.resize(count, bytes);
			mWideOutput.resize(count, bytes);
			std::fill(mWideInput.begin(), mWideInput.end(), 0);
			for (u64 item = 0; item < count; ++item)
			{
				if (input[item].size() != bits)
					throw RTE_LOC;
				for (u64 i = 0; i < bits; ++i)
					*BitIterator(mWideInput[item].data(), i) = input[item][i];
			}
			auto context = DpfMult::BitMatrixCoeffCtx(bits);
			auto inputView = DpfMult::BitMatrixCoeffCtx::View<const u8>(mWideInput);
			auto outputView = DpfMult::BitMatrixCoeffCtx::View<u8>(mWideOutput);
			co_await session.multiply<u8, DpfMult::BitMatrixCoeffCtx>(
				inputView.begin(),
				inputView.end(),
				outputView.begin(),
				socket,
				context);
			for (u64 item = 0; item < count; ++item)
			{
				output[item].resize(bits);
				for (u64 i = 0; i < bits; ++i)
					output[item][i] = bit(mWideOutput[item], i);
			}
		}

		macoro::task<BitVector> andBits(
			const BitVector& left,
			const BitVector& right,
			coproto::Socket& socket)
		{
			if (left.size() != right.size())
				throw RTE_LOC;
			BitVector result(left.size());
			co_await mMultiplier.multiplyBits(left, right, result, socket);
			co_return result;
		}

		/// Each input is a packed array of fixed-width records. The array length
		/// must be a power of two. One secret mux is evaluated per index bit.
		macoro::task<std::vector<BitVector>> readRecords(
			span<const BitVector> table,
			span<const u32> indexShare,
			u64 recordBits,
			coproto::Socket& socket)
		{
			if (table.size() != indexShare.size() || table.empty() || recordBits == 0)
				throw RTE_LOC;
			std::vector<BitVector> current(table.begin(), table.end());
			std::vector<BitVector> difference(table.size());
			std::vector<BitVector> selected(table.size());
			for (u64 level = 0; current[0].size() > recordBits; ++level)
			{
				const auto records = current[0].size() / recordBits;
				if ((records & 1) != 0)
					throw RTE_LOC;
				const auto nextRecords = records / 2;
				BitVector control(table.size());
				for (u64 item = 0; item < table.size(); ++item)
				{
					control[item] = (indexShare[item] >> level) & 1;
					difference[item].resize(nextRecords * recordBits);
					for (u64 record = 0; record < nextRecords; ++record)
						for (u64 bitIndex = 0; bitIndex < recordBits; ++bitIndex)
							difference[item][record * recordBits + bitIndex] =
								current[item][(2 * record) * recordBits + bitIndex] ^
								current[item][(2 * record + 1) * recordBits + bitIndex];
				}
				co_await multiplyRecords(control, difference, selected, socket);
				for (u64 item = 0; item < table.size(); ++item)
				{
					BitVector next(nextRecords * recordBits);
					for (u64 record = 0; record < nextRecords; ++record)
						for (u64 bitIndex = 0; bitIndex < recordBits; ++bitIndex)
							next[record * recordBits + bitIndex] =
								current[item][(2 * record) * recordBits + bitIndex] ^
								selected[item][record * recordBits + bitIndex];
					current[item] = std::move(next);
				}
			}
			co_return current;
		}

		macoro::task<std::vector<BitVector>> readRecords(
			span<const BitVector> table,
			span<const u32> indexShare,
			u64 recordBits,
			std::vector<DpfMult::MultSession>& sessions,
			coproto::Socket& socket)
		{
			if (table.size() != indexShare.size() || table.empty() || recordBits == 0)
				throw RTE_LOC;
			std::vector<BitVector> current(table.begin(), table.end());
			std::vector<BitVector> difference(table.size());
			std::vector<BitVector> selected(table.size());
			sessions.clear();
			for (u64 level = 0; current[0].size() > recordBits; ++level)
			{
				const auto records = current[0].size() / recordBits;
				if ((records & 1) != 0)
					throw RTE_LOC;
				const auto nextRecords = records / 2;
				BitVector control(table.size());
				for (u64 item = 0; item < table.size(); ++item)
				{
					control[item] = (indexShare[item] >> level) & 1;
					difference[item].resize(nextRecords * recordBits);
					for (u64 record = 0; record < nextRecords; ++record)
						for (u64 bitIndex = 0; bitIndex < recordBits; ++bitIndex)
							difference[item][record * recordBits + bitIndex] =
								current[item][(2 * record) * recordBits + bitIndex] ^
								current[item][(2 * record + 1) * recordBits + bitIndex];
				}
				sessions.emplace_back(co_await mMultiplier.setupMultiply(
					control.size(),
					control.getSpan<const u8>(),
					socket));
				co_await multiplyRecords(sessions.back(), difference, selected, socket);
				for (u64 item = 0; item < table.size(); ++item)
				{
					BitVector next(nextRecords * recordBits);
					for (u64 record = 0; record < nextRecords; ++record)
						for (u64 bitIndex = 0; bitIndex < recordBits; ++bitIndex)
							next[record * recordBits + bitIndex] =
								current[item][(2 * record) * recordBits + bitIndex] ^
								selected[item][record * recordBits + bitIndex];
					current[item] = std::move(next);
				}
			}
			co_return current;
		}

		macoro::task<std::vector<BitVector>> unitVectors(
			span<const u32> indexShare,
			const BitVector& valueShare,
			u64 size,
			coproto::Socket& socket)
		{
			if (indexShare.size() != valueShare.size() || indexShare.empty() ||
				size == 0 || (size & (size - 1)) != 0)
				throw RTE_LOC;
			std::vector<BitVector> current(indexShare.size(), BitVector(1));
			std::vector<BitVector> right(indexShare.size());
			for (u64 item = 0; item < indexShare.size(); ++item)
				current[item][0] = valueShare[item];
			for (u64 remaining = std::bit_width(size - 1); remaining; --remaining)
			{
				const auto level = remaining - 1;
				BitVector control(indexShare.size());
				for (u64 item = 0; item < indexShare.size(); ++item)
					control[item] = (indexShare[item] >> level) & 1;
				co_await multiplyRecords(control, current, right, socket);
				for (u64 item = 0; item < indexShare.size(); ++item)
				{
					BitVector next(current[item].size() * 2);
					for (u64 i = 0; i < current[item].size(); ++i)
					{
						next[2 * i] = current[item][i] ^ right[item][i];
						next[2 * i + 1] = right[item][i];
					}
					current[item] = std::move(next);
				}
			}
			co_return current;
		}

		macoro::task<std::vector<BitVector>> unitVectors(
			const BitVector& valueShare,
			u64 size,
			span<DpfMult::MultSession> sessions,
			coproto::Socket& socket)
		{
			if (valueShare.size() == 0 || size == 0 || (size & (size - 1)) != 0 ||
				sessions.size() != static_cast<u64>(std::bit_width(size - 1)))
				throw RTE_LOC;
			std::vector<BitVector> current(valueShare.size(), BitVector(1));
			std::vector<BitVector> right(valueShare.size());
			for (u64 item = 0; item < valueShare.size(); ++item)
				current[item][0] = valueShare[item];
			for (u64 remaining = sessions.size(); remaining; --remaining)
			{
				const auto level = remaining - 1;
				co_await multiplyRecords(sessions[level], current, right, socket);
				for (u64 item = 0; item < valueShare.size(); ++item)
				{
					BitVector next(current[item].size() * 2);
					for (u64 i = 0; i < current[item].size(); ++i)
					{
						next[2 * i] = current[item][i] ^ right[item][i];
						next[2 * i + 1] = right[item][i];
					}
					current[item] = std::move(next);
				}
			}
			co_return current;
		}

		u64 multiplicationCount() const
		{
			const auto t = mRowsPerSet;
			const auto w = mConfig.numPartitions();
			const auto ownerProducts = mNumRows * w;
			u64 ownerReads = 0;
			for (auto size : mConfig.mPartitionSizes)
				ownerReads += mNumRows * std::bit_width(size - 1);
			const auto forwardPerStep = mNumSets *
				(t + 2 * mRowBits + 3 * w + 2 + w * mRowBits);
			const auto backtrack = mNumSets *
				((w - 1) + (t - 1) * (2 * mRowBits + w) + t);
			return mConfig.mRepairLimit *
				(ownerProducts + ownerReads + t * forwardPerStep + backtrack) +
				mNumRows * w;
		}

	public:
		struct Result
		{
			BitVector mMatching;
			BitVector mOverflow;
			BitVector mPlacement;
		};

		DpfMult mMultiplier;

		void init(
			u64 partyIdx,
			u64 rowsPerSet,
			u64 numSets,
			WaterfallConfig config)
		{
			config.validate();
			if (partyIdx > 1 || rowsPerSet == 0 || numSets == 0 ||
				(rowsPerSet & (rowsPerSet - 1)) != 0)
				throw std::invalid_argument("Reachability requires a nonzero power-of-two row count. " LOCATION);
			mPartyIdx = partyIdx;
			mRowsPerSet = rowsPerSet;
			mNumSets = numSets;
			mNumRows = rowsPerSet * numSets;
			mRowBits = std::bit_width(rowsPerSet - 1);
			mConfig = std::move(config);
			mMultiplier.init(mPartyIdx, multiplicationCount());
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

		macoro::task<Result> repair(
			MatrixView<const u32> candidates,
			const BitVector& initialMatching,
			const std::vector<std::vector<BitVector>>& decoder,
			coproto::Socket& socket)
		{
			const auto t = mRowsPerSet;
			const auto w = mConfig.numPartitions();
			const auto h = mRowBits;
			if (candidates.rows() != mNumRows || candidates.cols() != w ||
				initialMatching.size() != mNumRows * w || decoder.size() != w)
				throw RTE_LOC;
			for (u64 partition = 0; partition < w; ++partition)
				if (decoder[partition].size() != mNumRows)
					throw RTE_LOC;

			BitVector matching = initialMatching;

			for (u64 round = 0; round < mConfig.mRepairLimit; ++round)
			{
				BitVector unmatched(mNumRows);
				for (u64 row = 0; row < mNumRows; ++row)
				{
					unmatched[row] = mPartyIdx;
					for (u64 partition = 0; partition < w; ++partition)
						unmatched[row] ^= matching[row * w + partition];
				}

				std::vector<std::vector<BitVector>> ownerRecord(w);
				std::vector<std::vector<u8>> occupancy(w, std::vector<u8>(mNumRows));
				std::vector<std::vector<u32>> owner(w, std::vector<u32>(mNumRows));
				std::vector<u8> ownerBuilt(w);
				for (u64 pivot = 0; pivot < w; ++pivot)
				{
					if (ownerBuilt[pivot])
						continue;
					std::vector<u64> group;
					for (u64 partition = pivot; partition < w; ++partition)
						if (!ownerBuilt[partition] &&
							mConfig.mPartitionSizes[partition] == mConfig.mPartitionSizes[pivot])
						{
							ownerBuilt[partition] = 1;
							group.push_back(partition);
						}

					BitVector controls(group.size() * mNumRows);
					std::vector<BitVector> decoderInput(group.size() * mNumRows);
					std::vector<BitVector> selected(group.size() * mNumRows);
					for (u64 member = 0; member < group.size(); ++member)
						for (u64 row = 0; row < mNumRows; ++row)
						{
							const auto item = member * mNumRows + row;
							controls[item] = matching[row * w + group[member]];
							decoderInput[item] = decoder[group[member]][row];
						}
					co_await multiplyRecords(controls, decoderInput, selected, socket);

					const auto d = mConfig.mPartitionSizes[pivot];
					std::vector<BitVector> tables(group.size() * mNumSets, BitVector(d * (h + 1)));
					for (u64 member = 0; member < group.size(); ++member)
						for (u64 set = 0; set < mNumSets; ++set)
							for (u64 row = 0; row < t; ++row)
							{
								const auto globalRow = set * t + row;
								const auto item = member * mNumRows + globalRow;
								auto& table = tables[member * mNumSets + set];
								for (u64 bin = 0; bin < d; ++bin)
								{
									table[bin * (h + 1)] ^= selected[item][bin];
									for (u64 b = 0; b < h; ++b)
										if ((row >> b) & 1)
											table[bin * (h + 1) + 1 + b] ^= selected[item][bin];
								}
							}

					std::vector<BitVector> repeated(group.size() * mNumRows);
					std::vector<u32> index(group.size() * mNumRows);
					for (u64 member = 0; member < group.size(); ++member)
						for (u64 row = 0; row < mNumRows; ++row)
						{
							const auto item = member * mNumRows + row;
							repeated[item] = tables[member * mNumSets + row / t];
							index[item] = candidates(row, group[member]);
						}
					auto groupOwner = co_await readRecords(repeated, index, h + 1, socket);
					for (u64 member = 0; member < group.size(); ++member)
					{
						const auto partition = group[member];
						ownerRecord[partition].resize(mNumRows);
						for (u64 row = 0; row < mNumRows; ++row)
						{
							const auto item = member * mNumRows + row;
							ownerRecord[partition][row] = std::move(groupOwner[item]);
							occupancy[partition][row] = ownerRecord[partition][row][0];
							for (u64 b = 0; b < h; ++b)
								owner[partition][row] |=
									u32(ownerRecord[partition][row][1 + b]) << b;
						}
					}
				}

				std::vector<BitVector> visited(mNumSets, BitVector(t));
				std::vector<BitVector> expanded(mNumSets, BitVector(t));
				std::vector<BitVector> parent(mNumSets, BitVector(t * h));
				std::vector<BitVector> parentPartition(mNumSets, BitVector(t * w));
				std::vector<BitVector> hitRow(mNumSets, BitVector(t));
				std::vector<BitVector> hitPartition(mNumSets, BitVector(w));
				BitVector hit(mNumSets);
				for (u64 set = 0; set < mNumSets; ++set)
					for (u64 row = 0; row < t; ++row)
						visited[set][row] = unmatched[set * t + row];

				for (u64 step = 0; step < t; ++step)
				{
					std::vector<BitVector> selectedRow(mNumSets, BitVector(t));
					BitVector prefix(mNumSets);
					for (u64 row = 0; row < t; ++row)
					{
						BitVector frontier(mNumSets);
						for (u64 set = 0; set < mNumSets; ++set)
							frontier[set] = visited[set][row] ^ expanded[set][row];
						BitVector first;
						if (row == 0)
							first = frontier;
						else
						{
							BitVector notPrefix(mNumSets);
							for (u64 set = 0; set < mNumSets; ++set)
								notPrefix[set] = prefix[set] ^ mPartyIdx;
							first = co_await andBits(frontier, notPrefix, socket);
						}
						for (u64 set = 0; set < mNumSets; ++set)
						{
							selectedRow[set][row] = first[set];
							prefix[set] ^= first[set];
						}
					}
					BitVector active = prefix;
					std::vector<u32> rowIndex(mNumSets);
					for (u64 set = 0; set < mNumSets; ++set)
					{
						for (u64 row = 0; row < t; ++row)
							if (row)
								for (u64 b = 0; b < h; ++b)
									if ((row >> b) & 1)
										rowIndex[set] ^= u32(selectedRow[set][row]) << b;
						expanded[set] ^= selectedRow[set];
					}
					BitVector notHit(mNumSets);
					for (u64 set = 0; set < mNumSets; ++set)
						notHit[set] = hit[set] ^ mPartyIdx;
					auto gamma = co_await andBits(active, notHit, socket);

					const auto rowRecordBits = w * (h + 1);
					std::vector<BitVector> rowTables(mNumSets, BitVector(t * rowRecordBits));
					for (u64 set = 0; set < mNumSets; ++set)
						for (u64 row = 0; row < t; ++row)
							for (u64 partition = 0; partition < w; ++partition)
							{
								const auto globalRow = set * t + row;
								const auto offset = row * rowRecordBits + partition * (h + 1);
								rowTables[set][offset] = occupancy[partition][globalRow];
								for (u64 b = 0; b < h; ++b)
									rowTables[set][offset + 1 + b] = (owner[partition][globalRow] >> b) & 1;
							}
					auto currentRecord = co_await readRecords(rowTables, rowIndex, rowRecordBits, socket);
					BitVector freePrefix(mNumSets);
					std::vector<BitVector> freeFirst(w, BitVector(mNumSets));
					std::vector<BitVector> currentOccupancy(w, BitVector(mNumSets));
					std::vector<std::vector<u32>> currentOwner(w, std::vector<u32>(mNumSets));
					BitVector gammaRepeated(mNumSets * w);
					BitVector notOccupied(mNumSets * w);
					for (u64 partition = 0; partition < w; ++partition)
					{
						for (u64 set = 0; set < mNumSets; ++set)
						{
							const auto item = partition * mNumSets + set;
							const auto offset = partition * (h + 1);
							currentOccupancy[partition][set] = currentRecord[set][offset];
							gammaRepeated[item] = gamma[set];
							notOccupied[item] = currentRecord[set][offset] ^ mPartyIdx;
							for (u64 b = 0; b < h; ++b)
								currentOwner[partition][set] |= u32(currentRecord[set][offset + 1 + b]) << b;
						}
					}
					auto allFree = co_await andBits(gammaRepeated, notOccupied, socket);
					for (u64 partition = 0; partition < w; ++partition)
					{
						BitVector free(mNumSets);
						for (u64 set = 0; set < mNumSets; ++set)
							free[set] = allFree[partition * mNumSets + set];
						if (partition == 0)
							freeFirst[partition] = free;
						else
						{
							BitVector notEarlier(mNumSets);
							for (u64 set = 0; set < mNumSets; ++set)
								notEarlier[set] = freePrefix[set] ^ mPartyIdx;
							freeFirst[partition] = co_await andBits(free, notEarlier, socket);
						}
						freePrefix ^= freeFirst[partition];
					}
					const auto beta = freePrefix;
					std::vector<BitVector> betaInput = selectedRow;
					std::vector<BitVector> betaOutput(mNumSets);
					co_await multiplyRecords(beta, betaInput, betaOutput, socket);
					for (u64 set = 0; set < mNumSets; ++set)
					{
						hitRow[set] ^= betaOutput[set];
						for (u64 partition = 0; partition < w; ++partition)
							hitPartition[set][partition] ^= freeFirst[partition][set];
						hit[set] ^= beta[set];
					}
					BitVector notBeta(mNumSets);
					for (u64 set = 0; set < mNumSets; ++set)
						notBeta[set] = beta[set] ^ mPartyIdx;
					auto explore = co_await andBits(gamma, notBeta, socket);
					std::vector<BitVector> occupancyInput(mNumSets, BitVector(w));
					for (u64 set = 0; set < mNumSets; ++set)
						for (u64 partition = 0; partition < w; ++partition)
							occupancyInput[set][partition] = currentOccupancy[partition][set];
					std::vector<BitVector> reached(mNumSets);
					co_await multiplyRecords(explore, occupancyInput, reached, socket);

					std::vector<BitVector> insertedAny(mNumSets, BitVector(t));
					for (u64 partition = 0; partition < w; ++partition)
					{
						std::vector<BitVector> ownerTables(mNumSets);
						std::vector<u32> ownerIndex(mNumSets);
						std::vector<DpfMult::MultSession> ownerSessions;
						for (u64 set = 0; set < mNumSets; ++set)
						{
							ownerTables[set] = visited[set];
							ownerIndex[set] = currentOwner[partition][set];
						}
						auto ownerVisited = co_await readRecords(
							ownerTables,
							ownerIndex,
							1,
							ownerSessions,
							socket);
						BitVector reachedBits(mNumSets);
						BitVector notVisited(mNumSets);
						for (u64 set = 0; set < mNumSets; ++set)
						{
							reachedBits[set] = reached[set][partition];
							notVisited[set] = ownerVisited[set][0] ^ mPartyIdx;
						}
						auto insertControl = co_await andBits(reachedBits, notVisited, socket);
						auto inserted = co_await unitVectors(
							insertControl,
							t,
							ownerSessions,
							socket);
						for (u64 set = 0; set < mNumSets; ++set)
						{
							visited[set] ^= inserted[set];
							insertedAny[set] ^= inserted[set];
							for (u64 row = 0; row < t; ++row)
								parentPartition[set][row * w + partition] ^= inserted[set][row];
						}
					}

					BitVector parentControl(mNumSets * h);
					std::vector<BitVector> parentInput(mNumSets * h);
					std::vector<BitVector> parentOutput(mNumSets * h);
					for (u64 set = 0; set < mNumSets; ++set)
						for (u64 b = 0; b < h; ++b)
						{
							const auto item = set * h + b;
							parentControl[item] = (rowIndex[set] >> b) & 1;
							parentInput[item] = insertedAny[set];
						}
					co_await multiplyRecords(parentControl, parentInput, parentOutput, socket);
					for (u64 set = 0; set < mNumSets; ++set)
						for (u64 b = 0; b < h; ++b)
							for (u64 row = 0; row < t; ++row)
								parent[set][row * h + b] ^= parentOutput[set * h + b][row];
				}

				std::vector<BitVector> pathRows = hitRow;
				std::vector<BitVector> pathEdges(mNumSets, BitVector(t * w));
				{
					std::vector<BitVector> output;
					if (w > 1)
					{
						BitVector controls(mNumSets * (w - 1));
						std::vector<BitVector> input(mNumSets * (w - 1));
						output.resize(mNumSets * (w - 1));
						for (u64 set = 0; set < mNumSets; ++set)
							for (u64 partition = 1; partition < w; ++partition)
							{
								const auto item = set * (w - 1) + partition - 1;
								controls[item] = hitPartition[set][partition];
								input[item] = hitRow[set];
							}
						co_await multiplyRecords(controls, input, output, socket);
					}
					for (u64 set = 0; set < mNumSets; ++set)
					{
						for (u64 row = 0; row < t; ++row)
							pathEdges[set][row * w] ^= hitRow[set][row];
						for (u64 partition = 1; partition < w; ++partition)
						{
							const auto item = set * (w - 1) + partition - 1;
							for (u64 row = 0; row < t; ++row)
							{
								pathEdges[set][row * w] ^= output[item][row];
								pathEdges[set][row * w + partition] ^= output[item][row];
							}
						}
					}
				}

				std::vector<BitVector> current = hitRow;
				for (u64 step = 0; step + 1 < t; ++step)
				{
					std::vector<u32> rowIndex(mNumSets);
					BitVector active(mNumSets);
					for (u64 set = 0; set < mNumSets; ++set)
						for (u64 row = 0; row < t; ++row)
						{
							active[set] ^= current[set][row];
							for (u64 b = 0; b < h; ++b)
								if ((row >> b) & 1)
									rowIndex[set] ^= u32(current[set][row]) << b;
						}

					const auto recordBits = 1 + h + w;
					std::vector<BitVector> tables(mNumSets, BitVector(t * recordBits));
					for (u64 set = 0; set < mNumSets; ++set)
						for (u64 row = 0; row < t; ++row)
						{
							const auto globalRow = set * t + row;
							tables[set][row * recordBits] = unmatched[globalRow];
							for (u64 b = 0; b < h; ++b)
								tables[set][row * recordBits + 1 + b] = parent[set][row * h + b];
							for (u64 partition = 0; partition < w; ++partition)
								tables[set][row * recordBits + 1 + h + partition] =
									parentPartition[set][row * w + partition];
						}
					auto record = co_await readRecords(tables, rowIndex, recordBits, socket);
					BitVector notRoot(mNumSets);
					for (u64 set = 0; set < mNumSets; ++set)
						notRoot[set] = record[set][0] ^ mPartyIdx;
					auto follow = co_await andBits(active, notRoot, socket);
					std::vector<u32> parentIndex(mNumSets);
					for (u64 set = 0; set < mNumSets; ++set)
						for (u64 b = 0; b < h; ++b)
							parentIndex[set] |= u32(record[set][1 + b]) << b;
					current = co_await unitVectors(parentIndex, follow, t, socket);
					for (u64 set = 0; set < mNumSets; ++set)
						pathRows[set] ^= current[set];

					std::vector<BitVector> output;
					if (w > 1)
					{
						BitVector controls(mNumSets * (w - 1));
						std::vector<BitVector> input(mNumSets * (w - 1));
						output.resize(mNumSets * (w - 1));
						for (u64 set = 0; set < mNumSets; ++set)
							for (u64 partition = 1; partition < w; ++partition)
							{
								const auto item = set * (w - 1) + partition - 1;
								controls[item] = record[set][1 + h + partition];
								input[item] = current[set];
							}
						co_await multiplyRecords(controls, input, output, socket);
					}
					for (u64 set = 0; set < mNumSets; ++set)
					{
						for (u64 row = 0; row < t; ++row)
							pathEdges[set][row * w] ^= current[set][row];
						for (u64 partition = 1; partition < w; ++partition)
						{
							const auto item = set * (w - 1) + partition - 1;
							for (u64 row = 0; row < t; ++row)
							{
								pathEdges[set][row * w] ^= output[item][row];
								pathEdges[set][row * w + partition] ^= output[item][row];
							}
						}
					}
				}

				BitVector pathControl(mNumRows);
				std::vector<BitVector> matchingRows(mNumRows, BitVector(w));
				std::vector<BitVector> removed(mNumRows);
				for (u64 set = 0; set < mNumSets; ++set)
					for (u64 row = 0; row < t; ++row)
					{
						const auto globalRow = set * t + row;
						pathControl[globalRow] = pathRows[set][row];
						for (u64 partition = 0; partition < w; ++partition)
							matchingRows[globalRow][partition] = matching[globalRow * w + partition];
					}
				co_await multiplyRecords(pathControl, matchingRows, removed, socket);
				for (u64 set = 0; set < mNumSets; ++set)
					for (u64 row = 0; row < t; ++row)
					{
						const auto globalRow = set * t + row;
						for (u64 partition = 0; partition < w; ++partition)
							matching[globalRow * w + partition] ^=
								removed[globalRow][partition] ^ pathEdges[set][row * w + partition];
					}
			}

			Result result;
			result.mMatching = std::move(matching);
			result.mOverflow.resize(mNumRows);
			for (u64 row = 0; row < mNumRows; ++row)
			{
				result.mOverflow[row] = mPartyIdx;
				for (u64 partition = 0; partition < w; ++partition)
					result.mOverflow[row] ^= result.mMatching[row * w + partition];
			}

			const auto columns = mConfig.numColumns();
			result.mPlacement.resize(mNumRows * columns);
			std::vector<u64> columnOffset(w);
			for (u64 partition = 1; partition < w; ++partition)
				columnOffset[partition] = columnOffset[partition - 1] +
					mConfig.mPartitionSizes[partition - 1];
			std::vector<u8> placementBuilt(w);
			for (u64 pivot = 0; pivot < w; ++pivot)
			{
				if (placementBuilt[pivot])
					continue;
				std::vector<u64> group;
				for (u64 partition = pivot; partition < w; ++partition)
					if (!placementBuilt[partition] &&
						mConfig.mPartitionSizes[partition] == mConfig.mPartitionSizes[pivot])
					{
						placementBuilt[partition] = 1;
						group.push_back(partition);
					}
				BitVector controls(group.size() * mNumRows);
				std::vector<BitVector> decoderInput(group.size() * mNumRows);
				std::vector<BitVector> selected(group.size() * mNumRows);
				for (u64 member = 0; member < group.size(); ++member)
					for (u64 row = 0; row < mNumRows; ++row)
					{
						const auto item = member * mNumRows + row;
						controls[item] = result.mMatching[row * w + group[member]];
						decoderInput[item] = decoder[group[member]][row];
					}
				co_await multiplyRecords(controls, decoderInput, selected, socket);
				for (u64 member = 0; member < group.size(); ++member)
					for (u64 row = 0; row < mNumRows; ++row)
						for (u64 bin = 0; bin < mConfig.mPartitionSizes[pivot]; ++bin)
							result.mPlacement[row * columns + columnOffset[group[member]] + bin] =
								selected[member * mNumRows + row][bin];
			}
			co_return result;
		}
	};
}
