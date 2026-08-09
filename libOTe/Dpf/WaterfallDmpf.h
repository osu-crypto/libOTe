#pragma once

#include "libOTe/config.h"

#if defined(ENABLE_SPARSE_DPF)

#include "cryptoTools/Common/Timer.h"
#include "libOTe/Dpf/CachedDpfExpansion.h"
#include "libOTe/Dpf/DpfMult.h"
#include "libOTe/Dpf/RevCuckoo/Dedup.h"
#include "libOTe/Dpf/SparseDpf.h"
#include "libOTe/Dpf/Waterfall/WaterfallBasic.h"
#include "libOTe/Dpf/Waterfall/WaterfallCandidates.h"
#include "libOTe/Dpf/Waterfall/WaterfallConfig.h"
#include "libOTe/Dpf/Waterfall/WaterfallReachability.h"
#include "libOTe/Dpf/Waterfall/WaterfallScatter.h"
#include "libOTe/Tools/CoeffCtx.h"

#include <bit>
#include <limits>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

namespace osuCrypto
{
	/// Complete two-party Waterfall DMPF lifecycle.
	///
	/// setPoints performs the one-time hidden placement and punctured sparse-DPF
	/// generation. expand reuses that state for any number of payload vectors.
	template<typename T, typename CoeffCtx = DefaultCoeffCtx<T>>
	struct WaterfallDmpf : TimerAdapter
	{
		static constexpr bool NativeU64 =
			std::is_same_v<std::remove_cvref_t<T>, u64> &&
			std::is_same_v<std::remove_cvref_t<CoeffCtx>, CoeffCtxInteger>;

		// Public configuration and lifecycle state.
		u64 mPartyIdx = 0;
		u64 mNumPointsPerSet = 0;
		u64 mNumSets = 0;
		u64 mDomain = 0;
		u64 mIndexBitCount = 0;
		WaterfallConfig mConfig;
		bool mCharacteristicTwo = false;
		bool mSetupComplete = false;

		// Setup protocols. Their outputs are cached and reused by expand().
		std::vector<Dedup> mDedup;
		WaterfallCandidates mCandidateGenerator;
		WaterfallBasic mBasic;
		WaterfallReachability mReachability;
		WaterfallScatter mWaterfallScatter;
		SparseDpf mSparseDpf;
		// One cached point function per input row implements repeated value
		// scattering without rerunning the hidden column permutation online.
		SparseDpf mValueScatterDpf;
		DpfMult mMultiplier;
		DpfMult::MultSession mMultSession;
		DpfMult mValueScatterMultiplier;
		DpfMult::MultSession mValueScatterMultSession;
		DpfMult::MultSession mDedupBatchSession;
		AlignedUnVector<block> mDedupBatchRecvOts;
		AlignedUnVector<std::array<block, 2>> mDedupBatchSendOts;

		// Cached setup output. mOverflow is the secret-shared correctness-error
		// indicator; callers may inspect it in tests, but the protocol never opens it.
		WaterfallCandidates::Proposal mProposal;
		BitVector mOverflow;
		std::vector<std::vector<block>> mLeafShares;
		std::vector<std::vector<u8>> mLeafTags;
		std::vector<std::vector<block>> mValueScatterLeafShares;
		std::vector<std::vector<u8>> mValueScatterLeafTags;
		std::vector<std::span<u32>> mValueScatterSets;
		std::unique_ptr<u32[]> mValueScatterSetBuf;
		std::vector<std::span<u32>> mSparseSets;
		std::unique_ptr<u32[]> mSparseSetBuf;

		// Reusable online buffers. Keeping these allocations across expansions is
		// important for the repeated-expansion use case.
		using VecT = typename CoeffCtx::template Vec<T>;
		VecT mTempOutput;
		std::vector<VecT> mExpanded;
		VecT mValueRows;
		VecT mValuePayload;
		VecT mLeafSums;
		VecT mGamma;
		VecT mDifference;
		std::vector<VecT> mValueScatterExpanded;
		VecT mValueScatterSums;
		VecT mValueScatterGamma;
		VecT mValueScatterDifference;
		VecT mDedupBatchWork;
		block mValueScatterHashSeed = block(0x7363617474657221ull, 0x76616c75652d6470ull);
		block mLeafHashSeed = block(3498747860745238796ull, 2347966293789782347ull);

		struct BaseCount
		{
			u64 mRecvCount = 0;
			u64 mSendCount = 0;
		};

		void init(
			u64 partyIdx,
			u64 numPointsPerSet,
			u64 numSets,
			u64 domain,
			WaterfallConfig config,
			bool characteristicTwo = CoeffCtx{}.template characteristicTwo<T>())
		{
			config.validate();
			if (partyIdx > 1 || numPointsPerSet == 0 || numSets == 0 || domain < 2)
				throw std::invalid_argument("Waterfall dimensions must be nonzero. " LOCATION);
			if ((numPointsPerSet & (numPointsPerSet - 1)) != 0)
				throw std::invalid_argument("Waterfall currently requires a power-of-two point count. " LOCATION);
			const auto fieldBits = std::bit_width(domain - 1);
			if (fieldBits > 32 || (1ull << fieldBits) != domain)
				throw std::invalid_argument("Waterfall currently requires a power-of-two domain of at most 2^32. " LOCATION);

			// init() starts a fresh lifecycle and may safely be called after a prior
			// setup/expansion sequence.
			clear();

			mPartyIdx = partyIdx;
			mNumPointsPerSet = numPointsPerSet;
			mNumSets = numSets;
			mDomain = domain;
			mIndexBitCount = log2ceil(domain + 1);
			mConfig = std::move(config);
			mCharacteristicTwo = characteristicTwo;
			mValueScatterHashSeed = block(0x7363617474657221ull, 0x76616c75652d6470ull);
			mLeafHashSeed = block(3498747860745238796ull, 2347966293789782347ull);

			mDedup.resize(mNumSets);
			for (auto& dedup : mDedup)
				dedup.init(mPartyIdx, mNumPointsPerSet, mIndexBitCount);
			mCandidateGenerator.init(
				mPartyIdx,
				mNumPointsPerSet,
				mNumSets,
				mDomain,
				mIndexBitCount,
				mConfig);
			mBasic.init(mPartyIdx, mNumPointsPerSet, mNumSets, mConfig);
			mReachability.init(mPartyIdx, mNumPointsPerSet, mNumSets, mConfig);

			const auto columns = mConfig.numColumns();
			mWaterfallScatter.init(mPartyIdx, mNumPointsPerSet, mNumSets, columns);
			mSparseDpf.init(
				mPartyIdx,
				mNumSets * columns,
				mDomain,
				log2ceil(columns) + 2);
			mValueScatterDpf.init(
				mPartyIdx,
				mNumSets * mNumPointsPerSet,
				columns,
				log2ceil(columns));
			if (!mCharacteristicTwo)
			{
				mMultiplier.init(mPartyIdx, mNumSets * columns);
				mValueScatterMultiplier.init(
					mPartyIdx,
					mNumSets * mNumPointsPerSet);
			}
			else
			{
				mMultiplier.init(mPartyIdx, 0);
				mValueScatterMultiplier.init(mPartyIdx, 0);
			}
			mMultSession.clear();
			mValueScatterMultSession.clear();
		}

		BaseCount baseOtCount() const
		{
			BaseCount result;
			for (const auto& dedup : mDedup)
			{
				const auto count = dedup.baseOtCount();
				result.mRecvCount += count.mRecvCount;
				result.mSendCount += count.mSendCount;
			}
			const auto candidates = mCandidateGenerator.baseOtCount();
			const auto symmetric =
				mBasic.baseOtCount() +
				mReachability.baseOtCount() +
				mSparseDpf.baseOtCount() +
				mValueScatterDpf.baseOtCount() +
				mMultiplier.baseOtCount() +
				mValueScatterMultiplier.baseOtCount();
			result.mRecvCount += candidates.mRecvCount + symmetric;
			result.mSendCount += candidates.mSendCount + symmetric;

			const auto scatter = mWaterfallScatter.baseOtCount();
			result.mRecvCount += scatter.mRecvCount;
			result.mSendCount += scatter.mSendCount;
			return result;
		}

		void setBaseOts(
			span<const std::array<block, 2>> baseSend,
			span<const block> baseRecv,
			const BitVector& recvChoice)
		{
			const auto total = baseOtCount();
			if (baseSend.size() != total.mSendCount ||
				baseRecv.size() != total.mRecvCount ||
				recvChoice.size() != total.mRecvCount)
				throw std::invalid_argument("Waterfall base OT count mismatch. " LOCATION);

			u64 sendIndex = 0;
			u64 recvIndex = 0;
			auto set = [&](auto& protocol)
			{
				const auto count = protocol.baseOtCount();
				u64 sendCount;
				u64 recvCount;
				if constexpr (std::is_integral_v<decltype(count)>)
				{
					sendCount = count;
					recvCount = count;
				}
				else
				{
					sendCount = count.mSendCount;
					recvCount = count.mRecvCount;
				}
				protocol.setBaseOts(
					baseSend.subspan(sendIndex, sendCount),
					baseRecv.subspan(recvIndex, recvCount),
					recvChoice.subvec(recvIndex, recvCount));
				sendIndex += sendCount;
				recvIndex += recvCount;
			};

			for (auto& dedup : mDedup)
				set(dedup);
			set(mCandidateGenerator);
			set(mBasic);
			set(mReachability);
			set(mWaterfallScatter);
			set(mSparseDpf);
			set(mValueScatterDpf);
			if (!mCharacteristicTwo)
			{
				set(mMultiplier);
				set(mValueScatterMultiplier);
			}
			if (sendIndex != baseSend.size() || recvIndex != baseRecv.size())
				throw RTE_LOC;
		}

		bool hasBaseOts() const
		{
			return mSparseDpf.hasBaseOts() || mMultSession.mX.size();
		}

		macoro::task<WaterfallReachability::Result> route(
			MatrixView<const u32> candidates,
			coproto::Socket& socket)
		{
			auto basic = co_await mBasic.place(candidates, socket);
			setTimePoint("basic placement done");
			auto repaired = co_await mReachability.repair(
				candidates,
				basic.mMatching,
				basic.mDecoder,
				socket);
			setTimePoint("reachability repair done");
			co_return repaired;
		}

		Matrix<u32> buildSparseSets(const WaterfallCandidates::Proposal& proposal)
		{
			const auto w = mConfig.numPartitions();
			const auto columns = mConfig.numColumns();
			if (proposal.mCoefficients.rows() != mNumSets * w ||
				proposal.mCoefficients.cols() != mNumPointsPerSet)
				throw RTE_LOC;
			if (mNumSets > std::numeric_limits<u64>::max() / w ||
				mNumSets * w > std::numeric_limits<u64>::max() / mDomain)
				throw std::overflow_error("Waterfall sparse-set size overflow. " LOCATION);

			const auto totalMemberships = mNumSets * w * mDomain;
			mSparseSetBuf = std::make_unique<u32[]>(totalMemberships);
			mSparseSets.assign(mNumSets * columns, {});
			Matrix<u32> representatives(mNumSets, columns);

			u64 algebraicDegree = 0;
			for (u64 exponent = 0; exponent < mNumPointsPerSet; ++exponent)
				algebraicDegree = std::max<u64>(algebraicDegree, std::popcount(exponent));
			// In characteristic two, the coordinate functions of x^e have
			// algebraic degree at most popcount(e). Recover the sparse ANF from
			// low-weight inputs, pack four <=8-bit hashes per word, then evaluate
			// every domain point with one in-place subset transform.
			bool usePackedAnf = algebraicDegree <= 8 && w <= 4;
			for (auto size : mConfig.mPartitionSizes)
				usePackedAnf &= size <= 256;

			std::vector<u32> lowWeightPoints;
			std::vector<u32> samples;
			std::vector<u32> packedBins;
			std::vector<u32> bins0;
			std::vector<u32> bins1;
			if (usePackedAnf)
			{
				lowWeightPoints.reserve(mDomain / 64);
				for (u64 point = 0; point < mDomain; ++point)
					if (static_cast<u64>(std::popcount(point)) <= algebraicDegree)
						lowWeightPoints.push_back(static_cast<u32>(point));
				samples.resize(mDomain);
				packedBins.resize(mDomain);
			}
			else
			{
				bins0.resize(mDomain);
				bins1.resize(mDomain);
			}

			u64 flatOffset = 0;
			for (u64 set = 0; set < mNumSets; ++set)
			{
				u64 columnOffset = 0;
				auto materialize = [&](u64 partition, span<const u32> bins, u64 shift)
				{
					const auto size = mConfig.mPartitionSizes[partition];
					const auto mask = static_cast<u32>(size - 1);
					std::vector<u64> counts(size, 0);
					for (u64 point = 0; point < mDomain; ++point)
						++counts[(bins[point] >> shift) & mask];

					std::vector<u64> cursor(size);
					u64 localOffset = 0;
					for (u64 bin = 0; bin < size; ++bin)
					{
						cursor[bin] = localOffset;
						mSparseSets[set * columns + columnOffset + bin] =
							std::span<u32>(mSparseSetBuf.get() + flatOffset + localOffset, counts[bin]);
						localOffset += counts[bin];
					}
					if (localOffset != mDomain)
						throw RTE_LOC;
					for (u64 point = 0; point < mDomain; ++point)
					{
						const auto bin = (bins[point] >> shift) & mask;
						mSparseSetBuf[flatOffset + cursor[bin]++] = static_cast<u32>(point);
					}
					for (u64 bin = 0; bin < size; ++bin)
					{
						const auto& sparseSet =
							mSparseSets[set * columns + columnOffset + bin];
						// An empty public column can contain no real address. Use
						// the zero representative for any inactive physical record
						// and retain an empty cached DPF tree for this column.
						representatives(set, columnOffset + bin) =
							sparseSet.empty() ? 0 : sparseSet[0];
					}
					flatOffset += mDomain;
					columnOffset += size;
				};

				if (usePackedAnf)
				{
					std::fill(samples.begin(), samples.end(), 0);
					std::fill(packedBins.begin(), packedBins.end(), 0);
					std::vector<std::vector<u32>> sampled(
						w, std::vector<u32>(lowWeightPoints.size()));
					std::vector<u32> zeroCoefficients(mNumPointsPerSet, 0);
					std::vector<u32> scratch(lowWeightPoints.size());
					for (u64 partition = 0; partition < w; partition += 2)
					{
						const bool hasSecond = partition + 1 < w;
						mCandidateGenerator.mHash.evaluatePointPair(
							proposal.mCoefficients[set * w + partition],
							hasSecond
								? span<const u32>(proposal.mCoefficients[set * w + partition + 1])
								: span<const u32>(zeroCoefficients),
							mConfig.mPartitionSizes[partition],
							hasSecond ? mConfig.mPartitionSizes[partition + 1] : 1,
							lowWeightPoints,
							sampled[partition],
							hasSecond ? span<u32>(sampled[partition + 1]) : span<u32>(scratch));
					}
					for (u64 index = 0; index < lowWeightPoints.size(); ++index)
					{
						u32 packed = 0;
						for (u64 partition = 0; partition < w; ++partition)
							packed |= sampled[partition][index] << (8 * partition);
						samples[lowWeightPoints[index]] = packed;
					}
					for (u64 index = 0; index < lowWeightPoints.size(); ++index)
					{
						const auto point = lowWeightPoints[index];
						u32 coefficient = 0;
						u32 subset = point;
						do
						{
							coefficient ^= samples[subset];
							subset = (subset - 1) & point;
						} while (subset != point);
						packedBins[point] = coefficient;
					}
					for (u64 bit = 0; bit < mCandidateGenerator.mHash.fieldBits(); ++bit)
					{
						const u64 half = u64(1) << bit;
						const u64 stride = 2 * half;
						for (u64 base = 0; base < mDomain; base += stride)
							for (u64 offset = 0; offset < half; ++offset)
								packedBins[base + half + offset] ^= packedBins[base + offset];
					}
					for (u64 partition = 0; partition < w; ++partition)
						materialize(partition, packedBins, 8 * partition);
				}
				else
				{
					u64 partition = 0;
					for (; partition + 1 < w; partition += 2)
					{
						mCandidateGenerator.mHash.evaluateConsecutivePair(
							proposal.mCoefficients[set * w + partition],
							proposal.mCoefficients[set * w + partition + 1],
							mConfig.mPartitionSizes[partition],
							mConfig.mPartitionSizes[partition + 1],
							bins0,
							bins1);
						materialize(partition, bins0, 0);
						materialize(partition + 1, bins1, 0);
					}
					if (partition < w)
					{
						const auto size = mConfig.mPartitionSizes[partition];
						const auto coefficients = proposal.mCoefficients[set * w + partition];
						for (u64 point = 0; point < mDomain; ++point)
						bins0[point] = mCandidateGenerator.mHash.evaluatePlain(
							coefficients,
							static_cast<u32>(point),
							size);
						materialize(partition, bins0, 0);
					}
				}
			}
			if (flatOffset != totalMemberships)
				throw RTE_LOC;
			return representatives;
		}

		void cacheU64DedupSession()
		{
			// Pack the per-set sessions in exactly the order consumed by expand():
			// first D (rows 1..t-1), then C (all unordered row pairs).
			u64 total = 0;
			for (auto& dedup : mDedup)
				total += dedup.mMultSessionD.mX.size() + dedup.mMultSessionC.mX.size();

			mDedupBatchRecvOts.resize(total);
			mDedupBatchSendOts.resize(total);
			mDedupBatchSession.mX.resize(total);
			mDedupBatchSession.mPartyIdx = mPartyIdx;
			mDedupBatchSession.mExpandIdx = 0;

			u64 offset = 0;
			auto append = [&](DpfMult::MultSession& session)
			{
				const auto size = session.mX.size();
				std::copy(
					session.mRecvOts.begin(),
					session.mRecvOts.end(),
					mDedupBatchRecvOts.begin() + offset);
				std::copy(
					session.mSendOts.begin(),
					session.mSendOts.end(),
					mDedupBatchSendOts.begin() + offset);
				for (u64 i = 0; i < size; ++i)
					mDedupBatchSession.mX[offset + i] = session.mX[i];
				offset += size;
			};
			for (auto& dedup : mDedup)
			{
				append(dedup.mMultSessionD);
				append(dedup.mMultSessionC);
			}
			if (offset != total)
				throw RTE_LOC;

			mDedupBatchSession.mRecvOts = span<block>(
				mDedupBatchRecvOts.data(), mDedupBatchRecvOts.size());
			mDedupBatchSession.mSendOts = span<std::array<block, 2>>(
				mDedupBatchSendOts.data(), mDedupBatchSendOts.size());
		}

		macoro::task<> setPoints(
			MatrixView<const u64> points,
			PRNG& prng,
			coproto::Socket& socket)
		{
			MACORO_TRY
			{
				if (mSetupComplete)
					throw std::runtime_error("Waterfall setPoints can only be called once per initialization. " LOCATION);
				if (points.rows() != mNumSets || points.cols() != mNumPointsPerSet)
					throw std::invalid_argument("Waterfall point matrix has the wrong dimensions. " LOCATION);

				setTimePoint("setPoints");
				const auto addressBytes = divCeil(mIndexBitCount, 8);
				const auto numRows = mNumSets * mNumPointsPerSet;
				Matrix<u8> addresses(numRows, addressBytes);
				Matrix<u8> alternate(numRows, addressBytes);
				for (u64 set = 0; set < mNumSets; ++set)
					for (u64 row = 0; row < mNumPointsPerSet; ++row)
					{
						const auto index = set * mNumPointsPerSet + row;
						copyBytesMin(addresses[index], points(set, row));
						copyBytesMin(alternate[index], mDomain * mPartyIdx);
					}

				std::vector<task<>> tasks;
				std::vector<Socket> sockets(mNumSets);
				for (u64 set = 0; set < mNumSets; ++set)
				{
					sockets[set] = socket.fork();
					tasks.push_back(mDedup[set].dedupKeys(
						addresses.submtx(set * mNumPointsPerSet, mNumPointsPerSet),
						alternate.submtx(set * mNumPointsPerSet, mNumPointsPerSet),
						prng,
						sockets[set]));
				}
				auto ready = co_await macoro::when_all_ready(std::move(tasks));
				for (auto& result : ready)
					result.result();
				if constexpr (NativeU64)
					cacheU64DedupSession();
				setTimePoint("dedup done");

				auto candidateState = co_await mCandidateGenerator.prepare(addresses, prng, socket);
				mProposal = co_await mCandidateGenerator.sample(candidateState, prng, socket);
				setTimePoint("candidates done");

				auto placement = co_await route(mProposal.mCandidates, socket);
				mOverflow = placement.mOverflow;
				setTimePoint("placement done");

				auto maskedAddresses = co_await mCandidateGenerator.maskActive(
					candidateState,
					addresses,
					socket);
				auto representatives = buildSparseSets(mProposal);
				setTimePoint("sparse sets done");

				auto scattered = co_await mWaterfallScatter.scatterAddresses(
					maskedAddresses,
					candidateState.mActivity,
					placement.mPlacement,
					representatives,
					prng,
					socket);
				std::vector<u64> punctures(mNumSets * mConfig.numColumns());
				for (u64 i = 0; i < punctures.size(); ++i)
					copyBytesMin(punctures[i], scattered.mAddresses[i]);
				setTimePoint("scatter done");

				mLeafShares.resize(mSparseSets.size());
				mLeafTags.resize(mSparseSets.size());
				for (u64 tree = 0; tree < mSparseSets.size(); ++tree)
				{
					mLeafShares[tree].resize(mSparseSets[tree].size());
					mLeafTags[tree].resize(mSparseSets[tree].size());
				}
				co_await mSparseDpf.expand(
					punctures,
					{},
					[&](u64 tree, u64 leaf, block value, u8 tag)
					{
						mLeafShares[tree][leaf] = value;
						mLeafTags[tree][leaf] = tag;
					},
					prng,
					mSparseSets,
					socket);
				setTimePoint("sparse DPF done");

				// The inverse setup permutation also yields an XOR share of each
				// row's destination. Cache that hidden map as one point function per
				// row; later payloads then need only a short per-row correction.
				const auto columns = mConfig.numColumns();
				mValueScatterSetBuf = std::make_unique<u32[]>(columns);
				for (u64 column = 0; column < columns; ++column)
					mValueScatterSetBuf[column] = static_cast<u32>(column);
				mValueScatterSets.assign(
					numRows,
					std::span<u32>(mValueScatterSetBuf.get(), columns));
				mValueScatterLeafShares.assign(
					numRows,
					std::vector<block>(columns));
				mValueScatterLeafTags.assign(
					numRows,
					std::vector<u8>(columns));
				co_await mValueScatterDpf.expand(
					scattered.mDestinations,
					{},
					[&](u64 tree, u64 leaf, block value, u8 tag)
					{
						mValueScatterLeafShares[tree][leaf] = value;
						mValueScatterLeafTags[tree][leaf] = tag;
					},
					prng,
					mValueScatterSets,
					socket);
				setTimePoint("value scatter DPF done");

				if (!mCharacteristicTwo)
				{
					BitVector negate(mLeafTags.size());
					for (u64 tree = 0; tree < mLeafTags.size(); ++tree)
					{
						u64 tagSum = 0;
						for (auto tag : mLeafTags[tree])
							tagSum += tag;
						negate[tree] = ((tagSum / 2) & 1) ^ (mPartyIdx & (tagSum & 1));
					}
					mMultSession = co_await mMultiplier.setupMultiply(
						negate.size(),
						negate.getSpan<const u8>(),
						socket);

					BitVector scatterNegate(mValueScatterLeafTags.size());
					for (u64 tree = 0; tree < mValueScatterLeafTags.size(); ++tree)
					{
						u64 tagSum = 0;
						for (auto tag : mValueScatterLeafTags[tree])
							tagSum += tag;
						scatterNegate[tree] =
							((tagSum / 2) & 1) ^ (mPartyIdx & (tagSum & 1));
					}
					mValueScatterMultSession =
						co_await mValueScatterMultiplier.setupMultiply(
							scatterNegate.size(),
							scatterNegate.getSpan<const u8>(),
							socket);
				}
				mSetupComplete = true;
				setTimePoint("setPoints done");
			}
			MACORO_CATCH(exception)
			{
				co_await socket.close();
				std::rethrow_exception(exception);
			}
			co_return;
		}

		template<typename Output, typename = std::enable_if_t<
			std::is_lvalue_reference<Output>::value || std::is_object<Output>::value>>
		macoro::task<> expand(
			auto&& values,
			PRNG&,
			coproto::Socket& socket,
			Output output,
			CoeffCtx context = {})
		{
			if (!mSetupComplete)
				throw std::runtime_error("Waterfall setPoints must complete before expand. " LOCATION);
			if (values.size() != mNumPointsPerSet * mNumSets)
				throw std::invalid_argument("Waterfall value vector has the wrong size. " LOCATION);
			if (context.template characteristicTwo<T>() != mCharacteristicTwo)
				throw std::invalid_argument("Waterfall coefficient characteristic does not match init. " LOCATION);

			setTimePoint("expand");

#define WATERFALL_SIMD8(VAR, STATEMENT) do { \
	{ constexpr u64 VAR = 0; STATEMENT; } \
	{ constexpr u64 VAR = 1; STATEMENT; } \
	{ constexpr u64 VAR = 2; STATEMENT; } \
	{ constexpr u64 VAR = 3; STATEMENT; } \
	{ constexpr u64 VAR = 4; STATEMENT; } \
	{ constexpr u64 VAR = 5; STATEMENT; } \
	{ constexpr u64 VAR = 6; STATEMENT; } \
	{ constexpr u64 VAR = 7; STATEMENT; } \
} while (0)

			if (mValueRows.size() != values.size())
				context.resize(mValueRows, values.size());
			context.copy(values.begin(), values.end(), mValueRows.begin());
			if constexpr (NativeU64)
			{
				const auto pairsPerSet =
					mNumPointsPerSet * (mNumPointsPerSet - 1) / 2;
				const auto productsPerSet = mNumPointsPerSet - 1 + pairsPerSet;
				const auto products = mNumSets * productsPerSet;
				if (mDedupBatchSession.mX.size() != products)
					throw RTE_LOC;
				if (mDedupBatchWork.size() != products)
					mDedupBatchWork.resize(products);

				u64 product = 0;
				for (u64 set = 0; set < mNumSets; ++set)
				{
					const auto valueOffset = set * mNumPointsPerSet;
					for (u64 row = 1; row < mNumPointsPerSet; ++row)
						mDedupBatchWork[product++] = mValueRows[valueOffset + row];
					for (u64 row = 0; row < mNumPointsPerSet; ++row)
						for (u64 duplicate = row + 1;
							duplicate < mNumPointsPerSet;
							++duplicate)
							mDedupBatchWork[product++] =
								mValueRows[valueOffset + duplicate];
				}
				if (product != products)
					throw RTE_LOC;

				co_await mDedupBatchSession.multiply<u64>(
					mDedupBatchWork.begin(),
					mDedupBatchWork.end(),
					mDedupBatchWork.begin(),
					socket,
					CoeffCtxInteger{});

				product = 0;
				for (u64 set = 0; set < mNumSets; ++set)
				{
					const auto valueOffset = set * mNumPointsPerSet;
					for (u64 row = 1; row < mNumPointsPerSet; ++row)
						mValueRows[valueOffset + row] = mDedupBatchWork[product++];
					for (u64 row = 0; row < mNumPointsPerSet; ++row)
						for (u64 duplicate = row + 1;
							duplicate < mNumPointsPerSet;
							++duplicate)
							mValueRows[valueOffset + row] += mDedupBatchWork[product++];
				}
				if (product != products)
					throw RTE_LOC;
			}
			else
			{
				std::vector<task<>> tasks;
				std::vector<Socket> sockets(mNumSets);
				std::vector<span<T>> perSet;
				perSet.reserve(mNumSets);
				for (u64 set = 0; set < mNumSets; ++set)
				{
					perSet.emplace_back(
						mValueRows.data() + set * mNumPointsPerSet,
						mNumPointsPerSet);
					sockets[set] = socket.fork();
					tasks.push_back(mDedup[set].template dedupValues<T>(
						perSet[set], sockets[set], context));
				}
				auto ready = co_await macoro::when_all_ready(std::move(tasks));
				for (auto& result : ready)
					result.result();
			}
			setTimePoint("value dedup done");

			// Evaluate the cached hidden row-to-column map and accumulate each
			// deduplicated value into its secret destination column.
			const auto columns = mConfig.numColumns();
			const auto rows = mNumSets * mNumPointsPerSet;
			if (mValuePayload.size() != mNumSets * columns)
				context.resize(mValuePayload, mNumSets * columns);
			context.zero(mValuePayload.begin(), mValuePayload.end());
			if (mValueScatterExpanded.size() != rows)
				mValueScatterExpanded.resize(rows);
			if (mValueScatterSums.size() != rows)
				context.resize(mValueScatterSums, rows);
			context.zero(mValueScatterSums.begin(), mValueScatterSums.end());
			auto scatterZero = context.template make<T>();
			context.zero(scatterZero);
			AES scatterAes(mValueScatterHashSeed);
			mValueScatterHashSeed = scatterAes.hashBlock(
				block(0x7363617474657221ull, 0x686173682d736565ull));
			for (u64 row = 0; row < rows; ++row)
			{
				if (mValueScatterExpanded[row].size() != columns)
					context.resize(mValueScatterExpanded[row], columns);
				auto* expanded = mValueScatterExpanded[row].data();
				const auto* shares = mValueScatterLeafShares[row].data();
				const auto columns8 = columns / 8 * 8;
				for (u64 column = 0; column < columns8; column += 8)
				{
					WATERFALL_SIMD8(q, context.fromBlock(
						expanded[column + q],
						scatterAes.hashBlock(shares[column + q])));
					if (mPartyIdx)
						WATERFALL_SIMD8(q, context.minus(
							expanded[column + q], scatterZero, expanded[column + q]));
					WATERFALL_SIMD8(q, context.plus(
						mValueScatterSums[row],
						mValueScatterSums[row],
						expanded[column + q]));
				}
				for (u64 column = columns8; column < columns; ++column)
				{
					context.fromBlock(
						expanded[column], scatterAes.hashBlock(shares[column]));
					if (mPartyIdx)
						context.minus(expanded[column], scatterZero, expanded[column]);
					context.plus(
						mValueScatterSums[row],
						mValueScatterSums[row],
						expanded[column]);
				}
			}

			if (mValueScatterGamma.size() != rows)
				context.resize(mValueScatterGamma, rows);
			for (u64 row = 0; row < rows; ++row)
				context.minus(
					mValueScatterGamma[row], mValueRows[row], mValueScatterSums[row]);
			if (!mCharacteristicTwo)
			{
				if (mValueScatterMultSession.mX.size() != rows)
					throw RTE_LOC;
				if constexpr (NativeU64)
				{
					co_await mValueScatterMultSession.conditionalNegateU64(
						mValueScatterGamma.begin(),
						mValueScatterGamma.end(),
						socket);
				}
				else
				{
					if (mValueScatterDifference.size() != rows)
						context.resize(mValueScatterDifference, rows);
					for (u64 row = 0; row < rows; ++row)
						context.plus(
							mValueScatterDifference[row],
							mValueScatterGamma[row],
							mValueScatterGamma[row]);
					co_await mValueScatterMultSession.multiply<T>(
						mValueScatterDifference.begin(),
						mValueScatterDifference.end(),
						mValueScatterDifference.begin(),
						socket,
						context);
					for (u64 row = 0; row < rows; ++row)
						context.minus(
							mValueScatterGamma[row],
							mValueScatterGamma[row],
							mValueScatterDifference[row]);
				}
			}
			co_await reveal(mValueScatterGamma, socket, context);

			auto scatterTemporary = context.template makeVec<T>(8);
			for (u64 row = 0; row < rows; ++row)
			{
				const auto set = row / mNumPointsPerSet;
				const auto outputOffset = set * columns;
				const auto* tags = mValueScatterLeafTags[row].data();
				const auto* expanded = mValueScatterExpanded[row].data();
				const auto columns8 = columns / 8 * 8;
				for (u64 column = 0; column < columns8; column += 8)
				{
					WATERFALL_SIMD8(q, context.mask(
						scatterTemporary[q],
						mValueScatterGamma[row],
						block::allSame<u8>(-tags[column + q])));
					if (mPartyIdx)
						WATERFALL_SIMD8(q, context.minus(
							scatterTemporary[q],
							expanded[column + q],
							scatterTemporary[q]));
					else
						WATERFALL_SIMD8(q, context.plus(
							scatterTemporary[q],
							expanded[column + q],
							scatterTemporary[q]));
					WATERFALL_SIMD8(q, context.plus(
						mValuePayload[outputOffset + column + q],
						mValuePayload[outputOffset + column + q],
						scatterTemporary[q]));
				}
				for (u64 column = columns8; column < columns; ++column)
				{
					context.mask(
						scatterTemporary[0],
						mValueScatterGamma[row],
						block::allSame<u8>(-tags[column]));
					if (mPartyIdx)
						context.minus(
							scatterTemporary[0], expanded[column], scatterTemporary[0]);
					else
						context.plus(
							scatterTemporary[0], expanded[column], scatterTemporary[0]);
					context.plus(
						mValuePayload[outputOffset + column],
						mValuePayload[outputOffset + column],
						scatterTemporary[0]);
				}
			}
			setTimePoint("value scatter done");

			details::expandCachedDpfLeaves<T>(
				mPartyIdx,
				mSparseSets,
				mLeafShares,
				mExpanded,
				mLeafSums,
				mLeafHashSeed,
				context);
			setTimePoint("leaf expansion done");

			if (mGamma.size() != mSparseSets.size())
				context.resize(mGamma, mSparseSets.size());
			for (u64 tree = 0; tree < mGamma.size(); ++tree)
				context.minus(mGamma[tree], mValuePayload[tree], mLeafSums[tree]);
			if (!mCharacteristicTwo)
			{
				if (mMultSession.mX.size() != mGamma.size())
					throw RTE_LOC;
				if constexpr (NativeU64)
				{
					co_await mMultSession.conditionalNegateU64(
						mGamma.begin(), mGamma.end(), socket);
				}
				else
				{
					if (mDifference.size() != mGamma.size())
						context.resize(mDifference, mGamma.size());
					for (u64 tree = 0; tree < mGamma.size(); ++tree)
						context.plus(mDifference[tree], mGamma[tree], mGamma[tree]);
					co_await mMultSession.multiply<T>(
						mDifference.begin(),
						mDifference.end(),
						mDifference.begin(),
						socket,
						context);
					for (u64 tree = 0; tree < mGamma.size(); ++tree)
						context.minus(mGamma[tree], mGamma[tree], mDifference[tree]);
				}
			}
			co_await reveal(mGamma, socket, context);
			setTimePoint("gamma done");

			details::applyCachedDpfUpdates<T>(
				mPartyIdx,
				mNumSets,
				columns,
				mDomain,
				mSparseSets,
				mLeafTags,
				mExpanded,
				mGamma,
				mTempOutput,
				output,
				context);

#undef WATERFALL_SIMD8
			setTimePoint("expand done");
			co_return;
		}

		task<> reveal(auto&& values, Socket& socket, auto&& context)
		{
			if constexpr (NativeU64)
			{
				std::vector<u64> wire(values.begin(), values.end());
				co_await socket.send(std::move(wire));
				wire.resize(values.size());
				co_await socket.recv(wire);
				for (u64 i = 0; i < values.size(); ++i)
					values[i] += wire[i];
			}
			else
			{
				auto remote = context.template makeVec<T>(values.size());
				std::vector<u8> buffer(values.size() * context.template byteSize<T>());
				context.serialize(values.begin(), values.end(), buffer.begin());
				co_await socket.send(std::move(buffer));
				buffer.resize(values.size() * context.template byteSize<T>());
				co_await socket.recv(buffer);
				context.deserialize(buffer.begin(), buffer.end(), remote.begin());
				for (u64 i = 0; i < values.size(); ++i)
					context.plus(values[i], values[i], remote[i]);
			}
		}

		void clear()
		{
			mDedup.clear();
			mWaterfallScatter.clear();
			mSparseDpf.clear();
			mValueScatterDpf.clear();
			mMultiplier.clear();
			mMultSession.clear();
			mValueScatterMultiplier.clear();
			mValueScatterMultSession.clear();
			mDedupBatchSession.clear();
			mDedupBatchRecvOts.clear();
			mDedupBatchSendOts.clear();
			mProposal = {};
			mOverflow = {};
			mLeafShares.clear();
			mLeafTags.clear();
			mValueScatterLeafShares.clear();
			mValueScatterLeafTags.clear();
			mValueScatterSets.clear();
			mValueScatterSetBuf.reset();
			mSparseSets.clear();
			mSparseSetBuf.reset();
			mExpanded.clear();
			mValueScatterExpanded.clear();
			mTempOutput.clear();
			mValueRows.clear();
			mValuePayload.clear();
			mLeafSums.clear();
			mGamma.clear();
			mDifference.clear();
			mValueScatterSums.clear();
			mValueScatterGamma.clear();
			mValueScatterDifference.clear();
			mDedupBatchWork.clear();
			mPartyIdx = 0;
			mNumPointsPerSet = 0;
			mNumSets = 0;
			mDomain = 0;
			mIndexBitCount = 0;
			mConfig = {};
			mCharacteristicTwo = false;
			mSetupComplete = false;
		}
	};
}

#endif
