#pragma once

#include "WaterfallConfig.h"
#include "WaterfallHash.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Dpf/DpfMult.h"
#include "libOTe/Dpf/RevCuckoo/Equality.h"
#include "libOTe/Tools/CoeffCtx.h"

#include <bit>
#include <limits>
#include <type_traits>
#include <utility>

namespace osuCrypto
{
	/// Produces the exactly uniform Waterfall candidate matrix.
	///
	/// Address-dependent powers and the real/dummy activity bit are prepared
	/// once. Each proposal then coin-tosses fresh public polynomial hashes and
	/// selects independent shared uniform values for dummy rows.
	class WaterfallCandidates
	{
		u64 mPartyIdx = 0;
		u64 mRowsPerSet = 0;
		u64 mNumSets = 0;
		u64 mNumRows = 0;
		u64 mDomain = 0;
		u64 mIndexBits = 0;
		WaterfallConfig mConfig;
		DpfMult::MultSession mSelectorSession;

	public:
		struct BaseCount
		{
			u64 mRecvCount = 0;
			u64 mSendCount = 0;
		};

		struct State
		{
			BitVector mActivity;
			WaterfallHash::Powers mPowers;
		};

		struct Proposal
		{
			block mPublicSeed = ZeroBlock;
			Matrix<u32> mCoefficients;
			Matrix<u32> mCandidates;
		};

		HybEquality mActivityEquality;
		WaterfallHash mHash;
		DpfMult mSelector;

		void init(
			u64 partyIdx,
			u64 rowsPerSet,
			u64 numSets,
			u64 domain,
			u64 indexBits,
			WaterfallConfig config)
		{
			config.validate();
			if (partyIdx > 1 || rowsPerSet == 0 || numSets == 0 || domain == 0)
				throw std::invalid_argument("Invalid Waterfall candidate parameters. " LOCATION);
			const auto fieldBits = static_cast<u64>(std::bit_width(domain - 1));
			if (fieldBits > 32 || (1ull << fieldBits) != domain || indexBits < fieldBits + 1)
				throw std::invalid_argument("Waterfall candidates require N=2^ell<=2^32 and an ell+1 bit dummy label. " LOCATION);

			mPartyIdx = partyIdx;
			mRowsPerSet = rowsPerSet;
			mNumSets = numSets;
			mNumRows = rowsPerSet * numSets;
			mDomain = domain;
			mIndexBits = indexBits;
			mConfig = std::move(config);
			mActivityEquality.init(mPartyIdx, mNumRows, mIndexBits);
			mHash.init(mPartyIdx, mNumRows, mRowsPerSet, fieldBits);
			mSelector.init(mPartyIdx, mNumRows);
		}

		BaseCount baseOtCount() const
		{
			const auto equality = mActivityEquality.baseOtCount();
			const auto symmetric = mHash.baseOtCount() + mSelector.baseOtCount();
			return {
				equality.mRecvCount + symmetric,
				equality.mSendCount + symmetric
			};
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
				throw std::invalid_argument("Waterfall candidate base OT count mismatch. " LOCATION);

			const auto equality = mActivityEquality.baseOtCount();
			mActivityEquality.setBaseOts(
				baseSend.subspan(0, equality.mSendCount),
				baseRecv.subspan(0, equality.mRecvCount),
				recvChoice.subvec(0, equality.mRecvCount));
			u64 sendIndex = equality.mSendCount;
			u64 recvIndex = equality.mRecvCount;
			auto setSymmetric = [&](auto& protocol)
			{
				const auto count = protocol.baseOtCount();
				protocol.setBaseOts(
					baseSend.subspan(sendIndex, count),
					baseRecv.subspan(recvIndex, count),
					recvChoice.subvec(recvIndex, count));
				sendIndex += count;
				recvIndex += count;
			};
			setSymmetric(mHash);
			setSymmetric(mSelector);
			if (sendIndex != baseSend.size() || recvIndex != baseRecv.size())
				throw RTE_LOC;
		}

		macoro::task<State> prepare(
			MatrixView<u8> addresses,
			PRNG& prng,
			coproto::Socket& socket)
		{
			if (addresses.rows() != mNumRows || addresses.cols() * 8 < mIndexBits)
				throw RTE_LOC;
			Matrix<u8> dummy(mNumRows, addresses.cols());
			if (mPartyIdx)
				for (u64 row = 0; row < mNumRows; ++row)
					copyBytesMin(dummy[row], mDomain);

			State state;
			co_await mActivityEquality.equal(addresses, dummy, state.mActivity, socket, prng);
			if (mPartyIdx)
				for (u64 row = 0; row < mNumRows; ++row)
					state.mActivity[row] ^= 1;
			state.mPowers = co_await mHash.prepare(addresses, socket);
			mSelectorSession = co_await mSelector.setupMultiply(
				mNumRows,
				state.mActivity.getSpan<const u8>(),
				socket);
			co_return state;
		}

		macoro::task<Proposal> sample(
			const State& state,
			PRNG& prng,
			coproto::Socket& socket)
		{
			if (state.mActivity.size() != mNumRows)
				throw RTE_LOC;
			block localSeed = prng.get<block>();
			block remoteSeed;
			co_await socket.send(coproto::copy(localSeed));
			co_await socket.recv(remoteSeed);

			Proposal proposal;
			proposal.mPublicSeed = localSeed ^ remoteSeed;
			const auto w = mConfig.numPartitions();
			proposal.mCoefficients.resize(mNumSets * w, mRowsPerSet);
			const auto fieldBits = mHash.fieldBits();
			const auto fieldMask = fieldBits == 32
				? std::numeric_limits<u32>::max()
				: (u32(1) << fieldBits) - 1;
			PRNG coefficientPrng(proposal.mPublicSeed);
			for (auto& coefficient : proposal.mCoefficients)
				coefficient = coefficientPrng.get<u32>() & fieldMask;

			Matrix<u32> hashValue(mNumRows, w);
			mHash.evaluate(
				state.mPowers,
				proposal.mCoefficients,
				mNumSets,
				mConfig.mPartitionSizes,
				hashValue);
			proposal.mCandidates.resize(mNumRows, w);
			std::vector<u32> difference(mNumRows);
			std::vector<u32> selected(mNumRows);
			for (u64 partition = 0; partition < w; ++partition)
			{
				const auto mask = static_cast<u32>(mConfig.mPartitionSizes[partition] - 1);
				for (u64 row = 0; row < mNumRows; ++row)
				{
					proposal.mCandidates(row, partition) = prng.get<u32>() & mask;
					difference[row] = proposal.mCandidates(row, partition) ^ hashValue(row, partition);
				}
				co_await mSelectorSession.multiply<u32, CoeffCtxGF2>(
					difference.begin(),
					difference.end(),
					selected.begin(),
					socket,
					CoeffCtxGF2{});
				for (u64 row = 0; row < mNumRows; ++row)
					proposal.mCandidates(row, partition) ^= selected[row];
			}
			co_return proposal;
		}

		macoro::task<Matrix<u8>> maskActive(
			const State& state,
			MatrixView<const u8> values,
			coproto::Socket& socket)
		{
			if (state.mActivity.size() != mNumRows || values.rows() != mNumRows)
				throw RTE_LOC;
			Matrix<u8> result(values.rows(), values.cols());
			auto context = DpfMult::BitMatrixCoeffCtx(values.cols() * 8);
			auto input = DpfMult::BitMatrixCoeffCtx::View<const u8>(values);
			auto output = DpfMult::BitMatrixCoeffCtx::View<u8>(result);
			co_await mSelectorSession.multiply<u8, DpfMult::BitMatrixCoeffCtx>(
				input.begin(),
				input.end(),
				output.begin(),
				socket,
				context);
			co_return result;
		}
	};
}
