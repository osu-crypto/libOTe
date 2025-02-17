#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Aligned.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Tools/Dpf/TriDpf.h"
namespace osuCrypto
{


	class FoleageF4Ole : public TimerAdapter
	{
	public:
		u64 mPartyIdx = 0;

		// log3 polynomial size
		u64 mLog3N = 0;

		// the number of noisy positions per polynomial
		u64 mT = 3;

		u64 mLog3T = 0;

		// the number of polynomials
		u64 mC = 4;

		// the size of a polynomial, 3^mLog3N
		u64 mN = 0;

		// The A poly in FFT format. We pack mC FFTs into a single u8. The 
		// first is hard coded to the identity polynomial.
		AlignedUnVector<u8> mFftA;

		// The A^2 poly in FFT format. We pack mC^2 FFTs into a single u32.
		AlignedVector<u32> mFftASquared;

		// depth of 3-ary DPF with 256 F4 values per leaf. 
		u64 _mDpfDomainDepth = 0;

		u64 _mDpfBlockSize = 0;

		// the number of F4 values per block. Each block will have 1 non-zero.
		// A polynomial will have mT blocks. i.e. mN = mT * mBlockSize.
		u64 mBlockSize = 0;

		u64 mBlockDepth = 0;

		u64 mDpfLeafDepth = 0;
		u64 mDpfTreeDepth = 0;
		u64 mDpfTreeSize = 0;

		u64 mDpfLeafSize = 0;

		// the coefficient of the sparse polynomial.
		// the i'th row containts the coeffs for the i'th poly.
		Matrix<u8> mSparseCoefficients;
		
		// the locations of the non-zeros in the j'th block of the sparse polynomial.
		// the i'th row containts the coeffs for the i'th poly.
		Matrix<u64> mSparsePositions;

		// a dpf used to construct the leaf value of the larger DPF.
		TriDpf<u8, CoeffCtxGF2> mDpfLeaf;

		// the main DPF
		TriDpf<block512, CoeffCtxGF2> mDpf;

		std::vector<block> mRecvOts;
		std::vector<std::array<block,2>> mSendOts;
		BitVector mChoiceOts;

		void init(u64 partyIdx, u64 n, PRNG& prng);

		struct BaseOtCount
		{
			u64 mSendCount, mRecvCount;
		};

		BaseOtCount baseOtCount() const
		{
			BaseOtCount counts;
			
			counts.mSendCount = mDpfLeaf.baseOtCount() + mDpf.baseOtCount();
			counts.mRecvCount = mDpfLeaf.baseOtCount() + mDpf.baseOtCount();
			if(mPartyIdx)
				counts.mSendCount += 2 * mC * mT;
			else								
				counts.mRecvCount += 2 * mC * mT;
			return counts;
		}


		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			auto baseCounts = baseOtCount();
			if (baseSendOts.size() != baseCounts.mSendCount)
				throw RTE_LOC;
			if (recvBaseOts.size() != baseCounts.mRecvCount)
				throw RTE_LOC;
			if (baseChoices.size() != baseCounts.mRecvCount)
				throw RTE_LOC;
			auto recvIter = recvBaseOts;
			auto sendIter = baseSendOts;
			auto choiceIter = baseChoices;

			auto dpfLeafCount = mDpfLeaf.baseOtCount();
			u64 offset = 0;
			mDpfLeaf.setBaseOts(
				sendIter.subspan(offset, dpfLeafCount),
				recvIter.subspan(offset, dpfLeafCount),
				BitVector(baseChoices.data(), dpfLeafCount, offset)
			);
			offset += dpfLeafCount;

			auto dpfCount = mDpf.baseOtCount();
			mDpf.setBaseOts(
				sendIter.subspan(offset, dpfCount),
				recvIter.subspan(offset, dpfCount),
				BitVector(baseChoices.data(), dpfCount, offset)
			);
			offset += dpfCount;

			auto sendOts = sendIter.subspan(offset);
			auto recvOts = recvIter.subspan(offset);
			mSendOts.insert(mSendOts.end(), sendOts.begin(), sendOts.end());
			mRecvOts.insert(mRecvOts.end(), recvOts.begin(), recvOts.end());
			mChoiceOts = BitVector(baseChoices.data(), baseChoices.size() - offset, offset);
		}

		macoro::task<> expand(
			span<block> ALsb,
			span<block> AMsb,
			span<block> CLsb,
			span<block> CMsb, PRNG& prng, coproto::Socket& sock);

		macoro::task<> tensor(span<u8> coeffs, span<u8> prod, coproto::Socket& sock);

		void sampleA(block seed);
	};
}
