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

		u64 mLog3T = 1;

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
		u64 mDpfDomainDepth = 0;

		u64 mDpfBlockSize = 0;

		// the number of F4 values per block. Each block will have 1 non-zero.
		// A polynomial will have mT blocks. i.e. mN = mT * mBlockSize.
		u64 mBlockSize = 0;

		// the coefficient of the sparse polynomial.
		// the i'th row containts the coeffs for the i'th poly.
		Matrix<u8> mSparseCoefficients;
		
		// the locations of the non-zeros in the j'th block of the sparse polynomial.
		// the i'th row containts the coeffs for the i'th poly.
		Matrix<u64> mSparsePositions;

		TriDpf mDpf;

		void init(u64 partyIdx, u64 n, PRNG& prng);

		macoro::task<> expand(
			span<block> ALsb,
			span<block> AMsb,
			span<block> CLsb,
			span<block> CMsb, PRNG& prng, coproto::Socket& sock);


		//macoro::task<> dpfEval(
		//	u64 domain,
		//	span<Trit32> points,
		//	span<u8> coeffs,
		//	MatrixView<uint128_t> output,
		//	PRNG& prng,
		//	coproto::Socket& sock);

		void sampleA(block seed);
	};
}
