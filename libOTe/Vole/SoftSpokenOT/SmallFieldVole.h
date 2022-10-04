#pragma once
// © 2022 Lawrence Roy.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Common/MatrixView.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/TwoChooseOne/TcoOtDefines.h"
#include "libOTe/Tools/Coproto.h"
#include "libOTe/Tools/SilentPprf.h"

namespace osuCrypto
{

	// Classes for Sect. 3.1 of SoftSpokenOT paper. Silent, so malicious security is easy. Outputs
	// vectors u, v to sender and Delta, w to receiver such that: w - v = u cdot Delta, where cdot means
	// componentwise product. u is a vector over GF(2), but Delta, v, and w are vectors over
	// GF(2^mFieldBits). Really, it outputs 128 of these (u, v)s and Ws at a time, packed into blocks.
	// Delta, v, and w have mFieldBits blocks for every block of u, to represent the larger finite field.
	// The bits of the finite field are stored in little endian order.

	// Commonalities between sender and receiver.
	class SmallFieldVoleBase
	{
		SmallFieldVoleBase(const SmallFieldVoleBase&) = default;

	public:
		static constexpr u64 fieldBitsMax = 31;

		u64 mFieldBits = 0;
		u64 mNumVoles = 0;
		u64 mNumVolesPadded = 0;
		bool mMalicious = false;
		bool mInit = false;

		// 2D array, with one row for each VOLE and one column for each field element (minus one for the
		// receiver). Since the receiver doesn't know the zeroth seed, the columns are all shifted by 1
		// for them.
		AlignedUnVector<block> mSeeds;

		SmallFieldVoleBase() = default;
		SmallFieldVoleBase(SmallFieldVoleBase&&) = default;
		SmallFieldVoleBase& operator=(SmallFieldVoleBase&&) = default;


		SmallFieldVoleBase copy() const
		{
			return *this;
		}

		static constexpr u64 baseOtCount(u64 fieldBits, u64 numVoles)
		{
			return fieldBits * numVoles;
		}

		u64 baseOtCount() const
		{
			assert(mInit);
			return baseOtCount(mFieldBits,  mNumVoles);
		}

		u64 fieldSize() const
		{
			return (u64)1 << mFieldBits;
		}

		u64 fieldBits() const
		{
			return mFieldBits;
		}


		bool hasSeed() const
		{
			return mSeeds.size();
		}


		// The number of useful blocks in u, v.
		u64 uSize() const { return mNumVoles; }
		u64 vSize() const { return mFieldBits * mNumVoles; }

		// The u correction must also be padded, according to uPadded(), as garbage values may be read.
		// ... plus the number of padding blocks at the end where garbage may be written.
		u64 uPadded() const { return mNumVolesPadded; }

		// The v correction must also be padded, according to uPadded(), as garbage values may be read.
		u64 vPadded() const { return mFieldBits * mNumVolesPadded; }


		// The number of useful blocks in w.
		u64 wSize() const { return mFieldBits * mNumVoles; }

		// wSize plus the number of padding blocks at the end where garbage may be written.
		u64 wPadded() const { return mFieldBits * mNumVolesPadded; }


	protected:

		void init(u64 fieldBits_, u64 numVoles_, bool malicious);

	private:
		//// Helper to convert generateImpl into a non-member function.
		//template<u64 fieldBitsConst, typename T, T Func>
		//struct call_member_func;

		friend class SmallFieldVoleSender;
		friend class SmallFieldVoleReceiver;
	};



	class SmallFieldVoleSender : public SmallFieldVoleBase
	{
		SmallFieldVoleSender(const SmallFieldVoleSender& b)
			: SmallFieldVoleBase(b)
			, mPprf(new SilentMultiPprfSender)
			, mGenerateFn(b.mGenerateFn)
		{}

	public:
		// Instead of special casing the last few VOLEs when the number of AES calls wouldn't be a
		// multiple of superBlkSize, just pad the mSeeds and output. The output must be sized for
		// numVolesPadded VOLEs, rather than mNumVoles, and the extra output values will be garbage. This
		// wastes a few AES calls, but saving them wouldn't have helped much because you still have to
		// pay for the AES latency.

		std::unique_ptr<SilentMultiPprfSender> mPprf;

		SmallFieldVoleSender() = default;
		SmallFieldVoleSender(SmallFieldVoleSender&&) = default;
		SmallFieldVoleSender& operator=(SmallFieldVoleSender&&) = default;

		// copy the vole seeds but not the pprf/base-OTs
		SmallFieldVoleSender copy()const
		{
			return *this;
		}

		void setBaseOts(span<std::array<block, 2>> msgs);

		void init(u64 fieldBits, u64 numVoles, bool malicious = false);


		// mSeeds must be the OT messages from mNumVoles instances of 2**mFieldBits - 1 of 2**mFieldBits OT,
		// with each OT occupying a contiguous memory range.
		void setSeed(span<const block> seeds_);


		// Uses a PPRF to implement the 2**mFieldBits - 1 of 2**mFieldBits OTs out of 1 of 2 base OTs. The
		// messages of the base OTs must be in baseMessages.
		task<> expand(Socket& chl, PRNG& prng, u64 numThreads);


		bool hasBaseOts() const
		{
			return mSeeds.size() || (mPprf && mPprf->hasBaseOts());
		}

		// outV outputs the values for v, i.e. xor_x x * PRG(seed[x]). outU gives the values for u (the
		// xor of all PRG evaluations).
		void generate(u64 blockIdx, const AES& aes, block* outU, block* outV) const
		{
			mGenerateFn(*this, blockIdx, aes, outU, outV);
		}

		void generate(u64 blockIdx, const AES& aes, span<block> outU, span<block> outV) const
		{
#ifndef NDEBUG
			if ((u64)outU.size() != uPadded())
				throw RTE_LOC;
			if ((u64)outV.size() != vPadded())
				throw RTE_LOC;
#endif

			return generate(blockIdx, aes, outU.data(), outV.data());
		}



	private:

		void init(u64 fieldBits_, u64 numVoles_);

		using GenerateFn =  void (*)(const SmallFieldVoleSender&,
			u64, const AES&, block* __restrict, block* __restrict);

		// a pointer to a template function that generates the output with the field bit count hard coded (for up to 10).
		GenerateFn mGenerateFn = nullptr;

		// Select specialized implementation of generate.
		static GenerateFn selectGenerateImpl(u64 fieldBits);
	};

	class SmallFieldVoleReceiver : public SmallFieldVoleBase
	{

		SmallFieldVoleReceiver(const SmallFieldVoleReceiver& b)
			: SmallFieldVoleBase(b)
			, mPprf(new SilentMultiPprfReceiver)
			, mDelta(b.mDelta)
			, mDeltaUnpacked(b.mDeltaUnpacked)
			, mGenerateFn(b.mGenerateFn)
		{}

	public:
		std::unique_ptr<SilentMultiPprfReceiver> mPprf;
		BitVector mDelta;
		AlignedUnVector<u8> mDeltaUnpacked; // Each bit of delta becomes a byte, either 0 or 0xff.

		SmallFieldVoleReceiver() = default;
		SmallFieldVoleReceiver(SmallFieldVoleReceiver&&) = default;
		SmallFieldVoleReceiver& operator=(SmallFieldVoleReceiver&&) = default;


		// copy the vole seeds but not the pprf/base-OTs
		SmallFieldVoleReceiver copy()const
		{
			return *this;
		}


		// Same as for SmallFieldVoleSender, except that the AES operations are performed in differently
		// sized chunks for the receiver.

		void init(u64 fieldBits_, u64 numVoles_, bool malicious = false);


		// mSeeds must be the OT messages from mNumVoles instances of 2**mFieldBits - 1 of 2**mFieldBits OT,
		// with each OT occupying a contiguous memory range. The choice bits (i.e. the indices of the
		// punctured points) from these OTs must be concatenated together into delta (in little endian),
		// which must then be uniformly random for security. mSeeds must be ordered so that the delta'th
		// seed in a mVole (the one that is unknown to the receiver) would be in position -1 (in general,
		// i gets stored at (i ^ delta) - 1).
		void setSeeds(span<const block> seeds_);


		void setBaseOts(span<const block> baseMessages, const BitVector& choices);

		bool hasBaseOts() const
		{
			return mSeeds.size() || (mPprf && mPprf->hasBaseOts());
		}

		const BitVector& getDelta() const { return mDelta; }

		// Uses a PPRF to implement the 2**mFieldBits - 1 of 2**mFieldBits OTs out of 1 of 2 base OTs. The
		// messages and choice bits (which must be uniformly random) of the base OTs must be in
		// baseMessages and choices.
		task<> expand(Socket& chl, PRNG& prng, u64 numThreads);


		// outW outputs the values for w, i.e. xor_x x * PRG(seed[x]). If correction is passed, its
		// effect is the same as running sharedFunctionXor(correction, outW) after this function.
		void generate(u64 blockIdx, const AES& aes,
			block* outW, const block* correction = nullptr) const
		{
			mGenerateFn(*this, blockIdx, aes, outW, correction);
		}

		void generate(u64 blockIdx, const AES& aes,
			span<block> outW, span<const block> correction = span<block>()) const
		{
#ifndef NDEBUG
			if ((u64)outW.size() != wPadded())
				throw RTE_LOC;
			if (correction.data() && (u64)correction.size() != uPadded())
				throw RTE_LOC;
#endif

			generate(blockIdx, aes, outW.data(), correction.data());
		}





		// The VOLE outputs secret shares shares of u cdot Delta, where u is in GF(2)^mNumVoles, Delta is
		// in GF(2^mFieldBits)^mNumVoles, and cdot represents the componentwise product. This computes the
		// cdot Delta operation (i.e. the secret shared function) on 128 vectors at once. The output is
		// XORed into product, which must be padded to length wPadded().
		template<typename T>
		inline void sharedFunctionXor(const T* u, T* product);

		template<typename T>
		void sharedFunctionXor(span<const T> u, span<T> product)
		{
#ifndef NDEBUG
			if ((u64)u.size() != mNumVoles)
				throw RTE_LOC;
			if ((u64)product.size() != wPadded())
				throw RTE_LOC;
#endif
			sharedFunctionXor(u.data(), product.data());
		}

		// Same, but on values in GF(2^mFieldBits)^mNumVoles instead of GF(2)^mNumVoles. modulus is the
		// modulus of the GF(2^mFieldBits) field being used.
		template<typename T>
		inline void sharedFunctionXorGF(const T* __restrict u, T* __restrict product, u64 modulus);

		// Helper for above. See below class for specialization on block.
		template<typename T>
		inline static T allSame(u8 in)
		{
			// Use sign extension.
			return (typename std::make_signed<T>::type) (i8) in;
		}


	private:

		void setDelta(BitVector delta_);


		using GenerateFn = void (*)(const SmallFieldVoleReceiver&,
			u64 blockIdx, const AES& aes,
			block* __restrict outW, const block* __restrict correction);

		GenerateFn mGenerateFn = nullptr;

		// Select specialized implementation of generate.
		static GenerateFn selectGenerateImpl(u64 fieldBits);

		template<typename T>
		OC_FORCEINLINE void sharedFunctionXorGFImpl(
			const T* __restrict u, T* __restrict product, u64 modulus,
			u64 nVole, u64 chunk);
	};

	template<> inline block SmallFieldVoleReceiver::allSame<block>(u8 in)
	{
		return block::allSame(in);
	}

	template<typename T>
	void SmallFieldVoleReceiver::sharedFunctionXor(const T* u, T* product)
	{
		for (u64 nVole = 0; nVole < mNumVoles; nVole += 4)
		{
			T uBlock[4];
			for (u64 i = 0; i < 4; ++i)
				uBlock[i] = u[nVole + i];

			for (u64 bit = 0; bit < mFieldBits; ++bit)
				for (u64 i = 0; i < 4; ++i)
					product[(nVole + i) * mFieldBits + bit] ^=
					uBlock[i] & allSame<T>(mDeltaUnpacked[(nVole + i) * mFieldBits + bit]);
		}
	}

	template<typename T>
	OC_FORCEINLINE void SmallFieldVoleReceiver::sharedFunctionXorGFImpl(
		const T* __restrict u, T* __restrict product, u64 modulus, u64 nVole, u64 step)
	{
		T products[4][2 * SmallFieldVoleBase::fieldBitsMax - 1] = { {0} };

		// Don't bother with fast multiplication for now.
		for (u64 bitU = 0; bitU < mFieldBits; ++bitU)
			for (u64 bitD = 0; bitD < mFieldBits; ++bitD)
				for (u64 i = 0; i < step; ++i)
					products[i][bitU + bitD] ^= u[(nVole + i) * mFieldBits + bitU] &
					allSame<T>(mDeltaUnpacked[(nVole + i) * mFieldBits + bitD]);

		// Apply modular reduction to put the result in GF(2^mFieldBits). Again, don't bother with
		// fast techinques.
		for (u64 j = 2 * mFieldBits - 2; j >= mFieldBits; --j)
			for (u64 k = 1; k <= mFieldBits; ++k)
				if ((modulus >> (mFieldBits - k)) & 1)
					for (u64 i = 0; i < step; ++i)
						products[i][j - k] ^= products[i][j];

		// XOR out
		for (u64 j = 0; j < mFieldBits; ++j)
			for (u64 i = 0; i < step; ++i)
				product[(nVole + i) * mFieldBits + j] ^= products[i][j];
	}

	template<typename T>
	void SmallFieldVoleReceiver::sharedFunctionXorGF(
		const T* __restrict u, T* __restrict product, u64 modulus)
	{
		u64 nVole;
		for (nVole = 0; nVole + 4 <= mNumVoles; nVole += 4)
			sharedFunctionXorGFImpl(u, product, modulus, nVole, 4);
		for (; nVole < mNumVoles; ++nVole)
			sharedFunctionXorGFImpl(u, product, modulus, nVole, 1);
	}

	namespace tests
	{
		void xorReduction();
	}

}

#endif
