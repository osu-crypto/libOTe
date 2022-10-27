#include "cryptoTools/Common/Defines.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/Prng.h"

namespace osuCrypto
{


	// THe encoder for the generator matrix G = B * A.
	// B is the expander while A is the accumulator.
	// 
	// B has mMessageSize rows and mCodeSize columns. It is sampled uniformly
	// with fixed row weight mExpanderWeight.
	//
	// A is a lower triangular n by n matrix with ones on the diagonal. The
	// mAccumulatorSize diagonals left of the main diagonal are uniformly random.
	// If mStickyAccumulator, then the first diagonal left of the main is always ones.
    class Tungsten
    {
    public:

		void config(
			u64 messageSize, 
			u64 codeSize, 
			u64 expanderWeight,
			u64 accumulatorSize,
			u64 stickyAccumulator = 1,
			block seed = block(0,0))
		{
			mMessageSize = messageSize;
			mCodeSize = codeSize;
			mExpanderWeight = expanderWeight;
			mAccumulatorSize = accumulatorSize;
			mStickyAccumulator = stickyAccumulator;

			assert(mStickyAccumulator <= mAccumulatorSize);
			mSeed = seed;
		}

		// the seed that generates the code.
		block mSeed = block(0,0);

		// The message size of the code. K.
		u64 mMessageSize = 0;

		// The codeword size of the code. n.
		u64 mCodeSize = 0;

		// The row weight of the B matrix.
		u64 mExpanderWeight = 0;

		// The size of the accumulator.
		u64 mAccumulatorSize = 0;

		u64 mStickyAccumulator = 1;

		u64 parityRows() const { return mCodeSize - mMessageSize; }
		u64 parityCols() const { return mCodeSize; }

		u64 generatorRows() const { return mMessageSize; }
		u64 generatorCols() const { return mCodeSize; }

		// Compute w = G * e.
		template<typename T>
		void cirTransEncode(span<T> e, span<T> w)
		{
			assert(e.size() == mCodeSize);
			assert(w.size() == mMessageSize);

			accumulate<T>(e);
			expand<T>(e, w);
		}

		template<typename T>
		void xorAdd(span<T> x, span<T> y)const
		{
			for (u64 i = 0; i < x.size(); ++i)
				x[i] = x[i] ^ y[i];
		}

		template<typename T>
		void accumulate(span<T> x)
		{
			PRNG prng(mSeed ^ OneBlock);

			auto AP = getAPar();

			std::vector<u64> buff(divCeil(mAccumulatorSize, 64));
			auto a8 = divCeil(mAccumulatorSize, 8);

			T zeroOne[2];
			memset(zeroOne, 0, sizeof(T));
			memset(zeroOne + 1, ~0, sizeof(T));
			DenseMtx A = DenseMtx::Identity(mCodeSize);
			for (i64 i = mCodeSize-1; i < mCodeSize; --i)
			{
				auto row = AP.row(i);
				auto rIter = row.rbegin();
				assert(*rIter++ == i);


				prng.get((u8*)buff.data(), a8);


				i64 j = i - 1;
				auto s = std::max<i64>(-1, j - mStickyAccumulator);
				auto e = std::max<i64>(-1, s - mAccumulatorSize);

				for (; j > s; --j)
				{
					x[j] = x[j] ^ x[i];
					xorAdd(A.col(j), A.col(i));
					assert(*rIter++ == j);
				}

				auto iter = BitIterator((u8*)buff.data(), 0);
				auto bb = buff.data();

				for (; j > e;)
				{
					auto rem = j - e;
					auto v = *bb++;
					auto ek = std::min<u64>(64, rem);

					for (u64 k = 0; k < ek; ++k, --j, ++iter)
					{
						assert((v & 1) == *iter);
						assert((v & 1) == (u8)AP(i, j));

						if (v & 1)
						{
							x[j] = x[j] ^ x[i];
							xorAdd(A.col(j), A.col(i));
							assert(*rIter++ == j);
						}
						//x[j] = x[j] ^ (x[i] & zeroOne[v & 1]);

						v = v/2;
					}
				}
				assert(rIter == row.rend());

			}

		}



		template<typename T>
		void expand(span<const T> e, span<T> w)
		{
			PRNG prng(mSeed);

			std::vector<u64> row(mExpanderWeight);
			for (auto i : rng(mMessageSize))
			{
				row[0] = prng.get<u64>() % mCodeSize;
				w[i] = e[row[0]];
				for (auto j : rng(1, mExpanderWeight))
				{
					do {
						row[j] = prng.get<u64>() % mCodeSize;
					} while (std::find(row.data(), row.data() + j, row[j]) != row.data() + j);

					w[i] = w[i] ^ e[row[j]];
				}
			}
		}

		SparseMtx getB() const
		{
			PRNG prng(mSeed);
			PointList points(mMessageSize, mCodeSize);

			std::vector<u64> row(mExpanderWeight);
			for (auto i : rng(mMessageSize))
			{
				row[0] = prng.get<u64>() % mCodeSize;
				points.push_back(i, row[0]);
				for (auto j : rng(1, mExpanderWeight))
				{
					do {
						row[j] = prng.get<u64>() % mCodeSize;
					} while (std::find(row.data(), row.data() + j, row[j]) != row.data() + j);

					points.push_back(i, row[j]);
				}
			}

			return points;
		}

		// Get the parity check version of the accumulator
		SparseMtx getAPar() const
		{
			PRNG prng(mSeed ^ OneBlock);
			PointList points(mCodeSize, mCodeSize);

			std::vector<u8> buff(divCeil(mAccumulatorSize, 8));
			for (u64 i = mCodeSize-1; i < mCodeSize; --i)
			{
				points.push_back(i, i);

				prng.get(buff.data(), buff.size());
				auto iter = BitIterator(buff.data(), 0);

				i64 j = i - 1;
				auto s = std::max<i64>(-1, j - mStickyAccumulator);
				auto e = std::max<i64>(-1, s - mAccumulatorSize);

				for (; j > s; --j)
					points.push_back(i, j);

				for (; j > e; --j, ++iter)
				{
					if (*iter)
						points.push_back(i, j);
				}
			}

			return points;
		}


		SparseMtx getA() const
		{
			auto APar = getAPar();
			
			auto A = DenseMtx::Identity(mCodeSize);

			for (u64 i = mCodeSize - 1; i < mCodeSize; --i)
			{
				for (auto y : APar.row(i))
				{
					if (y != i)
					{
						auto ay = A.col(y);
						auto ai = A.col(i);
						xorAdd(ay, ai);
					}							

				}

			}

			return A.sparse();
		}
    };
	
}