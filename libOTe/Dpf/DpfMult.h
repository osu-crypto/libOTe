#pragma once

#include "libOTe/config.h"
#if defined(ENABLE_REGULAR_DPF) || defined(ENABLE_SPARSE_DPF)

#include "cryptoTools/Common/Defines.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

namespace osuCrypto
{
	// this class implement binary scaler vector multiplication.
	// given a shared bit [x] and shared vector [y], this class
	// computes the shared vector [xy] = [x * y].
	//
	// this protocol used |x| OTs in both directions to execute the protocol.
	struct DpfMult
	{

		u64 mPartyIdx = 0;

		u64 mTotalMults = 0;

		oc::BitVector mChoiceBits;

		std::vector<block> mRecvOts;
		std::vector<std::array<block, 2>> mSendOts;

		u64 mOtIdx = 0;

		bool hasBaseOts() const { return mChoiceBits.size(); }

		u8 lsb(const block& b)
		{
			return b.get<u8>(0) & 1;
		}

		void init(
			u64 partyIdx,
			u64 n)
		{
			if (partyIdx > 1)
				throw RTE_LOC;

			mPartyIdx = partyIdx;
			mTotalMults = n;
			mOtIdx = 0;
			mSendOts.clear();
			mRecvOts.clear();
			mChoiceBits.resize(0);
		}


		// given shared [x], [y], output [xy] = [x * y] where multiplication
		// is perform component-wise, i.e. xi * yi = xyi, xi is a bit and yi 
		// is a vector.
		// 
		// We are given two OTs, one in each direction. Let us denote them as
		// 
		//   a0                      b0
		//   c00                     c01
		// 
		//   b1                      a1
		//   c10                     c11
		// 
		// such that 
		// 
		//    a0 * b0 = (c00 + c01)
		//    a1 * b1 = (c10 + c11)
		// 
		// Note that we write these OTs in OLE format, that is for OT (m0,m1),(g,mg)
		// we have a0=g, b0=(m0+m1), c00=mg, c01=m0 and similar for the second 
		// instance.
		//
		// We first convert these two "OTs/OLEs" into a random beaver triple
		//
		// [a] * [b] = [c']
		// 
		// We do this by computing
		//
		// [a] = (a0, a1)
		// [b] = (b1, b0)
		// [c'] = (c00+c10+a0b1, c01+c11+a1b0)
		// 
		// As you can see, all 4 cross terms are present. Given this beaver triple
		// we can use the standard protocol. We reveal
		// 
		// phi   = [x] + [a]
		// theta = [y] + [b]
		// 
		// [zy] = [c'] + theta a + phi b + theta phi
		//      = ab + (y+b) a + (x+a) b + (y+b)(x+a)
		//      = ab + ab + ya + xb + ab + yx + ya + xb + ab
		//      = xy
		//
		macoro::task<> multiply(const oc::BitVector& x, span<const block> y, span<block> xy, coproto::Socket& sock)
		{
			if (x.size() != y.size() || x.size() != xy.size())
				throw RTE_LOC;
			if (x.size() + mOtIdx > mTotalMults)
				throw RTE_LOC;
			if (hasBaseOts() == false)
				throw RTE_LOC;

			// our a share of a * b = c.
			BitVector a0; a0.append(mChoiceBits, x.size(), mOtIdx);

			// A0 = 11...1 * a , an expanded version of a used for masking.
			AlignedUnVector<block> A0(x.size());

			// our c share of a * b = c.
			AlignedUnVector<block> C(x.size());

			// theta = y + b
			AlignedUnVector<block> theta(x.size());

			// our b share of a * b = c
			AlignedUnVector<block> b1(x.size());

			for (u64 j = 0; j < x.size(); ++j)
			{
				A0[j] = block(-u64(a0[j]), -u64(a0[j]));
				auto c00 = mRecvOts[mOtIdx + j];
				auto c10 = mSendOts[mOtIdx + j][0];
				b1[j] = mSendOts[mOtIdx + j][0] ^ mSendOts[mOtIdx + j][1];

				// C0' = c00+c10+a0b1
				C[j] = c00 ^ c10 ^ (b1[j] & A0[j]);

				// theta = y + b
				theta[j] = y[j] ^ b1[j];
			}

			// phi = x + a
			auto phi = x ^ a0;
			while (phi.size() % 8)
				phi.pushBack(0);

			// reveal phi and theta
			auto thetaSize = theta.size() * sizeof(theta[0]);
			auto buffSize = thetaSize + phi.getSpan<u8>().size();
			AlignedUnVector<u8> buffer(buffSize);
			copyBytes(buffer.subspan(0, thetaSize), theta);
			copyBytes(buffer.subspan(thetaSize), phi.getSpan<u8>());
			co_await sock.send(std::move(buffer));
			buffer.resize(buffSize);
			co_await sock.recv(buffer);
			std::vector<block> theta1(theta.size());
			BitVector phi1(phi.size());
			copyBytes(theta1, buffer.subspan(0, thetaSize));
			copyBytes(phi1.getSpan<u8>(), buffer.subspan(thetaSize));

			// reconstruct phi
			phi ^= phi1;

			auto partyMask = block(-u64(mPartyIdx), -u64(mPartyIdx));
			for (u64 j = 0; j < x.size(); ++j)
			{
				// reconstruct theta
				theta[j] ^= theta1[j];

				// mask block of phi
				auto Phi = block(-u64(phi[j]), -u64(phi[j]));

				// [zy] = [c] + theta * [a] + phi * [b] + theta * phi
				xy[j] = C[j] ^ (theta[j] & A0[j]) ^ (Phi & b1[j]) ^ (partyMask & theta[j] & Phi);
			}


			mOtIdx += x.size();

		}

		static void packBits(span<u8> dest, MatrixView<u8> src, u64 bitCount)
		{
			if (dest.size() != divCeil(src.rows() * bitCount, 8))
				throw RTE_LOC;

			if (bitCount % 8 == 0)
			{
				auto bytes = divCeil(bitCount, 8);
				for (u64 i = 0; i < src.rows(); ++i)
				{
					copyBytes(dest.subspan(0, bytes), src[i].subspan(0, bytes));
					dest = dest.subspan(src.cols());
				}
			}
			else
			{
				auto dIter = BitIterator(dest.data());
				for (u64 i = 0; i < src.rows(); ++i)
				{
					auto sIter = BitIterator(src[i].data());
					for (u64 j = 0; j < bitCount; ++j)
					{
						*dIter = *sIter;
						++dIter;
						++sIter;
					}
				}
			}
		}

		static void unpackBits(Matrix<u8>& dest, span<u8> src, u64 bitCount)
		{
			if (src.size() != divCeil(dest.rows() * bitCount, 8))
				throw RTE_LOC;
			if (bitCount % 8 == 0)
			{
				auto bytes = divCeil(bitCount, 8);
				for (u64 i = 0; i < dest.rows(); ++i)
				{
					copyBytes(dest[i].subspan(0, bytes), src.subspan(0, bytes));
					src = src.subspan(dest.cols());
				}
			}
			else
			{
				auto sIter = BitIterator(src.data());
				for (u64 i = 0; i < dest.rows(); ++i)
				{
					auto dIter = BitIterator(dest[i].data());
					for (u64 j = 0; j < bitCount; ++j)
					{
						*dIter = *sIter;
						++dIter;
						++sIter;
					}
				}
			}
		}

		// Helper function to expand OT seeds on demand for generic types
		void expandSeed(span<u8> dst, block seed0, block seed1) const
		{
			if (dst.size() < 16)
			{
				auto v = seed0 ^ seed1;
				copyBytesMin(dst, v);
			}
			else
			{
				AES aes0(seed0);
				AES aes1(seed1);
				for (u64 i = 0; dst.size(); ++i)
				{
					auto v = aes0.ecbEncBlock(block(i, i))
						^ aes1.ecbEncBlock(block(i, i));
					copyBytesMin(dst, v);
					dst = dst.subspan(std::min<u64>(16, dst.size()));
				}
			}
		}

		// Generic Bit-Field Multiplication Protocol
		// 
		// Performs secure computation of [xy] = [x] * [y] where [x] is a secret-shared
		// bit vector and [y] is a secret-shared vector over an arbitrary field F.
		// 
		// @tparam F The field type for the y and xy vectors (e.g., u64, block, custom field types)
		// @tparam CoeffCtx The coefficient context providing field operations for type F
		// 
		// @param x Secret-shared bit vector (packed as bytes, LSB first)
		// @param y Secret-shared field vector of type F
		// @param xy Output vector for the secret-shared product [x] * [y]
		// @param sock Communication socket for the protocol
		// @param ctx Coefficient context providing field arithmetic operations
		// 
		// @returns A coroutine task that completes when multiplication is finished
		template<typename F, typename CoeffCtx>
		macoro::task<> multiply(
			span<const u8> x,
			auto&& y,
			auto&& xy,
			coproto::Socket& sock,
			const CoeffCtx& ctx)
		{

			auto session = co_await setupMultiply(y.size(), x, sock);
			co_await session.template multiply<F, CoeffCtx>(y.begin(), y.end(), xy.begin(), sock, ctx);
			co_return;
		}

		// Custom CoeffCtx for byte-oriented matrix operations
		struct BitMatrixCoeffCtx
		{
			// the number of bits each row will have
			u64 mBitCount;

			BitMatrixCoeffCtx(u64 bitCount) : mBitCount(bitCount) {}


			template<typename T>
			struct Iter
			{
				MatrixView<T> mBase;
				u64 mIdx = 0;

				// Iterator traits for random access iterator
				using iterator_category = std::random_access_iterator_tag;
				using value_type = span<T>;
				using difference_type = std::ptrdiff_t;
				using pointer = span<T>*;
				using reference = span<T>;

				Iter() = default;
				Iter(MatrixView<T> base, u64 idx) : mBase(base), mIdx(idx) {}

				// Dereference operators
				auto operator*() const { return mBase[mIdx]; }
				auto operator->() const { return &mBase[mIdx]; }

				// Subscript operator for random access
				span<T> operator[](difference_type i) const { return mBase[mIdx + i]; }

				// Prefix increment/decrement
				Iter& operator++() { ++mIdx; return *this; }
				Iter& operator--() { --mIdx; return *this; }

				// Postfix increment/decrement
				Iter operator++(int) { Iter tmp = *this; ++mIdx; return tmp; }
				Iter operator--(int) { Iter tmp = *this; --mIdx; return tmp; }

				// Arithmetic operators
				Iter operator+(difference_type n) const { return Iter(mBase, mIdx + n); }
				Iter operator-(difference_type n) const { return Iter(mBase, mIdx - n); }
				
				// Difference operator (required for std::distance)
				difference_type operator-(const Iter& other) const {
					if(mBase.data() != other.mBase.data())
						throw std::runtime_error("Iterators from different bases cannot be subtracted.");
					return static_cast<difference_type>(mIdx) - static_cast<difference_type>(other.mIdx);
				}

				// Compound assignment operators
				Iter& operator+=(difference_type n) { mIdx += n; return *this; }
				Iter& operator-=(difference_type n) { mIdx -= n; return *this; }

				// Comparison operators
				bool operator==(const Iter& other) const { 
					return mBase.data() == other.mBase.data() && mIdx == other.mIdx; 
				}
				bool operator!=(const Iter& other) const { 
					return !(*this == other);
				}
				bool operator<(const Iter& other) const {
					if(mBase.data() != other.mBase.data())
						throw std::runtime_error("Iterators from different bases cannot be compared.");
					return mIdx < other.mIdx;
				}
				bool operator<=(const Iter& other) const {
					return !(other < *this);
				}
				bool operator>(const Iter& other) const {
					return other < *this;
				}
				bool operator>=(const Iter& other) const {
					return !(*this < other);
				}
			};


			// Matrix type for this context - each element is a row view
			struct Vec
			{
				Matrix<u8> mData;

				u64 size() const { return mData.rows(); }
				span<const u8> operator[](u64 i) const
				{
					assert(i < mData.rows());
					return mData[i];
				}
				span<u8> operator[](u64 i)
				{
					assert(i < mData.rows());
					return mData[i];
				}

				auto begin() const { return Iter<u8>(mData, 0); }
				auto end() const { return Iter<u8>(mData, mData.rows()); }
			};

			template<typename T>
			struct View
			{
				MatrixView<T> mData;
				u64 size() const { return mData.rows(); }
				span<const T> operator[](u64 i) const
				{
					assert(i < mData.rows());
					return mData[i];
				}
				span<T> operator[](u64 i)
				{
					assert(i < mData.rows());
					return mData[i];
				}

				auto begin() const { return Iter<T>(mData, 0); }
				auto end() const { return Iter<T>(mData, mData.rows()); }
			};

			// The field type F is MatrixView<u8> (a single row)
			template<typename F>
			Vec makeVec(u64 size) const
			{
				static_assert(std::is_same_v<F, u8>, "F must be u8");

				// Return a matrix with size rows and appropriate column count for bitCount
				auto cols = divCeil(mBitCount, 8);
				return Vec{ Matrix<u8>(size, cols) };
			}

			void resize(auto&& vec, u64 size) const
			{
				auto cols = divCeil(mBitCount, 8);
				vec.mData.resize(size, cols);
			}

			template<typename F>
			auto make() const
			{
				auto cols = divCeil(mBitCount, 8 * sizeof(F));
				return std::vector<F>(cols);
			}

			template<typename F>
			u64 byteSize() const
			{
				return divCeil(mBitCount, 8);
			}

			void plus(auto&& ret, auto&& lhs, auto&& rhs) const
			{
				assert(ret.size() == lhs.size() && lhs.size() == rhs.size());
				for (u64 i = 0; i < ret.size(); ++i)
				{
					ret[i] = lhs[i] ^ rhs[i];
				}
			}

			void minus(auto&& ret,  auto&& lhs,  auto&&rhs) const
			{
				// Same as plus for GF(2)
				plus(ret, lhs, rhs);
			}

			void copy(auto&& dst, auto&& src) const
			{
				assert(dst.size() == src.size());
				std::copy(src.begin(), src.end(), dst.begin());
			}

			template<typename F>
			void zero(F& x) const
			{
				std::fill(x.begin(), x.end(), 0);
			}

			template<typename F>
			bool eq(const F& lhs, const F& rhs) const
			{
				if (lhs.size() != rhs.size()) return false;
				return std::equal(lhs.begin(), lhs.end(), rhs.begin());
			}

			template<typename F>
			void fromBlock(F& ret, const block& b) const
			{
				auto bytes = std::min(ret.size(), sizeof(block));
				if (ret.size() > sizeof(block))
				{
					// If we need more bytes than a block provides, expand using AES
					AES aes(b);
					for (u64 i = 0; i < ret.size(); i += sizeof(block))
					{
						auto remaining = std::min(ret.size() - i, sizeof(block));
						block expanded = aes.ecbEncBlock(block(i / sizeof(block), 0));
						std::memcpy(ret.data() + i, &expanded, remaining);
					}
				}
				else
				{
					std::memcpy(ret.data(), &b, bytes);
				}
			}

			template<typename F>
			void serialize(const F* begin, const F* end, u8* dst) const
			{
				for (auto it = begin; it != end; ++it)
				{
					std::memcpy(dst, it->data(), it->size());
					dst += it->size();
				}
			}

			void deserialize(const auto* src, const auto* srcEnd, auto dst) const
			{
				auto elementSize = byteSize<u8>();
				while (src < srcEnd)
				{
					dst->resize(divCeil(mBitCount, 8));
					std::memcpy(dst->data(), &*src, elementSize);
					src += elementSize;
				}
			}
		};

		// given shared [x], [y], output [xy] = [x * y] where multiplication
		// is perform component-wise, i.e. xi * yi = xyi, xi is a bit and yi 
		// is a vector.
		// This version generalizes to arbitrary length vector yi. Each row of
		// y is one vector.
		macoro::task<> multiply(
			u64 bitCount,
			span<const u8> x,
			MatrixView<const u8> y,
			MatrixView<u8> xy,
			coproto::Socket& sock)
		{
			u64 n = y.rows();

			if (x.size() != divCeil(y.rows(), 8) || y.rows() != xy.rows())
				throw RTE_LOC;
			if (y.cols() != xy.cols())
				throw RTE_LOC;
			if (divCeil(bitCount, 8) != y.cols())
				throw RTE_LOC;
			if (n + mOtIdx > mTotalMults)
				throw RTE_LOC;
			if (hasBaseOts() == false)
				throw RTE_LOC;

			if (bitCount < 8)
			{
				//std::cout << "DpfMult::multiply: bitCount "<< bitCount << " < 8. " << LOCATION << std::endl;
				//throw RTE_LOC;
			}

			// Create matrix coefficient context
			BitMatrixCoeffCtx ctx(bitCount);

			co_await multiply<u8, BitMatrixCoeffCtx>(
				x,
				BitMatrixCoeffCtx::View<const u8>(y),
				BitMatrixCoeffCtx::View<u8>(xy),
				sock,
				ctx
			);
			co_return;
		}



		// Session struct for storing the setup phase results of multiplication
		// the x shares have been fixed but can be multiplied with many different 
		// y shares.
		struct MultSession
		{
			u64 mPartyIdx = 0;
			u64 mExpandIdx = 0;

			// Store raw OT data from DpfMult
			std::vector<block> mRecvOts;
			std::vector<std::array<block, 2>> mSendOts;
			BitVector mX;

			// Multiply a new vector y with the stored x
			// Returns xy as secret shares
			template<typename F, typename CoeffCtx>
			macoro::task<> multiply(
				auto&& yBegin,
				auto&& yEnd,
				auto&& xyBegin,
				coproto::Socket& sock,
				CoeffCtx ctx = {})
			{
				// OT Setup:
				// For each multiplication, we have:
				// - mRecvOts0: A single block received from OT seed
				// - mChoiceBit0: The choice bit used in OT, becomes our bit share a0
				// - mSendOt0: Two blocks [seed0, seed1] sent in OT  
				//
				// such that 
				//  - mRecvOts0 = mSendOts1[mChoiceBit0]
				//  - mRecvOts1 = mSendOts0[mChoiceBit1]
				//
				// 
				// Observe that if we performed the following OTs. The parites
				// sample a random [t] of the field. Then they perform the following
				// 
				//                                (t1 + (0 ⊕ x1) * y1)
				// x0 ---------->  OT  <--------- (t1 + (1 ⊕ x1) * y1)
				//                 |
				//      <----------/
				// w0 = (t1 + (x0 ⊕ x1) * y1)
				//    = (t1 +  x        * y1)
				// 
				// (t0 + (x0 ⊕ 0) * y0)
				// (t0 + (x0 ⊕ 1) * y0)
				//     ------------->  OT  <--------- x1
				//                     |
				//                     \------------> w1 = (t0 + (x0 ⊕ x1) * y0)
				//                                       = (t0 +  x        * y0)
				// 
				// then we have 
				//	[w]-[t] = (t1 + x * y1) + (t0 + x * y0) - (t1 + t0)
				//          = (x * y1) + (x * y0)
				//          = x * (y0 + y1)
				//          = x * y
				// 
				// setupMultiply derandomize the OTs so that the choice bits
				// are x0,x1. This is done by sending the difference
				//   phi0 = x0 ⊕ c0
				//   phi1 = x1 ⊕ c1
				// where c0,c1 are the choice bits used in the OTs. The other party
				// will derandomize the OTs by computing
				//   if (phi0) swap(mSendOts0[0], mSendOts0[1]);
				//   if (phi1) swap(mSendOts1[0], mSendOts1[1]);
				// 
				// Then to reduce the communication, we dont want to send both 
				// OT messages. Observe that [t] is chosen uniformly at random.
				// Therefore we can define 
				//
				//  (t0 + (x0 ⊕ 0) * y0) = mSendOts0[0]
				//   t0 = mSendOts0[0] - (x0 ⊕ 0) * y0
				// 
				//  (t1 + (0 ⊕ x1) * y1) = mSendOts1[0]
				//   t1 = mSendOts1[0] - (0 ⊕ x1) * y1
				// 
				// This way we do not need to send (t1 + (0 ⊕ x1) * y1) as both parties
				// can locally compute it given mSendOts0[0].

				u64 n = mX.size();
				if (std::distance(yBegin, yEnd) != n)
					throw RTE_LOC;

				// make sure we can deref xy
				std::ignore = *(xyBegin + (n - 1));

				std::vector<u8> msg(n * ctx.template byteSize<F>());
				auto mIter = msg.data();
				auto zero = ctx.template make<F>();
				ctx.zero(zero);
				for (u64 i = 0; i < n; ++i)
				{
					auto t0 = ctx.template make<F>();
					ctx.fromBlock(t0, mSendOts[i][0]);

					auto xi = mX[i];
					if (xi)
						ctx.minus(t0, t0, yBegin[i]);

					// m1 = t0 + (x0 ⊕ 1) * y0
					auto m1 = ctx.template make<F>();
					ctx.fromBlock(m1, mSendOts[i][1]); // mask the m1 message using the OT.
					ctx.plus(m1, m1, t0);
					if (xi == 0)
						ctx.plus(m1, m1, yBegin[i]);

					ctx.serialize(&m1, &m1 + 1, mIter);
					mIter += ctx.template byteSize<F>();

					// xy = -t0
					auto nt0 = ctx.template make<F>();
					ctx.minus(xyBegin[i], zero, t0);
				}

				co_await sock.send(std::move(msg));
				msg.resize(n * ctx.template byteSize<F>());
				co_await sock.recv(msg);
				mIter = msg.data();
				for (u64 i = 0; i < n; ++i)
				{
					auto m1 = ctx.template make<F>();
					ctx.deserialize(mIter + 0, mIter + ctx.template byteSize<F>(), &m1);
					mIter += ctx.template byteSize<F>();

					auto mx = ctx.template make<F>();
					ctx.fromBlock(mx, mRecvOts[i]);

					auto w0 = ctx.template make<F>();
					auto xi = mX[i];
					if (xi)
					{
						// m1 = mx + w0
						//    = mx + (t1 + (1 ⊕ x1) * y1)
						//    = mx + (t1 +  x       * y1)
						// w0 = m1 - mx
						//	  = (t1 + x * y1)
						ctx.minus(w0, m1, mx);
					}
					else
					{
						// w0 = m0 = mx
						//    = (t1 + (0 ⊕ x1) * y1)
						//    = (t1 + x * y1)
						ctx.copy(w0, mx);
					}

					// reconstruct xy
					ctx.plus(xyBegin[i], xyBegin[i], w0);
				}
			}

			macoro::task<> multiplyMtx(
				MatrixView<const u8> y,
				MatrixView<u8> xy,
				coproto::Socket& sock)
			{
				if(y.cols() != xy.cols())
					throw RTE_LOC;
				if (y.rows() != xy.rows())
					throw RTE_LOC;
				if (y.rows() != mX.size())
					throw RTE_LOC;

				auto ctx = DpfMult::BitMatrixCoeffCtx(y.cols() * 8);
				auto vy = DpfMult::BitMatrixCoeffCtx::View<const u8>(y);
				auto vxt = DpfMult::BitMatrixCoeffCtx::View<u8>(xy);
				co_await multiply<u8, DpfMult::BitMatrixCoeffCtx>(
					vy.begin(), vy.end(),
					vxt.begin(),
					sock,
					ctx
				);
			}
		};




		// Setup phase for multiplication session
		// Input: shared bit vector x
		// Returns: MultSession that can be used for multiple multiplications
		macoro::task<MultSession> setupMultiply(
			u64 n,
			span<const u8> x,
			coproto::Socket& sock)
		{
			if (x.size() != divCeil(n, 8))
				throw RTE_LOC;
			if (n + mOtIdx > mTotalMults)
				throw RTE_LOC;
			if (hasBaseOts() == false)
				throw RTE_LOC;

			auto otIdx = mOtIdx;
			mOtIdx += n;

			MultSession session;
			session.mPartyIdx = mPartyIdx;
			session.mExpandIdx = 0;
			session.mRecvOts.assign(mRecvOts.data() + otIdx, mRecvOts.data() + otIdx + n);
			session.mSendOts.assign(mSendOts.data() + otIdx, mSendOts.data() + otIdx + n);
			session.mX = BitVector((u8*)x.data(), n, 0);

			// Extract our a shares from choice bits
			BitVector c0;
			c0.append(mChoiceBits, n, otIdx);

			// Compute phi0 = x0 + c0 (bit-wise XOR for bits)
			std::vector<u8> phi0(x.size());
			auto C0 = c0.getSpan<u8>();
			for (u64 i = 0; i < phi0.size(); ++i)
				phi0[i] = x[i] ^ C0[i];
			if (n % 8)
			{
				u8 mask = (1 << (n % 8)) - 1;
				phi0.back() &= mask;
			}

			co_await sock.send(std::move(phi0));
			// Receive phi1 from the other party
			std::vector<u8> phi1(x.size());
			co_await sock.recv(phi1);

			for (u64 i = 0; i < n; ++i)
			{
				if (bit(phi1, i))
					std::swap(session.mSendOts[i][0], session.mSendOts[i][1]);
			}

			co_return session;
		}

		// Setup phase for multiplication session
		// Input: shared bit vector x
		// Returns: MultSession that can be used for multiple multiplications
		MultSession randMultiply(u64 n)
		{
			if (n + mOtIdx > mTotalMults)
				throw RTE_LOC;
			if (hasBaseOts() == false)
				throw RTE_LOC;

			auto otIdx = mOtIdx;
			mOtIdx += n;

			MultSession session;
			session.mPartyIdx = mPartyIdx;
			session.mExpandIdx = 0;
			session.mRecvOts.assign(mRecvOts.data() + otIdx, mRecvOts.data() + otIdx + n);
			session.mSendOts.assign(mSendOts.data() + otIdx, mSendOts.data() + otIdx + n);
			session.mX.append(mChoiceBits, n, otIdx);

			return session;
		}


		// given shared [x], [y], output [xy] = [x * y] where multiplication
		// is perform component-wise, i.e. xi * yi = xyi, xi is a bit and yi 
		// is a vector.
		// This version generalizes to arbitrary length vector yi. Each row of
		// y is one vector.
		//
		//
		// given shared [x], [y], output [xy] = [x * y] where multiplication
		// is perform component-wise, i.e. xi * yi = xyi, xi, yi are bits.
		// 
		// We are given two OTs, one in each direction. Let us denote them as
		// 
		//   a0                      b0
		//   c00                     c01
		// 
		//   b1                      a1
		//   c10                     c11
		// 
		// such that 
		// 
		//    a0 * b0 = (c00 + c01)
		//    a1 * b1 = (c10 + c11)
		// 
		// Note that we write these OTs in OLE format, that is for OT (m0,m1),(g,mg)
		// we have a0=g, b0=(m0+m1), c00=mg, c01=m0 and similar for the second 
		// instance.
		//
		// We first convert these two "OTs/OLEs" into a random beaver triple
		//
		// [a] * [b] = [c']
		// 
		// We do this by computing
		//
		// [a] = (a0, a1)
		// [b] = (b1, b0)
		// [c'] = (c00+c10+a0b1, c01+c11+a1b0)
		// 
		// As you can see, all 4 cross terms are present. Given this beaver triple
		// we can use the standard protocol. We reveal
		// 
		// phi   = [x] + [a]
		// theta = [y] + [b]
		// 
		// [zy] = [c'] + theta [a] + phi [b] + theta phi
		//      = ab + (y+b) a + (x+a) b + (y+b)(x+a)
		//      = ab + ab + ya + xb + ab + yx + ya + xb + ab
		//      = xy
		//
		macoro::task<> multiplyBits(
			const BitVector& x,
			const BitVector& y,
			BitVector& xy,
			coproto::Socket& sock)
		{

			auto n = x.size();
			if (y.size() != n)
				throw RTE_LOC;
			if (xy.size() != n)
				throw RTE_LOC;
			return multiplyBits(n, x.getSpan<const u8>(), y.getSpan<const u8>(), xy.getSpan<u8>(), sock);
		}


		macoro::task<> multiplyBits(
			u64 n,
			span<const u8> x,
			span<const u8> y,
			span<u8> xy,
			coproto::Socket& sock)
		{
			if (x.size() != divCeil(n, 8))
				throw RTE_LOC;
			if (y.size() != divCeil(n, 8))
				throw RTE_LOC;
			if (xy.size() != divCeil(n, 8))
				throw RTE_LOC;
			if (n + mOtIdx > mTotalMults)
				throw RTE_LOC;
			if (hasBaseOts() == false)
				throw RTE_LOC;

			u64 n8 = divCeil(n, 8);
			auto otIdx = mOtIdx;
			mOtIdx += n;

			// our a share of a * b = c.
			BitVector a0; a0.append(mChoiceBits, n, otIdx);
			BitVector b1(n);
			// our c share of a * b = c.
			BitVector c(n);

			auto a8 = a0.getSpan<u8>();
			auto b8 = b1.getSpan<u8>();
			auto c8 = c.getSpan<u8>();

			u8 c00c10;
			for (u64 j = 0; j < n; ++j)
			{
				b1[j] = lsb(mSendOts[otIdx + j][0] ^ mSendOts[otIdx + j][1]);
				c00c10 = lsb(mRecvOts[otIdx + j] ^ mSendOts[otIdx + j][0]);
				c[j] = c00c10 ^ (b1[j] & a0[j]);
			}

			AlignedUnVector<u8> phi(n8), theta(n8);
			for (u64 i = 0; i < n8; ++i)
			{
				phi[i] = x[i] ^ a8[i];
				theta[i] = y[i] ^ b8[i];
			}
			if (n % 8)
			{
				u8 mask = (1 << (n % 8)) - 1;
				phi.back() &= mask;
				theta.back() &= mask;
			}

			co_await sock.send(coproto::copy(theta));
			co_await sock.send(coproto::copy(phi));

			AlignedUnVector<u8> theta1(theta.size()), phi1(phi.size());
			co_await sock.recv(theta1);
			co_await sock.recv(phi1);
			for (u64 i = 0; i < n8; ++i)
			{
				phi[i] ^= phi1[i];
				theta[i] ^= theta1[i];
				xy[i] =
					c8[i] ^
					(theta[i] & a8[i]) ^
					(phi[i] & b8[i]) ^
					(-mPartyIdx & theta[i] & phi[i]);
			}
		}


		u64 baseOtCount() const { return mTotalMults; }

		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			if (baseSendOts.size() != baseOtCount() ||
				recvBaseOts.size() != baseOtCount() ||
				baseChoices.size() != baseOtCount())
				throw RTE_LOC;

			mSendOts.clear();
			mRecvOts.clear();
			mSendOts.insert(mSendOts.end(), baseSendOts.begin(), baseSendOts.end());
			mRecvOts.insert(mRecvOts.end(), recvBaseOts.begin(), recvBaseOts.end());
			mChoiceBits = baseChoices;
			mOtIdx = 0;
		}


	};

	inline std::string toHex(span<u8> data)
	{
		std::stringstream ss;
		for (auto b : data)
			ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
		return ss.str();
	}

}
#undef SIMD8


#endif // defined(ENABLE_REGULAR_DPF) || defined(ENABLE_SPARSE_DPF)


