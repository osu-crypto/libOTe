#include "libOTe/TwoChooseOne/SilentOtExtSender.h"
#ifdef ENABLE_SILENTOT

#include "libOTe/Tools/Tools.h"
#include "libOTe/TwoChooseOne/SilentOtExtReceiver.h"
#include <libOTe/Tools/bitpolymul.h>
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/ThreadBarrier.h"
#include "libOTe/Base/BaseOT.h"
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>
#include <cryptoTools/Crypto/RandomOracle.h>

namespace osuCrypto
{
	//extern u64 numPartitions;
	//extern u64 nScaler;
	u64 nextPrime(u64 n);

	u64 secLevel(u64 scale, u64 p, u64 points)
	{
		return static_cast<u64>(points * std::log2(scale * p / double(p)) + std::log2(scale * p) / 2);
		//return std::log2(std::pow(scale * p / (p - 1.0), points) * (scale * p - points + 1));
	}
	u64 getPartitions(u64 scaler, u64 p, u64 secParam)
	{
		u64 ret = 1;
		while (secLevel(scaler, p, ret) < secParam)
			++ret;

		return roundUpTo(ret, 8);
	}

	void SilentOtExtSender::genBase(
		u64 n, Channel& chl, PRNG& prng, 
		u64 scaler, u64 secParam, bool mal,
		SilentBaseType basetype, u64 threads )
	{

		setTimePoint("sender.gen.start");

		configure(n, scaler, secParam, mal);



			auto count = mGen.baseOtCount();

			std::vector<std::array<block,2>> msg(count);

			switch (basetype)
			{
			case SilentBaseType::None:
				break;
			case SilentBaseType::Base:
			{
#ifdef LIBOTE_HAS_BASE_OT
                DefaultBaseOT base;
				base.send(msg, prng, chl, threads);
				setTimePoint("sender.gen.baseOT");
#else
                throw std::runtime_error("libOTe does not have base OTs...");
#endif
				break;
			}
			case SilentBaseType::BaseExtend:
			{
#ifdef LIBOTE_HAS_BASE_OT
				std::array<block, 128> baseMsg;

				BitVector bv(128);
				bv.randomize(prng);
                DefaultBaseOT base;
				base.receive(bv, baseMsg, prng,chl, threads);
				setTimePoint("sender.gen.baseOT");
				IknpOtExtSender iknp;
				iknp.setBaseOts(baseMsg, bv, chl);
				iknp.send(msg, prng, chl);
				setTimePoint("sender.gen.baseExtend");
#else
                throw std::runtime_error("libOTe does not have base OTs...");
#endif
				break;
			}
			case SilentBaseType::Extend:
			{
				std::array<block, 128> baseMsg;
				BitVector bv(128);
				bv.randomize(prng);

				IknpOtExtSender iknp;
				iknp.setBaseOts(baseMsg, bv);
				iknp.send(msg, prng, chl);
				setTimePoint("sender.gen.baseOT");
				break;
			}
			default:
				break;
			}


			mGen.setBase(msg);

            mDelta = prng.get();
			mGen.setValue(mDelta);
            
			for (u64 i = 0; i < mNumPartitions; ++i)
			{
				u64 mSi;
				do
				{
					auto si = prng.get<u64>() % mSizePer;
					mSi = si * mNumPartitions + i;
				} while (mSi >= mN2);
			}

		setTimePoint("sender.gen.done");
	}

	void SilentOtExtSender::configure(const u64& n, const u64& scaler, const u64& secParam, bool mal)
	{
		mP = nextPrime(n);
		mN = roundUpTo(mP, 128);
		mScaler = scaler;
		mNumPartitions = getPartitions(scaler, mP, secParam);
		mN2 = scaler * mN;
		mMal = mal;
		//std::cout << "P " << mP << std::endl;

		mSizePer = (mN2 + mNumPartitions - 1) / mNumPartitions;



			mGen.configure(mSizePer, mNumPartitions);
	}

	//sigma = 0   Receiver
	//
	//    u_i is the choice bit
	//    v_i = w_i + u_i * x
	//
	//    ------------------------ -
	//    u' =   0000001000000000001000000000100000...00000,   u_i = 1 iff i \in S 
	//
	//    v' = r + (x . u') = DPF(k0)
	//       = r + (000000x00000000000x000000000x00000...00000)
	//
	//    u = u' * H             bit-vector * H. Mapping n'->n bits
	//    v = v' * H		   block-vector * H. Mapping n'->n block
	//
	//sigma = 1   Sender
	//
	//    x   is the delta
	//    w_i is the zero message
	//
	//    m_i0 = w_i
	//    m_i1 = w_i + x
	//
	//    ------------------------
	//    x
	//    r = DPF(k1)
	//
	//    w = r * H


    void SilentOtExtSender::checkRT(span<Channel> chls, Matrix<block>& rT)
    {
        chls[0].send(rT.data(), rT.size());
        chls[0].send(mGen.mValue);
    }

     
	void SilentOtExtSender::send(
		span<std::array<block, 2>> messages,
		PRNG & prng,
		Channel & chl)
	{
		send(messages, prng, { &chl,1 });
	}

    void SilentOtExtSender::send(
        span<std::array<block, 2>> messages,
        PRNG& prng,
        span<Channel> chls)
    {
        setTimePoint("sender.expand.start");

        //std::vector<block> r(mN2);

        //for (u64 i = 0; i < r.size();)
        //{
        //    auto blocks = mGen.yeild();
        //    auto min = std::min<u64>(r.size() - i, blocks.size());
        //    memcpy(r.data() + i, blocks.data(), min * sizeof(block));

        //    i += min;
        //}

        //setTimePoint("sender.expand.dpf");

        //if (mN2 % 128) throw RTE_LOC;
        //Matrix<block> rT(128, mN2 / 128, AllocType::Uninitialized);
        //sse_transpose(r, rT);
        //setTimePoint("sender.expand.transpose");
        Matrix<block> rT;

            rT.resize(128, mN2 / 128, AllocType::Uninitialized);
            mGen.expand(chls, mDelta, prng, rT, true, mMal);
            setTimePoint("sender.expand.pprf_transpose");

#
        if (mDebug)
        {
            checkRT(chls, rT);
        }

		//if (0)
		//{

		//	int temp;
		//	chl.asyncSendCopy(temp);
		//	chl.asyncSendCopy(rT);
		//}

		auto type = MultType::QuasiCyclic;

		switch (type)
		{
		case MultType::Naive:
			randMulNaive(rT, messages);
			break;
		case MultType::QuasiCyclic:
			randMulQuasiCyclic(rT, messages, chls.size());
			break;
		default:
			break;
		}
		//randMulNaive(rT, messages);


	}
	void SilentOtExtSender::randMulNaive(Matrix<block> & rT, span<std::array<block, 2>> & messages)
	{

		std::vector<block> mtxColumn(rT.cols());

		PRNG pubPrng(ZeroBlock);

		for (i64 i = 0; i < messages.size(); ++i)
		{
			block& m0 = messages[i][0];
			block& m1 = messages[i][1];

			BitIterator iter((u8*)& m0, 0);

			mulRand(pubPrng, mtxColumn, rT, iter);

			m1 = m0 ^ mDelta;
		}

		setTimePoint("sender.expand.mul");
	}
	//namespace
	//{
	//	struct format
	//	{
	//		BitVector& bv;
	//		u64 shift;
	//		format(BitVector& v0, u64 v1) : bv(v0), shift(v1) {}
	//	};

	//	std::ostream& operator<<(std::ostream& o, format& f)
	//	{
	//		auto cur = f.bv.begin();
	//		for (u64 i = 0; i < f.bv.size(); ++i, ++cur)
	//		{
	//			if (i % 64 == f.shift)
	//				o << std::flush << Color::Blue;
	//			if (i % 64 == 0)
	//				o << std::flush << Color::Default;

	//			o << int(*cur) << std::flush;
	//		}

	//		o << Color::Default;

	//		return o;
	//	}
	//}

	void bitShiftXor(span<block> dest, span<block> in, u8 bitShift)
	{



		if (bitShift > 127)
			throw RTE_LOC;
		if (u64(in.data()) % 16)
			throw RTE_LOC;

		//BitVector bv0, bv1, inv;
		if (bitShift >= 64)
		{
			bitShift -= 64;
			const int bitShift2 = 64 - bitShift;
			u8* inPtr = ((u8*)in.data()) + sizeof(u64);
			//inv.append((u8*)inPtr, in.size() * 128 - 64);

			auto end = std::min<u64>(dest.size(), in.size() - 1);
			for (u64 i = 0; i < end; ++i, inPtr += sizeof(block))
			{
				block
					b0 = _mm_loadu_si128((block*)inPtr),
					b1 = _mm_load_si128((block*)(inPtr + sizeof(u64)));

				b0 = _mm_srli_epi64(b0, bitShift);
				b1 = _mm_slli_epi64(b1, bitShift2);

				//bv0.append((u8*)&b0, 128);
				//bv1.append((u8*)&b1, 128);

				dest[i] = dest[i] ^ b0 ^ b1;
			}


			if (end != static_cast<u64>(dest.size()))
			{
				u64 b0 = *(u64*)inPtr;
				b0 = (b0 >> bitShift);

				//bv0.append((u8*)&b0, 64);
				//bv1.append((u8*)&b1, 64);


				*(u64*)(&dest[end]) ^= b0;
			}
			//std::cout << " in     " << format(inv, bitShift) << std::endl;
			//std::cout << " a0     " << format(bv0, 64 - bitShift) << std::endl;
			//std::cout << " a1     " << format(bv1, 64 - bitShift) << std::endl;
		}
		else if (bitShift)
		{
			const int bitShift2 = 64 - bitShift;
			u8* inPtr = (u8*)in.data();

			auto end = std::min<u64>(dest.size(), in.size() - 1);
			for (u64 i = 0; i < end; ++i, inPtr += sizeof(block))
			{
				block
					b0 = _mm_load_si128((block*)inPtr),
					b1 = _mm_loadu_si128((block*)(inPtr + sizeof(u64)));

				b0 = _mm_srli_epi64(b0, bitShift);
				b1 = _mm_slli_epi64(b1, bitShift2);

				//bv0.append((u8*)&b0, 128);
				//bv1.append((u8*)&b1, 128);

				dest[i] = dest[i] ^ b0 ^ b1;
			}

			if (end != static_cast<u64>(dest.size()))
			{
				block b0 = _mm_load_si128((block*)inPtr);
				b0 = _mm_srli_epi64(b0, bitShift);

				//bv0.append((u8*)&b0, 128);

				dest[end] = dest[end] ^ b0;

				u64 b1 = *(u64*)(inPtr + sizeof(u64));
				b1 = (b1 << bitShift2);

				//bv1.append((u8*)&b1, 64);

				*(u64*)& dest[end] ^= b1;
			}



			//std::cout << " b0     " << bv0 << std::endl;
			//std::cout << " b1     " << bv1 << std::endl;
		}
		else
		{
			auto end = std::min<u64>(dest.size(), in.size());
			for (u64 i = 0; i < end; ++i)
			{
				dest[i] = dest[i] ^ in[i];
			}
		}
	}

	void modp(span<block> dest, span<block> in, u64 p)
	{
		auto pBlocks = (p + 127) / 128;
		auto pBytes = (p + 7) / 8;

		if (static_cast<u64>(dest.size()) < pBlocks)
			throw RTE_LOC;

		if (static_cast<u64>(in.size()) < pBlocks)
			throw RTE_LOC;

		auto count = (in.size() * 128 + p - 1) / p;

		//BitVector bv;
		//bv.append((u8*)in.data(), p);
		//std::cout << Color::Green << bv << std::endl << Color::Default;

		memcpy(dest.data(), in.data(), pBytes);


		for (u64 i = 1; i < count; ++i)
		{
			auto begin = i * p;
			auto end = std::min<u64>(i * p + p, in.size() * 128);

			auto shift = begin & 127;
			auto beginBlock = in.data() + (begin / 128);
			auto endBlock = in.data() + ((end + 127) / 128);

			if (endBlock > in.data() + in.size())
				throw RTE_LOC;


			auto in_i = span<block>(beginBlock, endBlock);

			bitShiftXor(dest, in_i, static_cast<u8>(shift));

			//bv.resize(0);
			//bv.append((u8*)dest.data(), p);
			//std::cout << Color::Green << bv << std::endl << Color::Default;
		}


		auto offset = (p & 7);
		if (offset)
		{
			u8 mask = (1 << offset) - 1;
			auto idx = p / 8;
			((u8*)dest.data())[idx] &= mask;
		}

		auto rem = dest.size() * 16 - pBytes;
		if (rem)
			memset(((u8*)dest.data()) + pBytes, 0, rem);
	}
	



	void SilentOtExtSender::randMulQuasiCyclic(Matrix<block> & rT, span<std::array<block, 2>> & messages, u64 threads)
	{
		auto nBlocks = mN / 128;
		auto n2Blocks = mN2 / 128;
		auto n64 = i64(nBlocks * 2);


		const u64 rows(128);
		if (rT.rows() != rows)
			throw RTE_LOC;

		if (rT.cols() != n2Blocks)
			throw RTE_LOC;


		using namespace bpm;
		//std::vector<block> a(nBlocks);
		//span<u64> a64 = spanCast<u64>(a);

		std::vector<FFTPoly> a(mScaler-1);
		Matrix<block>cModP1(128, nBlocks, AllocType::Uninitialized);

		std::unique_ptr<ThreadBarrier[]> brs(new ThreadBarrier[mScaler]);
		for (u64 i = 0; i < mScaler; ++i)
			brs[i].reset(threads);

#ifdef DEBUG
		Matrix<block> cc(mScaler, rows);
#endif
		auto routine = [&](u64 index)
		{
			u64 j = 0;
			FFTPoly bPoly;
			FFTPoly cPoly;

			Matrix<block>tt(1, 2 * nBlocks, AllocType::Uninitialized);
			auto temp128 = tt[0];
			FFTPoly::DecodeCache cache;


			for (u64 s = index + 1; s < mScaler; s += threads)
			{
				auto a64 = spanCast<u64>(temp128).subspan(n64);
				//mAesFixedKey.ecbEncCounterMode(s * nBlocks, nBlocks, temp128.data());

				PRNG pubPrng(toBlock(s));
				//pubPrng.mAes.ecbEncCounterMode(0, nBlocks, temp128.data());
				pubPrng.get(a64.data(), a64.size());
				a[s - 1].encode(a64);
			}

			if (index == 0)
				setTimePoint("recver.expand.randGen");

			brs[j++].decrementWait();

			if (index == 0)
				setTimePoint("recver.expand.randGenWait");



			auto multAddReduce = [this, nBlocks, n64, &a, &bPoly, &cPoly, &temp128, &cache](span<block> b128, span<block> dest)
			{
				for (u64 s = 1; s < mScaler; ++s)
				{
					auto& aPoly = a[s - 1];
					auto b64 = spanCast<u64>(b128).subspan(s * n64, n64);

					bPoly.encode(b64);

					if (s == 1)
					{
						cPoly.mult(aPoly, bPoly);
					}
					else
					{
						bPoly.multEq(aPoly);
						cPoly.addEq(bPoly);
					}
				}

				// decode c[i] and store it at t64Ptr
				cPoly.decode(spanCast<u64>(temp128), cache, true);

				for (u64 j = 0; j < nBlocks; ++j)
					temp128[j] = temp128[j] ^ b128[j];

				// reduce s[i] mod (x^p - 1) and store it at cModP1[i]
				modp(dest, temp128, mP);

			};

			for (u64 i = index; i < rows; i += threads)
			{
				multAddReduce(rT[i], cModP1[i]);
			}


			if (index == 0)
				setTimePoint("sender.expand.mulAddReduce");

			brs[j++].decrementWait();

#ifdef DEBUG
			if (index == 0)
			{
				RandomOracle ro(16);
				ro.Update(cc.data(), cc.size());
				block b;
				ro.Final(b);
				std::cout << "cc " << b << std::endl;
			}
#endif

			std::array<block, 8> hashBuffer;
			std::array<block, 128> tpBuffer;
			auto numBlocks = (messages.size() + 127) / 128;
			auto begin = index * numBlocks / threads;
			auto end = (index + 1) * numBlocks / threads;
			for (u64 i = begin; i < end; ++i)
			//for (u64 i = index; i < numBlocks; i += threads)
			{
				u64 j = i * tpBuffer.size();

				auto min = std::min<u64>(tpBuffer.size(), messages.size() - j);

				for (u64 j = 0; j < tpBuffer.size(); ++j)
					tpBuffer[j] = cModP1(j, i);

				//for (u64 j = 0, k = i; j < tpBuffer.size(); ++j, k += cModP1.cols())
				//	tpBuffer[j] = cModP1(k);

				sse_transpose128(tpBuffer);


				//#define NO_HASH


#ifdef NO_HASH
				auto end = i * tpBuffer.size() + min;
				for (u64 k = 0; j < end; ++j, ++k)
				{
					messages[j][0] = tpBuffer[k];
					messages[j][1] = tpBuffer[k] ^ mDelta;
				}
#else
				u64 k = 0;
				auto min2 = min & ~7;
				for (; k < min2; k += 8)
				{
					mAesFixedKey.ecbEncBlocks(tpBuffer.data() + k, hashBuffer.size(), hashBuffer.data());

					messages[j + k + 0][0] = tpBuffer[k + 0] ^ hashBuffer[0];
					messages[j + k + 1][0] = tpBuffer[k + 1] ^ hashBuffer[1];
					messages[j + k + 2][0] = tpBuffer[k + 2] ^ hashBuffer[2];
					messages[j + k + 3][0] = tpBuffer[k + 3] ^ hashBuffer[3];
					messages[j + k + 4][0] = tpBuffer[k + 4] ^ hashBuffer[4];
					messages[j + k + 5][0] = tpBuffer[k + 5] ^ hashBuffer[5];
					messages[j + k + 6][0] = tpBuffer[k + 6] ^ hashBuffer[6];
					messages[j + k + 7][0] = tpBuffer[k + 7] ^ hashBuffer[7];

					tpBuffer[k + 0] = tpBuffer[k + 0] ^ mDelta;
					tpBuffer[k + 1] = tpBuffer[k + 1] ^ mDelta;
					tpBuffer[k + 2] = tpBuffer[k + 2] ^ mDelta;
					tpBuffer[k + 3] = tpBuffer[k + 3] ^ mDelta;
					tpBuffer[k + 4] = tpBuffer[k + 4] ^ mDelta;
					tpBuffer[k + 5] = tpBuffer[k + 5] ^ mDelta;
					tpBuffer[k + 6] = tpBuffer[k + 6] ^ mDelta;
					tpBuffer[k + 7] = tpBuffer[k + 7] ^ mDelta;

					mAesFixedKey.ecbEncBlocks(tpBuffer.data() + k, hashBuffer.size(), hashBuffer.data());

					messages[j + k + 0][1] = tpBuffer[k + 0] ^ hashBuffer[0];
					messages[j + k + 1][1] = tpBuffer[k + 1] ^ hashBuffer[1];
					messages[j + k + 2][1] = tpBuffer[k + 2] ^ hashBuffer[2];
					messages[j + k + 3][1] = tpBuffer[k + 3] ^ hashBuffer[3];
					messages[j + k + 4][1] = tpBuffer[k + 4] ^ hashBuffer[4];
					messages[j + k + 5][1] = tpBuffer[k + 5] ^ hashBuffer[5];
					messages[j + k + 6][1] = tpBuffer[k + 6] ^ hashBuffer[6];
					messages[j + k + 7][1] = tpBuffer[k + 7] ^ hashBuffer[7];
				}

				for (; k < min; ++k)
				{
					messages[j + k][0] = mAesFixedKey.ecbEncBlock(tpBuffer[k]) ^ tpBuffer[k];
					messages[j + k][1] = mAesFixedKey.ecbEncBlock(tpBuffer[k] ^ mDelta) ^ tpBuffer[k] ^ mDelta;
				}

#endif
				//messages[i][0] = view(i, 0);
				//messages[i][1] = view(i, 0) ^ mDelta;
			}

			if(index==0)
				setTimePoint("sender.expand.transposeXor");
		};


		std::vector<std::thread> thrds(threads - 1);
		for (u64 i = 0; i < thrds.size(); ++i)
			thrds[i] = std::thread(routine, i);

		routine(thrds.size());

		for (u64 i = 0; i < thrds.size(); ++i)
			thrds[i].join();

	}
}

#endif