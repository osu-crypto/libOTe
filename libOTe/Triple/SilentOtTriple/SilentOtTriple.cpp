#include "SilentOtTriple.h"
#ifdef ENABLE_SILENTOT


namespace osuCrypto
{

#ifdef ENABLE_SSE

	OC_FORCEINLINE block shuffle_epi8(const block& a, const block& b)
	{
		return _mm_shuffle_epi8(a, b);
	}

	template<int s>
	OC_FORCEINLINE block slli_epi16(const block& v)
	{
		return _mm_slli_epi16(v, s);
	}

	OC_FORCEINLINE  int movemask_epi8(const block v)
	{
		return _mm_movemask_epi8(v);
	}
#else
	OC_FORCEINLINE block shuffle_epi8(const block& a, const block& b)
	{
		// _mm_shuffle_epi8(a, b): 
		//     FOR j := 0 to 15
		//         i: = j * 8
		//         IF b[i + 7] == 1
		//             dst[i + 7:i] : = 0
		//         ELSE
		//             index[3:0] : = b[i + 3:i]
		//             dst[i + 7:i] : = a[index * 8 + 7:index * 8]
		//         FI
		//     ENDFOR

		block dst;
		for (u64 i = 0; i < 16; ++i)
		{
			auto bi = b.get<i8>(i);

			// 0 if bi < 0. otherwise 11111111
			u8 mask = ~(-i8(bi >> 7));
			u8 idx = bi & 15;

			dst.set<i8>(i, a.get<i8>(idx) & mask);
		}
		return dst;
	}

	template<int s>
	OC_FORCEINLINE block slli_epi16(const block& v)
	{
		block r;
		auto rr = (i16*)&r;
		auto vv = (const i16*)&v;
		for (u64 i = 0; i < 8; ++i)
			rr[i] = vv[i] << s;
		return r;
	}

	OC_FORCEINLINE int movemask_epi8(const block v)
	{
		// extract all the of MSBs if each byte.
		u64 mask = 1;
		int r = 0;
		for (i64 i = 0; i < 16; ++i)
		{
			r |= (v.get<u8>(0) >> i) & mask;
			mask <<= 1;
		}
		return r;
	}

#endif



	// the LSB of X is the choice bit of the OT.
	void compressRecver(
		span<oc::block> X,
		span<oc::block> C,
		span<oc::block> A,
		span<oc::block> B)
	{

		auto cIter16 = (u16*)C.data();
		auto cIter8 = (u8*)C.data();
		auto aIter8 = (u8*)A.data();
		auto bIter8 = (u8*)B.data();

		if (B.size())
		{
			if (C.size() * 256 != X.size())
				throw RTE_LOC;
			if (A.size() * 256 != X.size())
				throw RTE_LOC;
			if (A.size() * 256 != X.size())
				throw RTE_LOC;

		}
		else
		{

			if (C.size() * 128 != X.size())
				throw RTE_LOC;
			if (A.size() * 128 != X.size())
				throw RTE_LOC;
		}

		auto shuffle = std::array<block, 16>{};
		memset(shuffle.data(), 1 << 7, sizeof(*shuffle.data()) * shuffle.size());
		for (u64 i = 0; i < 16; ++i)
			shuffle[i].set<u8>(i, 0);

		auto OneBlock = block(1);
		auto AllOneBlock = block(~0ull, ~0ull);
		block mask = OneBlock ^ AllOneBlock;

		auto m = &X[0];

		for (u64 i = 0; i < X.size(); i += 16)
		{
			u8 choice[2];
			for (u64 j = 0; j < 2; ++j)
			{
				// extract the choice bit from the LSB of m
				u32 b0 = m[0].testc(OneBlock);
				u32 b1 = m[1].testc(OneBlock);
				u32 b2 = m[2].testc(OneBlock);
				u32 b3 = m[3].testc(OneBlock);
				u32 b4 = m[4].testc(OneBlock);
				u32 b5 = m[5].testc(OneBlock);
				u32 b6 = m[6].testc(OneBlock);
				u32 b7 = m[7].testc(OneBlock);

				// pack the choice bits.
				choice[j] =
					b0 ^
					(b1 << 1) ^
					(b2 << 2) ^
					(b3 << 3) ^
					(b4 << 4) ^
					(b5 << 5) ^
					(b6 << 6) ^
					(b7 << 7);

				// mask of the choice bit which is stored in the LSB
				m[0] = m[0] & mask;
				m[1] = m[1] & mask;
				m[2] = m[2] & mask;
				m[3] = m[3] & mask;
				m[4] = m[4] & mask;
				m[5] = m[5] & mask;
				m[6] = m[6] & mask;
				m[7] = m[7] & mask;

				oc::mAesFixedKey.hashBlocks<8>(m, m);

				m += 8;
			}
			m -= 16;

			// _mm_shuffle_epi8(a, b): 
			//     FOR j := 0 to 15
			//         i: = j * 8
			//         IF b[i + 7] == 1
			//             dst[i + 7:i] : = 0
			//         ELSE
			//             index[3:0] : = b[i + 3:i]
			//             dst[i + 7:i] : = a[index * 8 + 7:index * 8]
			//         FI
			//     ENDFOR

			// _mm_sll_epi16 : shifts 16 bit works left
			// _mm_movemask_epi8: packs together the MSG

			block a00 = shuffle_epi8(m[0], shuffle[0]);
			block a01 = shuffle_epi8(m[1], shuffle[1]);
			block a02 = shuffle_epi8(m[2], shuffle[2]);
			block a03 = shuffle_epi8(m[3], shuffle[3]);
			block a04 = shuffle_epi8(m[4], shuffle[4]);
			block a05 = shuffle_epi8(m[5], shuffle[5]);
			block a06 = shuffle_epi8(m[6], shuffle[6]);
			block a07 = shuffle_epi8(m[7], shuffle[7]);
			block a08 = shuffle_epi8(m[8], shuffle[8]);
			block a09 = shuffle_epi8(m[9], shuffle[9]);
			block a10 = shuffle_epi8(m[10], shuffle[10]);
			block a11 = shuffle_epi8(m[11], shuffle[11]);
			block a12 = shuffle_epi8(m[12], shuffle[12]);
			block a13 = shuffle_epi8(m[13], shuffle[13]);
			block a14 = shuffle_epi8(m[14], shuffle[14]);
			block a15 = shuffle_epi8(m[15], shuffle[15]);

			a00 = a00 ^ a08;
			a01 = a01 ^ a09;
			a02 = a02 ^ a10;
			a03 = a03 ^ a11;
			a04 = a04 ^ a12;
			a05 = a05 ^ a13;
			a06 = a06 ^ a14;
			a07 = a07 ^ a15;

			a00 = a00 ^ a04;
			a01 = a01 ^ a05;
			a02 = a02 ^ a06;
			a03 = a03 ^ a07;

			a00 = a00 ^ a02;
			a01 = a01 ^ a03;

			a00 = a00 ^ a01;

			a00 = slli_epi16<7>(a00);

			u16 ap = movemask_epi8(a00);

			if (bIter8)
			{
				//u16 x = ap ^ bp;
				u8 y0 = choice[1];
				u8 y1 = choice[0];
				u8 z0 = ap;
				u8 z1 = ap >> 8;

				*aIter8++ = y0;
				*bIter8++ = y1;
				*cIter8++ = (y0 & y1) ^ z0 ^ z1;
			}
			else
			{

				*aIter8++ = choice[0];
				*aIter8++ = choice[1];
				*cIter16++ = ap;
			}
			m += 16;

		}
	}


	void compressSender(
		block delta,
		span<oc::block> Y,
		span<oc::block> C,
		span<oc::block> A,
		span<oc::block> B)
	{

		auto cIter16 = (u16*)C.data();
		auto aIter16 = (u16*)A.data();


		auto cIter8 = (u8*)C.data();
		auto aIter8 = (u8*)A.data();
		auto bIter8 = (u8*)B.data();

		if (B.size())
		{
			if (C.size() * 256 != Y.size())
				throw RTE_LOC;
			if (A.size() * 256 != Y.size())
				throw RTE_LOC;
			if (A.size() * 256 != Y.size())
				throw RTE_LOC;

		}
		else
		{

		if (C.size() * 128 != Y.size())
			throw RTE_LOC;
		if (A.size() * 128 != Y.size())
			throw RTE_LOC;
		}
		using block = oc::block;

		auto shuffle = std::array<block, 16>{};
		memset(shuffle.data(), 1 << 7, sizeof(*shuffle.data()) * shuffle.size());
		for (u64 i = 0; i < 16; ++i)
			shuffle[i].set<u8>(i, 0);

		std::array<block, 16> sendMsg;
		auto m = Y.data();

		auto OneBlock = block(1);
		auto AllOneBlock = block(~0ull, ~0ull);
		block mask = OneBlock ^ AllOneBlock;
		delta = delta & mask;

		for (u64 i = 0; i < Y.size(); i += 16)
		{
			auto s = sendMsg.data();

			for (u64 j = 0; j < 2; ++j)
			{
				m[0] = m[0] & mask;
				m[1] = m[1] & mask;
				m[2] = m[2] & mask;
				m[3] = m[3] & mask;
				m[4] = m[4] & mask;
				m[5] = m[5] & mask;
				m[6] = m[6] & mask;
				m[7] = m[7] & mask;

				oc::mAesFixedKey.hashBlocks<8>(m, s);

				s += 8;
				m += 8;
			}


			block a00 = shuffle_epi8(sendMsg[0], shuffle[0]);
			block a01 = shuffle_epi8(sendMsg[1], shuffle[1]);
			block a02 = shuffle_epi8(sendMsg[2], shuffle[2]);
			block a03 = shuffle_epi8(sendMsg[3], shuffle[3]);
			block a04 = shuffle_epi8(sendMsg[4], shuffle[4]);
			block a05 = shuffle_epi8(sendMsg[5], shuffle[5]);
			block a06 = shuffle_epi8(sendMsg[6], shuffle[6]);
			block a07 = shuffle_epi8(sendMsg[7], shuffle[7]);
			block a08 = shuffle_epi8(sendMsg[8], shuffle[8]);
			block a09 = shuffle_epi8(sendMsg[9], shuffle[9]);
			block a10 = shuffle_epi8(sendMsg[10], shuffle[10]);
			block a11 = shuffle_epi8(sendMsg[11], shuffle[11]);
			block a12 = shuffle_epi8(sendMsg[12], shuffle[12]);
			block a13 = shuffle_epi8(sendMsg[13], shuffle[13]);
			block a14 = shuffle_epi8(sendMsg[14], shuffle[14]);
			block a15 = shuffle_epi8(sendMsg[15], shuffle[15]);

			s = sendMsg.data();
			m -= 16;
			for (u64 j = 0; j < 2; ++j)
			{
				s[0] = m[0] ^ delta;
				s[1] = m[1] ^ delta;
				s[2] = m[2] ^ delta;
				s[3] = m[3] ^ delta;
				s[4] = m[4] ^ delta;
				s[5] = m[5] ^ delta;
				s[6] = m[6] ^ delta;
				s[7] = m[7] ^ delta;

				oc::mAesFixedKey.hashBlocks<8>(s, s);


				s += 8;
				m += 8;
			}

			block b00 = shuffle_epi8(sendMsg[0], shuffle[0]);
			block b01 = shuffle_epi8(sendMsg[1], shuffle[1]);
			block b02 = shuffle_epi8(sendMsg[2], shuffle[2]);
			block b03 = shuffle_epi8(sendMsg[3], shuffle[3]);
			block b04 = shuffle_epi8(sendMsg[4], shuffle[4]);
			block b05 = shuffle_epi8(sendMsg[5], shuffle[5]);
			block b06 = shuffle_epi8(sendMsg[6], shuffle[6]);
			block b07 = shuffle_epi8(sendMsg[7], shuffle[7]);
			block b08 = shuffle_epi8(sendMsg[8], shuffle[8]);
			block b09 = shuffle_epi8(sendMsg[9], shuffle[9]);
			block b10 = shuffle_epi8(sendMsg[10], shuffle[10]);
			block b11 = shuffle_epi8(sendMsg[11], shuffle[11]);
			block b12 = shuffle_epi8(sendMsg[12], shuffle[12]);
			block b13 = shuffle_epi8(sendMsg[13], shuffle[13]);
			block b14 = shuffle_epi8(sendMsg[14], shuffle[14]);
			block b15 = shuffle_epi8(sendMsg[15], shuffle[15]);

			a00 = a00 ^ a08;
			a01 = a01 ^ a09;
			a02 = a02 ^ a10;
			a03 = a03 ^ a11;
			a04 = a04 ^ a12;
			a05 = a05 ^ a13;
			a06 = a06 ^ a14;
			a07 = a07 ^ a15;

			b00 = b00 ^ b08;
			b01 = b01 ^ b09;
			b02 = b02 ^ b10;
			b03 = b03 ^ b11;
			b04 = b04 ^ b12;
			b05 = b05 ^ b13;
			b06 = b06 ^ b14;
			b07 = b07 ^ b15;

			a00 = a00 ^ a04;
			a01 = a01 ^ a05;
			a02 = a02 ^ a06;
			a03 = a03 ^ a07;

			b00 = b00 ^ b04;
			b01 = b01 ^ b05;
			b02 = b02 ^ b06;
			b03 = b03 ^ b07;

			a00 = a00 ^ a02;
			a01 = a01 ^ a03;

			b00 = b00 ^ b02;
			b01 = b01 ^ b03;

			a00 = a00 ^ a01;
			b00 = b00 ^ b01;

			a00 = slli_epi16<7>(a00);
			b00 = slli_epi16<7>(b00);

			u16 ap = movemask_epi8(a00);
			u16 bp = movemask_epi8(b00);

			assert(aIter16 < (u16*)(A.data() + A.size()));
			assert(cIter16 < (u16*)(C.data() + C.size()));

			if (bIter8)
			{
				// triples

				// want
				// a0 + a1 = a
				// b0 + b1 = b
				// c0 + c1 = c
				// a * b = c

				// have
				// x0 * y0 = [z0]
				// x1 * y1 = [z1]

				// transform
				// a0 * b0 + a0 * b1 + a1 * b0 + a1 * b1 = c0 + c1
				// 
				//           a0 * b1 
				//                     a1 * b0
				//
				// a0 = x0
				// b0 = x1
				// a1 = y0
				// b1 = y1
				// c0 = x0 * x1 + z00 + z01
				// c1 = y0 * y1 + z10 + z11

				// y for other party...
				u16 x = ap ^ bp;
				u8 x0 = x;
				u8 x1 = x >> 8;
				u8 z0 = ap;
				u8 z1 = ap >> 8;

				*aIter8++ = x0;
				*bIter8++ = x1;
				*cIter8++ = (x0 & x1) ^ z0 ^ z1;
			}
			else
			{
				// ole
				*aIter16++ = ap ^ bp;
				*cIter16++ = ap;
			}
		}
	}




	void SilentOtTriple::init(u64 partyIdx, u64 n, SilentSecType mal, Type type)
	{
		mPartyIdx = partyIdx;
		if (type == Type::Triple)
			mN = 2 * roundUpTo(n, 128);
		else
			mN = roundUpTo(n, 128);;

		if (mPartyIdx)
		{
			mSendRecv.emplace<0>();
			std::get<0>(mSendRecv).configure(mN, 2, 1, mal);
		}
		else
		{
			mSendRecv.emplace<1>();
			std::get<1>(mSendRecv).configure(mN, 2, 1, mal);
		}
	}


	SilentOtTriple::BaseCount SilentOtTriple::baseCount(PRNG& prng)
	{
		SilentOtTriple::BaseCount r;
		if (mSendRecv.index())
		{
			r.mRecvChoice = std::get<1>(mSendRecv).sampleBaseChoiceBits(prng);
			auto count = std::get<1>(mSendRecv).baseCount();
			while(count.mBaseOtCount < r.mRecvChoice.size())
				r.mRecvChoice.pushBack(prng.getBit());
			mChoice = r.mRecvChoice;
		}
		else
		{
			r.mSendCount = std::get<0>(mSendRecv).baseCount().mBaseOtCount;
		}

		return r;
	}

	void SilentOtTriple::setBaseOts(span<const std::array<block, 2>> baseSendOts, span<const block> recvBaseOts)
	{
		if (mSendRecv.index())
		{
			std::get<1>(mSendRecv).setBaseCors(recvBaseOts, mChoice, {}, {});
		}
		else
		{
			std::get<0>(mSendRecv).setBaseCors(baseSendOts, {}, {});
		}
	}

	bool SilentOtTriple::hasBaseOts() const
	{
		if (mSendRecv.index())
		{
			return std::get<1>(mSendRecv).hasBaseOts();
		}
		else
		{
			return std::get<0>(mSendRecv).hasBaseOts();
		}
	}

	macoro::task<> SilentOtTriple::genBaseOts(PRNG& prng, Socket& sock, SilentBaseType baseType)
	{
		if (mSendRecv.index())
		{
			return std::get<1>(mSendRecv).genBaseCors(prng, sock, baseType == SilentBaseType::BaseExtend);
		}
		else
		{
			std::get<0>(mSendRecv).mDelta = prng.get<block>();
			return std::get<0>(mSendRecv).genBaseCors(std::get<0>(mSendRecv).mDelta, prng, sock, baseType == SilentBaseType::BaseExtend);
		}
	}

	macoro::task<> SilentOtTriple::expand(span<block> A, span<block> C, PRNG& prng, coproto::Socket& sock)
	{

		if (A.size() != divCeil(mN, 128))
			throw RTE_LOC;
		if (C.size() != divCeil(mN, 128))
			throw RTE_LOC;

		//bool debug = false;
		if (mSendRecv.index())
		{
			//return recvTask(std::get<1>(mSendRecv), mN, prng, sock, X, C);
			auto& mReceiver = std::get<1>(mSendRecv);
			if (mTimer)
				mReceiver.setTimer(*mTimer);
			mReceiver.mLpnMultType = mLpnMultType;
			//mReceiver.mGen.mEagerSend = false;

			//if (debug)
			//{
			//	auto baseSend = std::vector<std::array<block, 2>>{};
			//	baseSend.resize(mReceiver.baseCount().mBaseOtCount);
			//	co_await sock.recv(baseSend);

			//	{
			//		for (u64 i = 0; i < baseSend.size(); ++i)
			//		{
			//			if (mReceiver.gen().mBaseOTs(i) != baseSend[i][mReceiver.mGen.mBaseChoices(i)])
			//			{
			//				std::cout << "base OTs do not match. " << LOCATION << std::endl;
			//				std::terminate();
			//			}
			//		}
			//	}
			//}

			co_await mReceiver.silentReceiveInplace(mReceiver.mRequestNumOts, prng, sock, oc::ChoiceBitPacking::True);
			compressRecver(mReceiver.mA, C, A, {});
			setTimePoint("compressRecverDone");

		}
		else
		{
			auto& mSender = std::get<0>(mSendRecv);
			if (mTimer)
				mSender.setTimer(*mTimer);
			//if (debug)
			//{
			//	co_await sock.send(coproto::copy(mSender.mGen.mBaseOTs));
			//}
			//assert(mSender.mGen.hasBaseOts());
			mSender.mLpnMultType = mLpnMultType;
			//mSender.mGen.mEagerSend = false;

			co_await mSender.silentSendInplace(mSender.mDelta, mSender.mRequestNumOts, prng, sock);
			compressSender(*mSender.mDelta, mSender.mB, C, A, {});

			setTimePoint("compressSenderDone");
		}
	}

	macoro::task<> SilentOtTriple::expand(
		span<block> A, span<block> B, span<block> C,
		PRNG& prng, coproto::Socket& sock)
	{
		if (A.size() != divCeil(mN, 256))
			throw RTE_LOC;
		if (B.size() != divCeil(mN, 256))
			throw RTE_LOC;
		if (C.size() != divCeil(mN, 256))
			throw RTE_LOC;

		if (mSendRecv.index())
		{
			auto& mReceiver = std::get<1>(mSendRecv);
			if (mTimer)
				mReceiver.setTimer(*mTimer);
			mReceiver.mLpnMultType = mLpnMultType;
			//mReceiver.mGen.mEagerSend = false;

			co_await mReceiver.silentReceiveInplace(mReceiver.mRequestNumOts, prng, sock, oc::ChoiceBitPacking::True);
			compressRecver(mReceiver.mA, C, A, B);
			setTimePoint("compressRecverDone");
		}
		else
		{
			auto& mSender = std::get<0>(mSendRecv);
			if (mTimer)
				mSender.setTimer(*mTimer);
			mSender.mLpnMultType = mLpnMultType;
			//mSender.mGen.mEagerSend = false;

			co_await mSender.silentSendInplace(prng.get(), mSender.mRequestNumOts, prng, sock);
			compressSender(*mSender.mDelta, mSender.mB, C, A, B);
			setTimePoint("compressSenderDone");
		}
	}

}
#endif
