#include "libOTe/TwoChooseOne/BgciksOtExtReceiver.h"
#include "libOTe/TwoChooseOne/BgciksOtExtSender.h"
#include "libOTe/DPF/BgiGenerator.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Common/Log.h>
#include <bitpolymul2/bitpolymul.h>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <cryptoTools/Common/ThreadBarrier.h>
//#include <bits/stdc++.h> 

namespace osuCrypto
{
	bool gUseBgicksPprf(true);

	//using namespace std;

	// Utility function to do modular exponentiation. 
	// It returns (x^y) % p 
	int power(u64 x, u64 y, u64 p)
	{
		u64 res = 1;      // Initialize result 
		x = x % p;  // Update x if it is more than or 
					// equal to p 
		while (y > 0)
		{
			// If y is odd, multiply x with result 
			if (y & 1)
				res = (res * x) % p;

			// y must be even now 
			y = y >> 1; // y = y/2 
			x = (x * x) % p;
		}
		return res;
	}

	// This function is called for all k trials. It returns 
	// false if n is composite and returns false if n is 
	// probably prime. 
	// d is an odd number such that  d*2<sup>r</sup> = n-1 
	// for some r >= 1 
	bool millerTest(u64 d, PRNG& prng, u64 n)
	{
		// Pick a random number in [2..n-2] 
		// Corner cases make sure that n > 4 
		u64 a = 2 + prng.get<u64>() % (n - 4);

		// Compute a^d % n 
		u64 x = power(a, d, n);

		if (x == 1 || x == n - 1)
			return true;

		// Keep squaring x while one of the following doesn't 
		// happen 
		// (i)   d does not reach n-1 
		// (ii)  (x^2) % n is not 1 
		// (iii) (x^2) % n is not n-1 
		while (d != n - 1)
		{
			x = (x * x) % n;
			d *= 2;

			if (x == 1)     return false;
			if (x == n - 1) return true;
		}

		// Return composite 
		return false;
	}

	// It returns false if n is composite and returns true if n 
	// is probably prime.  k is an input parameter that determines 
	// accuracy level. Higher value of k indicates more accuracy. 
	bool isPrime(u64 n, PRNG & prng, u64 k = 20)
	{
		// Corner cases 
		if (n <= 1 || n == 4)  return false;
		if (n <= 3) return true;

		// Find r such that n = 2^d * r + 1 for some r >= 1 
		u64 d = n - 1;
		while (d % 2 == 0)
			d /= 2;

		// Iterate given nber of 'k' times 
		for (u64 i = 0; i < k; i++)
			if (!millerTest(d, prng, n))
				return false;

		return true;
	}


	u64 nextPrime(u64 n)
	{
		PRNG prng(ZeroBlock);

		while (isPrime(n, prng) == false)
			++n;
		return n;
	}


	//// The number of DPF points that will be used.
	//u64 numPartitions = 8;

	//// defines n' = nScaler * n
	//u64 nScaler = 4;

	u64 getPartitions(u64 scaler, u64 p, u64 secParam);

	void BgciksOtExtReceiver::genBase(
		u64 n,
		Channel & chl,
		PRNG & prng,
		u64 scaler,
		u64 secParam,
		BgciksBaseType basetype,
		u64 threads)
	{
		setTimePoint("recver.gen.start");
		configure(n, scaler, secParam);

		if (gUseBgicksPprf)
		{
			auto count = mGen.baseOtCount();
			std::vector<block> msg(count);
			BitVector choice(count);
			choice.randomize(prng);

			switch (basetype)
			{
			case osuCrypto::BgciksBaseType::None:
				break;
			case osuCrypto::BgciksBaseType::Base:
			{
				NaorPinkas base;
				base.receive(choice, msg, prng, chl, threads);
				setTimePoint("recver.gen.baseOT");
				break;
			}
			case osuCrypto::BgciksBaseType::BaseExtend:
			{
				NaorPinkas base;
				std::array<std::array<block, 2>, 128> baseMsg;
				prng.get(baseMsg.data(), baseMsg.size());
				base.send(baseMsg, prng, chl, threads);
				setTimePoint("recver.gen.baseOT");
				IknpOtExtReceiver iknp;
				iknp.setBaseOts(baseMsg);
				iknp.receive(choice, msg, prng, chl);
				setTimePoint("recver.gen.baseExtension");
				break;
			}
			case osuCrypto::BgciksBaseType::Extend:
			{
				std::array<std::array<block, 2>, 128> baseMsg;
				IknpOtExtReceiver iknp;
				iknp.setBaseOts(baseMsg);
				iknp.receive(choice, msg, prng, chl);
				setTimePoint("recver.gen.baseExtension");
				break;
			}
			default:
				break;
			}

			TODO("comment this out and fix bug");
			memset(msg.data(), 0, msg.size() * 16);

			mGen.setBase(msg, choice);
			mGen.getTransposedPoints(mS);
			for (u64 i = 0; i < mS.size(); ++i)
			{
				if (mS[i] >= mN2)
				{
					//auto s = mS.size();
					mS.resize(i);

					//std::cout << "resiz"
				}
				//throw std::runtime_error("known issue, (fixable, ask peter). " LOCATION);
			}
		}
		else
		{

			auto numPartitions = mS.size();
			auto groupSize = 8;
			auto depth = log2ceil((mSizePer + groupSize - 1) / groupSize) + 1;

			std::vector<std::vector<block>>
				k1(numPartitions), g1(numPartitions),
				k2(numPartitions), g2(numPartitions);

			PRNG prng2(toBlock(n));
			mS.resize(numPartitions);
			std::vector<u64> S(numPartitions);
			mDelta = AllOneBlock;// prng2.get();


			for (u64 i = 0; i < numPartitions; ++i)
			{
				do
				{

					S[i] = prng2.get<u64>() % mSizePer;

					mS[i] = S[i] * numPartitions + i;

				} while (mS[i] >= mN2);

				k1[i].resize(depth);
				k2[i].resize(depth);
				g1[i].resize(groupSize);
				g2[i].resize(groupSize);

				BgiGenerator::keyGen(S[i], mDelta, toBlock(i), k1[i], g1[i], k2[i], g2[i]);
			}

			mGenBgi.init(k2, g2);

		}


		setTimePoint("recver.gen.done");

	}

	void BgciksOtExtReceiver::configure(const osuCrypto::u64 & n, const osuCrypto::u64 & scaler, const osuCrypto::u64 & secParam)
	{

		mP = nextPrime(n);
		mN = roundUpTo(mP, 128);
		mScaler = scaler;
		mN2 = scaler * mN;

		auto numPartitions = getPartitions(scaler, mP, secParam);
		mS.resize(numPartitions);
		mSizePer = (mN2 + numPartitions - 1) / numPartitions;


		if (gUseBgicksPprf)
		{
			//if (mTimer)
			//	mGen.setTimer(getTimer());

			mGen.configure(mSizePer, mS.size());
		}
	}

	u64 BgciksOtExtReceiver::baseOtCount()
	{

		if (gUseBgicksPprf)
			return mGen.baseOtCount();
		return 0;
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


	Matrix<block> expandTranspose(BgiEvaluator::MultiKey & gen, u64 n)
	{
		Matrix<block> rT(128, n / 128, AllocType::Uninitialized);

		std::array<block, 128> tpBuffer;

		if (n % 128)
			throw RTE_LOC;
		if (gen.mNumKeys > tpBuffer.size())
			throw std::runtime_error("not implemented, generalize the following loop to enable. " LOCATION);

		u64 curBlock = 0;

		for (u64 i = 0, j = 0; i < n;)
		{
			auto blocks = gen.yeild();
			auto blockCount = std::min<u64>(n - i, blocks.size());

			auto min2 = std::min<u64>(tpBuffer.size() - curBlock, blockCount);

			memcpy(tpBuffer.data() + curBlock, blocks.data(), min2 * sizeof(block));
			curBlock += min2;

			if (curBlock == tpBuffer.size())
			{
				sse_transpose128(tpBuffer);
				curBlock = 0;

				for (u64 k = 0; k < tpBuffer.size(); ++k)
				{
					rT(k, j) = tpBuffer[k];
				}

				++j;

				if (min2 != blockCount)
				{
					curBlock = blockCount - min2;
					memcpy(tpBuffer.data(), blocks.data() + min2, curBlock * sizeof(block));
				}
			}


			i += blockCount;
		}

		return rT;
	}

	void BgciksOtExtReceiver::receive(
		span<block> messages,
		BitVector & choices,
		PRNG & prng,
		Channel & chl)
	{
		receive(messages, choices, prng, { &chl,1 });
	}
	void BgciksOtExtReceiver::receive(
		span<block> messages,
		BitVector & choices,
		PRNG & prng,
		span<Channel> chls)
	{
		setTimePoint("recver.expand.start");

		// column major matric. mN2 columns and 1 row of 128 bits (128 bit rows)
		//std::vector<block> r(mN2);
		Matrix<block> rT;

		if (gUseBgicksPprf)
		{
			rT.resize(128, mN2 / 128, AllocType::Uninitialized);
			mGen.expand(chls, prng, rT, true);
			setTimePoint("sender.expand.pprf_transpose");


			RandomOracle ro(16);
			ro.Update(rT.data(), rT.size());
			block b;
			ro.Final(b);

			//std::cout << "test " << b << std::endl;
		}
		else
		{
			rT = expandTranspose(mGenBgi, mN2);
			setTimePoint("recver.expand.dpf_transpose");
		}

		//if(0)
		//{
		//	int temp__;
		//	Matrix<block> rT2(rT.rows(), rT.cols()), r2(mN2, 1);
		//	chls[0].recv(temp__);
		//	chls[0].recv(rT2.data(), rT2.size());
		//	for (u64 i = 0; i < rT.size(); ++i)
		//		rT2(i) = rT2(i) ^ rT(i);
		//	
		//	sse_transpose(MatrixView<block>(rT2), MatrixView<block>(r2));

		//	//for (u64 j = 0; j < rT.rows(); ++j)
		//	//{
		//	//	std::cout << "r[" << j << "] ";
		//	//	for (u64 i = 0; i < rT.cols(); ++i)
		//	//		std::cout << " "<< (rT2(i, j));
		//	//	std::cout << std::endl;
		//	//}

		//	std::cout << mGen.mDomain << " " << mGen.mPntCount <<
		//		" " << rT.rows() << " " << rT.cols() << std::endl;
		//	for (u64 i = 0; i < rT2.cols(); ++i)
		//	{
		//		for (u64 j = 0; j < 128; ++j)
		//		{

		//			//if (cmd.isSet("v"))
		//			std::cout << "r[" << i << "][" << j << "] " << (rT2(j, i)) << " ~ " << rT(j, i) << std::endl << Color::Default;
		//		}
		//	}

		//	std::cout << std::endl;
		//	for (u64 i = 0; i < mN2; ++i)
		//		std::cout << "w[" << i << "] " << r2(i) << std::endl;
		//}

		//auto n = mN2;
		//auto& gen = mGen;
		//{
		//    std::array<block, 128> tpBuffer;
		//    if (n % 128)
		//        throw RTE_LOC;
		//    if (gen.mNumKeys > tpBuffer.size())
		//        throw std::runtime_error("not implemented, generalize the following loop to enable. " LOCATION);

		//    Matrix<block> rT(128, n / 128, AllocType::Uninitialized);
		//    u64 curBlock = 0;

		//    for (u64 i = 0, j = 0; i < n;)
		//    {
		//        auto blocks = gen.yeild();
		//        auto blockCount = std::min<u64>(n - i, blocks.size());

		//        auto min2 = std::min<u64>(tpBuffer.size() - curBlock, blockCount);

		//        memcpy(tpBuffer.data() + curBlock, blocks.data(), min2 * sizeof(block));
		//        curBlock += min2;

		//        if (curBlock == tpBuffer.size())
		//        {
		//            sse_transpose128(tpBuffer);
		//            curBlock = 0;

		//            for (u64 k = 0; k < tpBuffer.size(); ++k)
		//            {
		//                rT(k, j) = tpBuffer[k];
		//            }

		//            ++j;

		//            if (min2 != blockCount)
		//            {
		//                curBlock = blockCount - min2;
		//                memcpy(tpBuffer.data(), blocks.data() + min2, curBlock * sizeof(block));
		//            }
		//        }


		//        i += blockCount;
		//    }
		//}



		//Matrix<block> rT2(128, mN2 / 128, AllocType::Uninitialized);
		//sse_transpose(r, rT2);

		//for (u64 x = 0; x < rT.rows(); ++x)
		//{
		//    for (u64 y = 0; y < rT.cols(); ++y)
		//    {
		//        std::cout << rT(x, y) << " " << rT2(x, y) << std::endl;
		//    }
		//    std::cout << std::endl;
		//}

		//setTimePoint("recver.expand.transpose");


		auto type = MultType::QuasiCyclic;

		switch (type)
		{
		case osuCrypto::MultType::Naive:
			randMulNaive(rT, messages);
			break;
		case osuCrypto::MultType::QuasiCyclic:
			randMulQuasiCyclic(rT, messages, choices, chls.size());
			break;
		default:
			break;
		}

		//auto dest = mul(rMtx, mtx);
		//auto dest2 = convert(messages);
		//for (u64 i = 0; i < dest.rows(); ++i)
		//{
		//    std::cout << i << ":";

		//    for (u64 j = 0; j < dest.cols(); ++j)
		//    {
		//        if (dest(i, j) != dest2(j, i))
		//            std::cout << Color::Red;

		//        std::cout << ", " << int(dest(i, j)) << " " << int(dest2(j, i)) << Color::Default;
		//    }

		//    std::cout << std::endl;
		//}
		//std::cout << std::endl;

	}


	void BgciksOtExtReceiver::randMulNaive(Matrix<block> & rT, span<block> & messages)
	{
		std::vector<block> mtxColumn(rT.cols());
		PRNG pubPrng(ZeroBlock);

		for (u64 i = 0; i < messages.size(); ++i)
		{
			block& m = messages[i];
			BitIterator iter((u8*)& m, 0);
			mulRand(pubPrng, mtxColumn, rT, iter);
		}
		setTimePoint("recver.expand.mul");
	}

	void BgciksOtExtReceiver::randMulQuasiCyclic(Matrix<block> & rT, span<block> & messages, BitVector & choices, u64 threads)
	{
		auto nBlocks = mN / 128;
		auto nBytes = mN / 8;
		auto n2Blocks = mN2 / 128;
		auto n64 = i64(nBlocks * 2);

		const u64 rows(128);
		if (rT.rows() != rows)
			throw RTE_LOC;
		if (rT.cols() != n2Blocks)
			throw RTE_LOC;

		std::vector<block> a(nBlocks);
		using TSpan = std::vector<block>;
		static_assert(std::is_convertible<
			TSpan,
			span<typename TSpan::value_type>
		>::value, "hmm");
		auto a64 = spanCast<u64>(a);

		//std::cout << (a64.data()) << " " << (a.data()) << std::endl;
		assert(a64.size() == n64 && a64.data() == (u64*)a.data());
		//u64 * a64ptr = (u64*)a.data();
		bpm::FFTPoly aPoly;

		BitVector sb(mN2);
		for (u64 i = 0; i < mS.size(); ++i)
		{
			sb[mS[i]] = 1;
		}
		std::vector<bpm::FFTPoly> c(rows);


		std::unique_ptr<ThreadBarrier[]> brs(new ThreadBarrier[mScaler]);
		for (u64 i = 0; i < mScaler; ++i)
			brs[i].reset(threads);

		auto routine = [&](u64 index)
		{
			auto j = 0;
			bpm::FFTPoly sPoly;
			bpm::FFTPoly bPoly;

			//std::vector<block> a(nBlocks);
			//u64 * a64ptr = (u64*)a.data();
			//bpm::FFTPoly aPoly;

			for (u64 s = 1; s < mScaler; ++s)
			{

				if (index == 0)
				{
					PRNG pubPrng(toBlock(s));
					pubPrng.get(a.data(), a.size());
					aPoly.encode(a64);
				}

				brs[j++].decrementWait();

				for (u64 i = index; i < rows; i += threads)
				{
					auto b64 = spanCast<u64>(rT[i]).subspan(s * n64, n64);
					u64* b64ptr = (u64*)(rT[i].data() + s * nBlocks);
					assert(b64ptr == b64.data());

					bPoly.encode(b64);

					if (s > 1)
					{
						bPoly.multEq(aPoly);
						c[i].addEq(bPoly);
					}
					else
					{
						c[i].mult(aPoly, bPoly);
					}
				}

				if (index == 0)
				{
					auto s64 = sb.getSpan<u64>().subspan(s * n64, n64);
					u64* s64ptr = (u64*)(sb.data() + s * nBytes);
					assert(s64.data() == s64ptr);

					bPoly.encode(s64);

					if (s > 1)
					{
						bPoly.multEq(aPoly);
						sPoly.addEq(bPoly);
					}
					else
					{
						sPoly.mult(aPoly, bPoly);
					}

				}

			}


			if (index == 0)
				setTimePoint("recver.expand.mul");


			//Matrix<block>cModP1(128, nBlocks, AllocType::Uninitialized);
			//std::vector<u64> temp(c[index].mPoly.size() + 2);
			//bpm::FFTPoly::DecodeCache cache;

			//u64 * t64Ptr = (u64*)temp.data();
			//auto t128Ptr = (block*)temp.data();
			//for (u64 i = index; i < rows; i += threads)
			//{
			//	// decode c[i] and store it at t64Ptr
			//	c[i].decode({ t64Ptr, 2 * n64 }, cache, true);

			//	u64* b64ptr = (u64*)rT[i].data();
			//	for (u64 j = 0; j < n64; ++j)
			//		t64Ptr[j] ^= b64ptr[j];

			//	// reduce s[i] mod (x^p - 1) and store it at cModP1[i]
			//	modp(cModP1[i], { t128Ptr, n64 }, mP);
			//	//memcpy(cModP1[i].data(), t64Ptr, nBlocks * sizeof(block));
			//}


			Matrix<block>cModP1(128, nBlocks, AllocType::Uninitialized);
			std::vector<u64> temp64(n64 * 2);
			bpm::FFTPoly::DecodeCache cache;

			auto temp128 = spanCast<block>(temp64);

			//auto t128Ptr = (block*)temp.data();
			for (u64 i = index; i < rows; i += threads)
			{
				// decode c[i] and store it at t64Ptr
				c[i].decode(temp64, cache, true);

				//u64* b64ptr = (u64*)rT[i].data();
				auto b128 = rT[i].subspan(0, nBlocks);
				for (u64 j = 0; j < nBlocks; ++j)
					temp128[j] = temp128[j] ^ b128[j];

				// reduce s[i] mod (x^p - 1) and store it at cModP1[i]
				modp(cModP1[i], temp128, mP);
				//memcpy(cModP1[i].data(), t64Ptr, nBlocks * sizeof(block));
			}

			brs[j++].decrementWait();

			if (index == 0)
			{

				choices.resize(0);
				choices.resize(mN);

				span<block> c128 = choices.getSpan<block>();
				span<u64> c64 = choices.getSpan<u64>();
				assert(c64.size() == n64);
				assert(c128.size() == nBlocks);

				//sPoly.decode({ temp64.data(), 2 * n64 }, cache, true);

				sPoly.decode(temp64, cache, true);

				auto b128 = sb.getSpan<block>();
				for (u64 j = 0; j < nBlocks; ++j)
					temp128[j] = temp128[j] ^ b128[j];

				modp(c128, temp128, mP);
				//memcpy((block*)choices.data(), t64Ptr, nBlocks * sizeof(block));
			}



			//brs[j++].decrementWait();


			//if (index == 0)
			//{
			//	choices.resize(0);
			//	choices.resize(mN);
			//	span<block> b128 = choices.getSpan<block>();
			//	span<u64> b64 = choices.getSpan<u64>();

			//	sPoly.decode(temp64, cache, true);

			//	for (u64 j = 0; j < n64; ++j)
			//		temp64[j] ^= b64[j];

			//	//for (u64 j = 0; j < nBlocks; ++j)
			//	//	temp128[j] = temp128[j] ^ b128[j];

			//	modp(b128, temp128, mP);
			//}

			if (index == 0)
				setTimePoint("recver.expand.decodeReduce");

			//MatrixView<block> view(messages.begin(), messages.end(), 1);
			//sse_transpose(cModP1, view);
	//#define NO_HASH
			std::array<block, 8> hashBuffer;
			//std::array<block, 128> tpBuffer;
			auto end = messages.size() / 128;
			for (u64 i = index; i < end; i += threads)
			{
				u64 j = i * 128;
				auto& tpBuffer = *(std::array<block, 128>*)(messages.data() + j);

				for (u64 k = 0; k < 128; ++k)
					tpBuffer[k] = cModP1(k, i);

				sse_transpose128(tpBuffer);

#ifndef NO_HASH
				for (u64 k = 0; k < 128; k += 8)
				{
					mAesFixedKey.ecbEncBlocks(tpBuffer.data() + k, hashBuffer.size(), hashBuffer.data());

					tpBuffer[k + 0] = tpBuffer[k + 0] ^ hashBuffer[0];
					tpBuffer[k + 1] = tpBuffer[k + 1] ^ hashBuffer[1];
					tpBuffer[k + 2] = tpBuffer[k + 2] ^ hashBuffer[2];
					tpBuffer[k + 3] = tpBuffer[k + 3] ^ hashBuffer[3];
					tpBuffer[k + 4] = tpBuffer[k + 4] ^ hashBuffer[4];
					tpBuffer[k + 5] = tpBuffer[k + 5] ^ hashBuffer[5];
					tpBuffer[k + 6] = tpBuffer[k + 6] ^ hashBuffer[6];
					tpBuffer[k + 7] = tpBuffer[k + 7] ^ hashBuffer[7];
				}
#endif
			}

			auto rem = messages.size() % 128;
			if (rem && index == 0)
			{
				std::array<block, 128> tpBuffer;

				for (u64 j = 0; j < tpBuffer.size(); ++j)
					tpBuffer[j] = cModP1(j, end);

				sse_transpose128(tpBuffer);

#ifndef NO_HASH
				for (u64 k = 0; k < rem; ++k)
				{
					tpBuffer[k] = tpBuffer[k] ^ mAesFixedKey.ecbEncBlock(tpBuffer[k]);
				}
#endif

				memcpy(messages.data() + end * 128, tpBuffer.data(), rem * sizeof(block));
			}

			if (index == 0)
				setTimePoint("recver.expand.transposeXor");

		};


		std::vector<std::thread> thrds(threads - 1);
		for (u64 i = 0; i < thrds.size(); ++i)
			thrds[i] = std::thread(routine, i);

		routine(thrds.size());

		for (u64 i = 0; i < thrds.size(); ++i)
			thrds[i].join();
	}


}
//Matrix<u8> convert(span<block> b)
//{
//    Matrix<u8> ret(b.size(), 128);
//    BitIterator iter((u8*)b.data(), 0);

//    for (u64 i = 0; i < ret.size(); ++i)
//    {
//        ret(i) = *iter++;
//    }
//    return ret;
//}


//Matrix<u8> transpose(const Matrix<u8>& v)
//{
//    Matrix<u8> ret(v.cols(), v.rows());

//    for (u64 i = 0; i < v.rows(); ++i)
//    {
//        for (u64 j = 0; j < v.cols(); ++j)
//        {
//            ret(j, i) = v(i, j);
//        }
//    }
//    return ret;
//}


//void convertCol(Matrix<u8>& dest, u64 j, span<block> b)
//{
//    BitIterator iter((u8*)b.data(), 0);
//    for (u64 i = 0; i < dest.rows(); ++i)
//    {
//        dest(i, j) = *iter++;
//    }
//}



//Matrix<u8> mul(const Matrix<u8>& l, const Matrix<u8>& r)
//{
//    if (l.cols() != r.rows())
//        throw RTE_LOC;

//    Matrix<u8> ret(l.rows(), r.cols());

//    for (u64 i = 0; i < ret.rows(); ++i)
//    {
//        for (u64 j = 0; j < ret.cols(); ++j)
//        {
//            auto& x = ret(i, j);
//            x = 0;
//            for (u64 k = 0; k < r.rows(); ++k)
//            {
//                x ^= l(i, k) & r(k, j);
//            }
//        }

//    }
//    return ret;
//}
