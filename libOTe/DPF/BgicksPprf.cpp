#include "BgicksPprf.h"

#include <cryptoTools/Common/Log.h>
#include <libOTe/Tools/Tools.h>
namespace osuCrypto
{

	//#define DEBUG_PRINT_PPRF

	BgicksMultiPprfSender::BgicksMultiPprfSender(u64 domainSize, u64 pointCount)
	{
		configure(domainSize, pointCount);
	}
	void BgicksMultiPprfSender::configure(u64 domainSize, u64 pointCount)
	{
		mDomain = domainSize;
		mDepth = log2ceil(mDomain);
		mPntCount = pointCount;
		mPntCount8 = roundUpTo(pointCount, 8);

		mBaseOTs.resize(0, 0);
	}

	void BgicksMultiPprfReceiver::configure(u64 domainSize, u64 pointCount)
	{
		mDomain = domainSize;
		mDepth = log2ceil(mDomain);
		mPntCount = pointCount;
		mPntCount8 = roundUpTo(pointCount, 8);

		mBaseOTs.resize(0, 0);
	}

	u64 BgicksMultiPprfSender::baseOtCount() const
	{
		return mDepth * mPntCount;
	}
	u64 BgicksMultiPprfReceiver::baseOtCount() const
	{
		return mDepth * mPntCount;
	}

	bool BgicksMultiPprfSender::hasBaseOts() const
	{
		return mBaseOTs.size();
	}
	bool BgicksMultiPprfReceiver::hasBaseOts() const
	{
		return mBaseOTs.size();
	}
	void BgicksMultiPprfSender::setBase(span<std::array<block, 2>> baseMessages)
	{
		if (baseOtCount() != baseMessages.size())
			throw RTE_LOC;

		mBaseOTs.resize(mPntCount, mDepth);
		memcpy(mBaseOTs.data(), baseMessages.data(), baseMessages.size() * sizeof(block));
	}

	void BgicksMultiPprfReceiver::setBase(span<block> baseMessages, BitVector & choices)
	{
		if (baseOtCount() != baseMessages.size())
			throw RTE_LOC;

		if (baseOtCount() != choices.size())
			throw RTE_LOC;

		mBaseOTs.resize(mPntCount, mDepth);
		memcpy(mBaseOTs.data(), baseMessages.data(), baseMessages.size() * sizeof(block));

		mBaseChoices.resize(mPntCount, mDepth);
		for (u64 i = 0; i < mBaseChoices.size(); ++i)
		{
			mBaseChoices(i) = choices[i];
		}
	}


	//std::map<u64, std::array<block, 128>> blocks;

	void copyOut(bool transpose, span<std::array<block, 8>> lvl, MatrixView<block> output, u64 min, u64 g)
	{

		if (transpose)
		{

			if (lvl.size() >= 16)
			{
				auto sec = g / 8;
				auto size = lvl.size() / 16;
				auto begin = sec * size;
				auto end = std::min<u64>(begin + size, output.cols());

				for (u64 i = begin, k = 0; i < end; ++i, ++k)
				{
					if (lvl.size() < (k + 1) * 16)
						throw RTE_LOC;

					auto & io = *(std::array<block, 128>*)(&lvl[k * 16]);

					//if (blocks.find(sec) != blocks.end())
					//{
					//	std::array<block, 128> io2 = blocks[sec];
					//	for (u64 j = 0; j < 128; ++j)
					//		std::cout << "Tin["<< sec<<"][" << j << "]" << io[j] << " " << io2[j] << " " << (io[j] ^ io2[j])<< std::endl;
					//}
					//
					//blocks[sec] = io;

					sse_transpose128(io);


					//for (u64 j = 0; j < 128; ++j)
					//	std::cout << "Tou[" << sec << "][" << j << "]" << io[j] << std::endl;

					for (u64 j = 0; j < 128; ++j)
						output(j, i) = io[j];
				}

				//memset(lvl.data(), 0, lvl.size() * sizeof(block) * 8);
			}
			else
				throw RTE_LOC;
		}
		else
		{
			if (min == 8)
			{

				for (u64 i = 0; i < output.rows(); ++i)
				{
					auto oi = output[i].subspan(g, 8);
					auto& ii = lvl[i];
					oi[0] = ii[0];
					oi[1] = ii[1];
					oi[2] = ii[2];
					oi[3] = ii[3];
					oi[4] = ii[4];
					oi[5] = ii[5];
					oi[6] = ii[6];
					oi[7] = ii[7];
				}
			}
			else
			{
				for (u64 i = 0; i < output.rows(); ++i)
				{
					auto oi = output[i].subspan(g, min);
					auto& ii = lvl[i];
					for (u64 j = 0; j < min; ++j)
						oi[j] = ii[j];
				}
			}
		}
	}

	void BgicksMultiPprfSender::expand(
		Channel& chl,
		block value,
		PRNG& prng,
		MatrixView<block> output,
		bool transpose)
	{
		expand({ &chl, 1 }, value, prng, output, transpose);
	}

	void BgicksMultiPprfSender::expand(
		span<Channel> chls,
		block value,
		PRNG& prng,
		MatrixView<block> output,
		bool transpose)
	{
		setValue(value);
		setTimePoint("pprf.send.start");


		if (transpose)
		{
			if (output.rows() != 128)
				throw RTE_LOC;

			if (output.cols() > (mDomain * mPntCount + 127) / 128)
				throw RTE_LOC;

			if (mPntCount & 7)
				throw RTE_LOC;
		}
		else
		{
			if (output.rows() != mDomain)
				throw RTE_LOC;

			if (output.cols() != mPntCount)
				throw RTE_LOC;
		}

		block seed = prng.get();

		auto routine = [&](u64 index)
		{

			auto& chl = chls[index];

			std::array<std::vector<std::array<block, 8>>, 2> sums;
			std::vector<std::array<block, 8>> tree((1ull << (mDepth + 1)));

			auto getLevel = [&](u64 i)
			{
				auto size = (1ull << i);
				auto offset = (size - 1);

				auto b = tree.begin() + offset;
				auto e = b + size;
				return span<std::array<block, 8>>(b, e);
			};

			auto print = [](span<block> b)
			{
				std::stringstream ss;
				if (b.size())
					ss << b[0];
				for (u64 i = 1; i < b.size(); ++i)
				{
					ss << ", " << b[i];
				}
				return ss.str();
			};

			std::array<AES, 2> aes;
			aes[0].setKey(toBlock(3242342));
			aes[1].setKey(toBlock(8993849));


			for (u64 g = index * 8; g < mPntCount; g += 8 * chls.size())
			{

				//lout << "send[" << index << "][" << g << "]" << std::endl;
				auto min = std::min<u64>(8, mPntCount - g);
				PRNG prng(seed ^ toBlock(g));
				prng.get(getLevel(0));

				sums[0].resize(mDepth);
				sums[1].resize(mDepth);

				for (u64 d = 0; d < mDepth; ++d)
				{
					auto level0 = getLevel(d);
					auto level1 = getLevel(d + 1);

					auto width = level1.size();

					for (u64 i = 0; i < width; ++i)
					{
						u8 keep = i & 1;
						auto i0 = i >> 1;
						auto& a = aes[keep];
						auto& sub = level0[i0];
						auto& sub1 = level1[i];
						auto& sum = sums[keep][d];


						// H(x) = AES(k[keep], x) + x;
						a.ecbEncBlocks(sub.data(), 8, sub1.data());
						sub1[0] = sub1[0] ^ sub[0];
						sub1[1] = sub1[1] ^ sub[1];
						sub1[2] = sub1[2] ^ sub[2];
						sub1[3] = sub1[3] ^ sub[3];
						sub1[4] = sub1[4] ^ sub[4];
						sub1[5] = sub1[5] ^ sub[5];
						sub1[6] = sub1[6] ^ sub[6];
						sub1[7] = sub1[7] ^ sub[7];

						//if (d == 1 && i == 0)
						//{
						//    std::cout << "r[" << (d) << "] = " << sub[2] << " -> r[" << (d + 1) << "] = " << sub1[2] << std::endl;
						//}

						// sum += H(x)
						sum[0] = sum[0] ^ sub1[0];
						sum[1] = sum[1] ^ sub1[1];
						sum[2] = sum[2] ^ sub1[2];
						sum[3] = sum[3] ^ sub1[3];
						sum[4] = sum[4] ^ sub1[4];
						sum[5] = sum[5] ^ sub1[5];
						sum[6] = sum[6] ^ sub1[6];
						sum[7] = sum[7] ^ sub1[7];

					}
					//std::cout << "s lvl[" << (d + 1) << "] " << print(getLevel(d + 1)) << std::endl;
					//std::cout << "sum0 [" << (d + 1) << "] " << print(sums[0][d]) << std::endl;
					//std::cout << "sum1 [" << (d + 1) << "] " << print(sums[1][d]) << std::endl;
				}

#ifdef DEBUG_PRINT_PPRF
				chl.send(tree);
#endif

				for (u64 d = 0; d < mDepth - 1; ++d)
				{
					//auto idx = d * mPntCount + g;
					for (u64 j = 0; j < min; ++j)
					{
#ifdef DEBUG_PRINT_PPRF
						std::cout << "c[" << g + j << "][" << d << "][0] " << sums[0][d][j] << " " << mBaseOTs[g + j][d][0] << std::endl;;
						std::cout << "c[" << g + j << "][" << d << "][1] " << sums[1][d][j] << " " << mBaseOTs[g + j][d][1] << std::endl;;
#endif													  
						sums[0][d][j] = sums[0][d][j] ^ mBaseOTs[g + j][d][0];
						sums[1][d][j] = sums[1][d][j] ^ mBaseOTs[g + j][d][1];
					}
				}
				//setTimePoint("pprf.send.expand-" + std::to_string(g));


				auto d = mDepth - 1;
				std::vector<std::array<block, 4>> lastOts(min);
				for (u64 j = 0; j < min; ++j)
				{
					//auto idx = d * mPntCount + j + g;
					//u8 bit = permute[idx];

					lastOts[j][0] = sums[0][d][j];
					lastOts[j][1] = sums[1][d][j] ^ mValue;
					lastOts[j][2] = sums[1][d][j];
					lastOts[j][3] = sums[0][d][j] ^ mValue;

					std::array<block, 4> masks, maskIn;

					maskIn[0] = mBaseOTs[g + j][d][0];
					maskIn[1] = mBaseOTs[g + j][d][0] ^ AllOneBlock;
					maskIn[2] = mBaseOTs[g + j][d][1];
					maskIn[3] = mBaseOTs[g + j][d][1] ^ AllOneBlock;

					mAesFixedKey.ecbEncFourBlocks(maskIn.data(), masks.data());
					masks[0] = masks[0] ^ maskIn[0];
					masks[1] = masks[1] ^ maskIn[1];
					masks[2] = masks[2] ^ maskIn[2];
					masks[3] = masks[3] ^ maskIn[3];

					//std::cout << "sum[" << j << "][0] " << lastOts[j][0] << " " << lastOts[j][1] << std::endl;
					//std::cout << "sum[" << j << "][1] " << lastOts[j][2] << " " << lastOts[j][3] << std::endl;
#ifdef DEBUG_PRINT_PPRF
					std::cout << "c[" << g + j << "][" << d << "][0] " << sums[0][d][j] << " " << mBaseOTs[g + j][d][0] << std::endl;;
					std::cout << "c[" << g + j << "][" << d << "][1] " << sums[1][d][j] << " " << mBaseOTs[g + j][d][1] << std::endl;;
#endif							
					lastOts[j][0] = lastOts[j][0] ^ masks[0];
					lastOts[j][1] = lastOts[j][1] ^ masks[1];
					lastOts[j][2] = lastOts[j][2] ^ masks[2];
					lastOts[j][3] = lastOts[j][3] ^ masks[3];
				}

				sums[0].resize(mDepth - 1);
				sums[1].resize(mDepth - 1);

				//int temp;
				//chl.send(g);
				chl.asyncSend(std::move(sums[0]));
				chl.asyncSend(std::move(sums[1]));
				//chl.asyncSend(temp);
				chl.asyncSend(std::move(lastOts));


				auto lvl = getLevel(mDepth);
				copyOut(transpose, lvl, output, min, g);

				//setTimePoint("pprf.send.copyOut-" + std::to_string(g));

			}
		};


		std::vector<std::thread> thrds(chls.size() - 1);
		for (u64 i = 0; i < thrds.size(); ++i)
			thrds[i] = std::thread(routine, i);
			//routine(i);


		routine(thrds.size());

		for (u64 i = 0; i < thrds.size(); ++i)
			thrds[i].join();
	}

	void BgicksMultiPprfSender::setValue(block value)
	{
		mValue = value;
	}

	void BgicksMultiPprfReceiver::getPoints(span<u64> points)
	{
		memset(points.data(), 0, points.size() * sizeof(u64));
		for (u64 i = 0; i < mDepth; ++i)
		{
			auto shift = mDepth - i - 1;
			for (u64 j = 0; j < mPntCount; ++j)
			{
				//auto idx = i * mPntCount + j;
				points[j] |= u64(1 ^ mBaseChoices[j][i]) << shift;
			}
		}
	}

	void BgicksMultiPprfReceiver::getTransposedPoints(span<u64> points)
	{
		getPoints(points);

		for (u64 i = 0; i < points.size(); ++i)
		{
			auto j = i / 8;
			auto k = i % 8;
			auto base = 8 * (1ull << mDepth) * j;
			points[i] = points[i] * 8 + base + k;
		}
	}

	void BgicksMultiPprfReceiver::expand(Channel& chl, PRNG& prng, MatrixView<block> output, bool transpose)
	{
		expand({ &chl, 1 }, prng, output, transpose);
	}

	void BgicksMultiPprfReceiver::expand(span<Channel> chls, PRNG& prng, MatrixView<block> output, bool transpose)
	{

		setTimePoint("pprf.recv.start");

		//lout << " d " << mDomain << " p " << mPntCount << " do " << mDepth << std::endl;

		if (transpose)
		{
			if (output.rows() != 128)
				throw RTE_LOC;

			if (output.cols() > (mDomain * mPntCount + 127) / 128)
				throw RTE_LOC;

			if (mPntCount & 7)
				throw RTE_LOC;
		}
		else
		{
			if (output.rows() != mDomain)
				throw RTE_LOC;

			if (output.cols() != mPntCount)
				throw RTE_LOC;
		}


		std::vector<u64> points(mPntCount);
		getPoints(points);
		//for (u64 j = 0; j < mPntCount; ++j)
		//    std::cout << "point[" << j << "] " << points[j] << std::endl;

		std::array<AES, 2> aes;
		aes[0].setKey(toBlock(3242342));
		aes[1].setKey(toBlock(8993849));


		auto routine = [&](u64 index)
		{
			auto& chl = chls[index];

			std::array<std::array<block, 8>, 2> mySums;
			std::vector<std::array<block, 8>> tree(1ull << (mDepth + 1));
#ifdef DEBUG_PRINT_PPRF
			std::vector<std::array<block, 8>> ftree(1ull << (mDepth + 1));
#endif

			auto getLevel = [&](u64 i, bool f = false)
			{
				auto size = (1ull << i);
				auto offset = (size - 1);
#ifdef DEBUG_PRINT_PPRF
				auto b = (f ? ftree.begin() : tree.begin()) + offset;
#else
				auto b = tree.begin() + offset;
#endif
				auto e = b + size;
				return span<std::array<block, 8>>(b, e);
			};

			auto printLevel = [&](u64 d)
			{

				auto level0 = getLevel(d);
				auto flevel0 = getLevel(d, true);

				std::cout
					<< "---------------------\nlevel " << d
					<< "\n---------------------" << std::endl;

				std::array<block, 2> sums{ ZeroBlock ,ZeroBlock };
				for (u64 i = 0; i < level0.size(); ++i)
				{
					for (u64 j = 0; j < 8; ++j)
					{

						if (neq(level0[i][j], flevel0[i][j]))
							std::cout << Color::Red;

						std::cout << "p[" << i << "][" << j << "] "
							<< level0[i][j] << " " << flevel0[i][j] << std::endl << Color::Default;

						if (i == 0 && j == 0)
							sums[i & 1] = sums[i & 1] ^ flevel0[i][j];
					}
				}

				std::cout << "sums[0] = " << sums[0] << " " << sums[1] << std::endl;
			};

			std::array<std::vector<std::array<block, 8>>, 2> sums;
			sums[0].resize(mDepth - 1);
			sums[1].resize(mDepth - 1);

			for (u64 g = index * 8; g < mPntCount; g += 8 * chls.size())
			{
#ifdef DEBUG_PRINT_PPRF
				chl.recv(ftree);
#endif
				//u64 g2;
				//chl.recv(g2);
				//lout << "recv["<<index<<"][" << g << "] vs " << g2 << std::endl;
				chl.recv(sums[0].data(), sums[0].size());
				chl.recv(sums[1].data(), sums[1].size());

				//memset(tree.data(), 0, tree.size() * sizeof(std::array<block, 8>));

				auto l1 = getLevel(1);
				auto l1f = getLevel(1, true);
				auto min = std::min<u64>(8, mPntCount - g);

				for (u64 i = 0; i < min; ++i)
				{
					int notAi = mBaseChoices[i + g][0];
					l1[notAi][i] = mBaseOTs[i + g][0] ^ sums[notAi][0][i];
					l1[notAi ^ 1][i] = ZeroBlock;
					//auto idxn = i + (notAi^1) * mPntCount8;
					//l1[idxn] = mBaseOTs[i] ^ sums[notAi^1](i);

					//std::cout << "l1[" << notAi << "]["<<i<<"] " << l1[notAi][i] << " = "
					//    << (mBaseOTs[i+g][0]) << " ^ "
					//    << sums[notAi][0][i] << " vs " << l1f[notAi][i] << std::endl;

				}
				//std::cout << std::endl;
				//Matrix<block> fullTree(mDepth, mDomain);

#ifdef DEBUG_PRINT_PPRF
				printLevel(1);
#endif

				for (u64 d = 1; d < mDepth; ++d)
				{
					auto level0 = getLevel(d);
					auto level1 = getLevel(d + 1);


					memset(mySums[0].data(), 0, mySums[0].size() * sizeof(block));
					memset(mySums[1].data(), 0, mySums[1].size() * sizeof(block));

					auto width = level1.size();
					for (u64 i = 0; i < width; ++i)
					{
						u8 keep = i & 1;
						auto i0 = i >> 1;
						auto& a = aes[keep];
						auto& sub = level0[i0];
						auto& sub1 = level1[i];

						auto& sum = mySums[keep];


						//auto _td = &level0[i0 + mPntCount8 - 1];
						//auto _td1 = &level1[i + mPntCount8 - 1];

						// hash the current node td and store the result in td1.

							// H(x) = AES(k[keep], x) + x;
						a.ecbEncBlocks(sub.data(), 8, sub1.data());
						sub1[0] = sub1[0] ^ sub[0];
						sub1[1] = sub1[1] ^ sub[1];
						sub1[2] = sub1[2] ^ sub[2];
						sub1[3] = sub1[3] ^ sub[3];
						sub1[4] = sub1[4] ^ sub[4];
						sub1[5] = sub1[5] ^ sub[5];
						sub1[6] = sub1[6] ^ sub[6];
						sub1[7] = sub1[7] ^ sub[7];

#ifdef DEBUG_PRINT_PPRF
						for (u64 i = 0; i < 8; ++i)
							if (eq(sub[i], ZeroBlock))
								sub1[i] = ZeroBlock;
#endif

						// sum += H(x)
						sum[0] = sum[0] ^ sub1[0];
						sum[1] = sum[1] ^ sub1[1];
						sum[2] = sum[2] ^ sub1[2];
						sum[3] = sum[3] ^ sub1[3];
						sum[4] = sum[4] ^ sub1[4];
						sum[5] = sum[5] ^ sub1[5];
						sum[6] = sum[6] ^ sub1[6];
						sum[7] = sum[7] ^ sub1[7];
					}



					if (d != mDepth - 1)
					{

						for (u64 i = 0; i < min; ++i)
						{
							auto a = points[i + g] >> (mDepth - 1 - d);
							auto notAi = (a & 1) ^ 1;
							auto idx = (a ^ 1);// *mPntCount + i;
#ifdef DEBUG_PRINT_PPRF
							auto prev = level1[idx][i];
#endif
							//level1[a] = CCBlock;
							level1[idx][i] =
								level1[idx][i] ^
								sums[notAi][d][i] ^
								mySums[notAi][i] ^
								mBaseOTs[i + g][d];
#ifdef DEBUG_PRINT_PPRF
							std::cout << "up[" << i << "] = level1[" << idx << "][" << i << "] "
								<< prev << " -> " << level1[idx][i] << " " << a << " " << idx << " ~~ "
								<< mBaseOTs[i + g][d] << " " << sums[notAi][d][i] << " @ " << (i + g) << " " << d << std::endl;
#endif
						}

					}
#ifdef DEBUG_PRINT_PPRF
					printLevel(d + 1);
#endif

					//std::cout << "r[" << (d + 1) << "] " << level1[0] << std::endl;
				}
				//printLevel(mDepth);
				//setTimePoint("pprf.recv.expand-" + std::to_string(g));

				int temp;
				std::vector<std::array<block, 4>> lastOts(min);
				//chl.recv(temp);
				chl.recv(lastOts);

				auto level = getLevel(mDepth);
				//auto flevel = getLevel(mDepth, true);
				auto d = mDepth - 1;
				for (u64 j = 0; j < min; ++j)
				{

					auto a = points[j + g];
					auto notAi = (a & 1) ^ 1;
					auto idx = (a ^ 1);// *mPntCount + j;
					auto idx1 = a;// *mPntCount + j;

					//auto idx = i * mPntCount + j;

					//lastOts[j][0] = sums[0](i, j);
					//lastOts[j][1] = sums[1](i, j);
					//lastOts[j][3] = sums[0](i, j);
					//lastOts[j][2] = sums[1](i, j);

					std::array<block, 2> masks, maskIn;

					maskIn[0] = mBaseOTs[j + g][d];
					maskIn[1] = mBaseOTs[j + g][d] ^ AllOneBlock;

					mAesFixedKey.ecbEncTwoBlocks(maskIn.data(), masks.data());
					masks[0] = masks[0] ^ maskIn[0];
					masks[1] = masks[1] ^ maskIn[1];

					auto& ot0 = lastOts[j][2 * notAi + 0];
					auto& ot1 = lastOts[j][2 * notAi + 1];

					ot0 = ot0 ^ masks[0];
					ot1 = ot1 ^ masks[1];

#ifdef DEBUG_PRINT_PPRF
					auto prev = level[idx][j];
#endif

					mySums[notAi][j] = mySums[notAi][j] ^ level[idx][j];
					mySums[notAi ^ 1][j] = mySums[notAi ^ 1][j] ^ level[idx1][j];

					level[idx][j] = ot0 ^ mySums[notAi][j];
					level[idx1][j] = ot1 ^ mySums[notAi ^ 1][j];

#ifdef DEBUG_PRINT_PPRF
					std::cout << "up[" << d << "] = level1[" << (idx / mPntCount8) << "][" << (idx % mPntCount8) << " "
						<< prev << " -> " << level[idx][j] << " ~~ "
						<< mBaseOTs[j + g][d] << " " << ot0 << " @ " << (j + g) << " " << d << std::endl;
#endif

					//std::cout << "    " << ot0 << " ^ " << (mySums[notAi][j] ^ flevel[idx]) << std::endl;
					//std::cout << "    " << (ot0^mySums[notAi][j]) << " ^ " << (flevel[idx]) << std::endl;
				}

				auto lvl = getLevel(mDepth);
				copyOut(transpose, lvl, output, min, g);
			}
		};



		std::vector<std::thread> thrds(chls.size() - 1);
		for (u64 i = 0; i < thrds.size(); ++i)
			thrds[i] = std::thread(routine, i);
			//routine(i);

		routine(thrds.size());

		for (u64 i = 0; i < thrds.size(); ++i)
			thrds[i].join();
	}

}

//while (leafIdx != mDomain)
//{
//    // for the current leaf index, traverse to the leaf.
//    while (d != mDepth)
//    {

//        auto level0 = getLevel(d);
//        auto level1 = getLevel(d + 1);

//        // for our current position, are we going left or right?
//        auto pIdx = (leafIdx >> (mDepth - 1 - d));
//        u8 keep = pIdx & 1;

//        auto& a = aes[keep];
//        auto td = tree[d];
//        auto td1 = tree[d + 1];
//        auto sum = &sums[keep](d, 0);

//        auto td_ = level0.subspan(pIdx >>1, mPntCount8);
//        auto td1_ = level1.subspan(pIdx, mPntCount8);

//        ++d;

//        // hash the current node td and store the result in td1.
//        for (u64 i = 0; i < mPntCount8; i += 8)
//        {
//            auto sub = td.subspan(i, 8);
//            auto sub1 = td1.subspan(i, 8);
//            auto sub1_ = td1_.subspan(i, 8);

//            // H(x) = AES(k[keep], x) + x;
//            a.ecbEncBlocks(sub.data(), 8, td1.data());


//            sub1[0] = sub1[0] ^ sub[0];
//            sub1[1] = sub1[1] ^ sub[1];
//            sub1[2] = sub1[2] ^ sub[2];
//            sub1[3] = sub1[3] ^ sub[3];
//            sub1[4] = sub1[4] ^ sub[4];
//            sub1[5] = sub1[5] ^ sub[5];
//            sub1[6] = sub1[6] ^ sub[6];
//            sub1[7] = sub1[7] ^ sub[7];

//            sub1_[0] = sub1[0];
//            sub1_[1] = sub1[1];
//            sub1_[2] = sub1[2];
//            sub1_[3] = sub1[3];
//            sub1_[4] = sub1[4];
//            sub1_[5] = sub1[5];
//            sub1_[6] = sub1[6];
//            sub1_[7] = sub1[7];
//                             
//            // sum += H(x)
//            sum[i + 0] = sum[i + 0] ^ sub1[0];
//            sum[i + 1] = sum[i + 1] ^ sub1[1];
//            sum[i + 2] = sum[i + 2] ^ sub1[2];
//            sum[i + 3] = sum[i + 3] ^ sub1[3];
//            sum[i + 4] = sum[i + 4] ^ sub1[4];
//            sum[i + 5] = sum[i + 5] ^ sub1[5];
//            sum[i + 6] = sum[i + 6] ^ sub1[6];
//            sum[i + 7] = sum[i + 7] ^ sub1[7];
//        }
//    }


//    auto td1 = &tree(d, 0);
//    memcpy(output[leafIdx].data(), td1, mPntCount * sizeof(block));

//    u64 shift = (leafIdx + 1) ^ leafIdx;
//    d -= log2floor(shift) + 1;
//    ++leafIdx;
//}
