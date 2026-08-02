#include "Gmw.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Common/Defines.h"
#include <numeric>
#include "libOTe/Tools/Tools.h"
#include "cryptoTools/Circuit/BetaLibrary.h"
#include <array>
#include "cryptoTools/Common/Log.h"
#ifdef ENABLE_CIRCUITS

namespace osuCrypto
{
	using PRNG = PRNG;

	void Gmw::init(
		u64 partyIdx,
		u64 n,
		const BetaCircuit& cir)
	{
		mN = n;

		mCir = cir;
		mN128 = divCeil(mN, 128);

		if (mCir.mLevelCounts.size() == 0)
			mCir.levelByAndDepth(mLevelize);

		mNumRounds = mCir.mLevelCounts.size();
		mGates = mCir.mGates;
		mWords.resize(0);
		mWords.resize(mCir.mWireCount);
		mRemainingMappings = mCir.mWireCount;
		mMem.clear();
		mPrint = mCir.mPrints.begin();


		mRole = partyIdx;// gen.partyIdx();
//		if (mCir.mNonlinearGateCount)
//			mTriples = gen.binOleRequest(2 * mCir.mNonlinearGateCount * roundUpTo(mN, 128));
	}


	void Gmw::implSetInput(u64 i, MatrixView<u8> input, u64 alignment)
	{
		MatrixView<u8> memView = getInputView(i);

		auto numWires = memView.rows();

		auto bits = alignment * 8;

		// inputs should be the right alignment.
		auto exp = (numWires + bits - 1) / bits;
		auto act = input.cols() / alignment;
		if (exp != act)
		{
			throw std::runtime_error("incorrect number of input bits per row. " LOCATION);
		}

		if (input.rows() != mN)
			throw std::runtime_error("incorrect number of input rows. " LOCATION);

		transpose(input, memView);
	}

	void Gmw::setZeroInput(u64 i)
	{
		MatrixView<u8> memView = getInputView(i);
		memset(memView.data(), 0, memView.size());
	}

	void Gmw::implGetOutput(u64 i, MatrixView<u8> out, u64 alignment)
	{
		MatrixView<u8> memView = getOutputView(i);

		auto numWires = memView.rows();
		auto bits = alignment * 8;

		// inputs should be 8 bit or 128 bit aligned.
		if ((numWires + bits - 1) / bits != out.cols() / alignment)
			throw RTE_LOC;

		if (out.rows() != mN)
			throw RTE_LOC;

		transpose(memView, out);
	}

	MatrixView<u8> Gmw::getInputView(u64 i)
	{
		if (mCir.mInputs.size() <= i)
			throw RTE_LOC;

		auto& inWires = mCir.mInputs[i];

		return getMemView(inWires);
	}

	MatrixView<u8> Gmw::getOutputView(u64 i)
	{
		if (mCir.mOutputs.size() <= i)
			throw RTE_LOC;

		auto& wires = mCir.mOutputs[i];
		// for(auto w : wires)
		// {
		//     if(mCir.mWireFlags[w] == BetaWireFlag::InvWire)
		//     {
		//         throw RTE_LOC;
		//     }  
		// }

		return getMemView(wires);
	}

	MatrixView<u8> Gmw::getMemView(BetaBundle& wires)
	{
		// we require the input bundles and memory are contiguous.
		for (u64 j = 1; j < wires.size(); ++j)
		{
			if (wires[j - 1] + 1 != wires[j])
				throw RTE_LOC;
		}

		if (mWords[wires[0]])
		{
			// we require the input bundles and memory are contiguous.
			for (u64 j = 1; j < wires.size(); ++j)
			{
				if (mWords[wires[j - 1]] + mN128 != mWords[wires[j]])
					throw RTE_LOC;
			}
		}
		else
		{
			static_assert(std::is_nothrow_move_constructible<Matrix<block>>::value, "assumes");
			block* old = nullptr;
			if (mMem.size())
				old = mMem.back().data();
			mMem.emplace_back();

			if (old && old != (mMem.end() - 2)->data())
				throw RTE_LOC;

			mMem.back().resize(wires.size(), mN128, AllocType::Uninitialized);
			for (u64 j = 0; j < wires.size(); ++j)
			{
				map(wires[j], mMem.back()[j].data());
				//mWords[] =;
			}
		}

		MatrixView<u8> memView((u8*)mWords[wires[0]], wires.size(), mN128 * 16);
		return memView;
	}

	//void Gmw::preprocess()
	//{
	//	if (mCir.mGates.size() == 0)
	//		throw std::runtime_error("init(...) must be called first. " LOCATION);

	//	if (mCir.mNonlinearGateCount)
	//	{
	//		mTriples.start();
	//	}
	//}

	struct DebugCheckSums
	{
		block a, b, c, d;
	};

	// The basic protocol where the inputs are not shared:
	// Sender has 
	//   > input x
	//   > rand  a, b
	// Recver has
	//   > input y
	//   > rand  c, d = ac + b
	//
	// Sender sends u = a + x
	// Recver sends w = c + y
	//
	// Sender outputs z1 = wx     = cx + yx
	// Recver outputs z2 = uc + d = cx + ca + ca + b
	//                            = cx + b
	// Observe z1 + z2 = xy
	//
	// The full protocol where the inputs are shared:
	// Sender has 
	//   > input x1, y1
	// Recver has
	//   > input x2, y2
	//
	// The protocols invoke the basic protocol twice.
	//   > Sender inputs (x1, y1)
	//   > Recver inputs (y2, x2)
	// 
	//   > Sender receives (z11, z21)
	//   > Recver receives (z12, z22)
	//
	// The final output is:
	// Sender outputs: z1 = x1y1 + z11 + z21 
	//                    = x1y1 + (x1y2 + r1) + (x2y1 +r2)
	//                    = x1y1 + x1y2 + x2y1 + r
	// Recver outputs: z2 = x2y2 + z12 + z22 
	//                    = x2y2 + r1 + r2
	//                    = x2y2 + r
	coproto::task<> Gmw::run(coproto::Socket& chl)
	{
		auto gates = span<BetaGate>{};
		auto gate = span<BetaGate>::iterator{};
		auto dirtyBits = std::vector<u8>{};
		auto pinnedInputs = std::vector<u8>{};
		auto in = std::array<block*, 2>{};
		auto out = (block*)nullptr;
		auto ww = std::vector<block>{};
		auto debugCheckSums = std::array<DebugCheckSums, 2>{};
		auto print = coproto::unique_function<void(u64)>{};
		auto a = AlignedUnVector<block>{};
		auto b = AlignedUnVector<block>{};
		auto c = AlignedUnVector<block>{};
		auto d = AlignedUnVector<block>{};
		auto buff = AlignedUnVector<block>{};
		auto buffIter = (block*)nullptr;
		//auto triple = BinOle{};
		auto mult = span<block>{mOleMult};
		auto add = span<block>{mOleAdd};
		auto j = u64{};
		auto roundIdx = u64{};
		auto roundRem = u64{};
		auto batchSize = 1ull << 14;

		if (mRole > 1)
			std::terminate();
		if (mCir.mGates.size() == 0ull)
			throw std::runtime_error("Gmw::init(...) was not called");

		finalizeMapping();
		if (mO.mDebug)
		{
			mO.mWords.resize(mWords.size(), mN128);

			for (u64 i = 0; i < mWords.size(); i++)
			{
				for (u64 j = 0; j < mN128; ++j)
					mO.mWords(i, j) = mWords[i][j];
			}
			co_await chl.send(std::move(mO.mWords));

			mO.mWords.resize(mWords.size(), mN128);
			co_await chl.recv(mO.mWords);

			for (u64 i = 0; i < mWords.size(); i++)
			{
				for (u64 j = 0; j < mN128; ++j)
					mO.mWords(i, j) = mO.mWords(i, j) ^ mWords[i][j];
			}

			memset(&debugCheckSums, 0, sizeof(debugCheckSums));
		}

		for (roundIdx = 0; roundIdx < numRounds(); ++roundIdx)
		{
			gates = mGates.subspan(0, mCir.mLevelCounts[roundIdx]);
			mGates = mGates.subspan(mCir.mLevelCounts[roundIdx]);


			if (mO.mDebug)
			{
				dirtyBits.resize(0);
				pinnedInputs.resize(0);
				dirtyBits.resize(mCir.mWireCount, 0);
				pinnedInputs.resize(mCir.mWireCount, 0);
			}

			// a  * c  = b  + d
			// a' * c' = b' + d'
			a.resize(mN128 * mCir.mLevelAndCounts[roundIdx]);
			b.resize(mN128 * mCir.mLevelAndCounts[roundIdx]);
			c.resize(mN128 * mCir.mLevelAndCounts[roundIdx]);
			d.resize(mN128 * mCir.mLevelAndCounts[roundIdx]);
			roundRem = mN128 * mCir.mLevelAndCounts[roundIdx] * 2;


			// get enough correlated randomness to cover the current round.
			j = 0;
			while (j != a.size())
			{
				// if we are out, get more random triples.
				//if (add.size() == 0)
				//{
				//	co_await mTriples.get(triple);
				//	add = triple.mAdd;
				//	mult = triple.mMult;
				//}

				// the number of multiplications that we can do in this batch.
				auto min = std::min<u64>(a.size() - j, add.size() / 2);

				// depending on the role, we need to take the first or second half of the triples
				// as the first correlation.
				span<block> aa, bb, cc, dd;
				if (mRole)
				{
					aa = mult.subspan(0, min);
					cc = mult.subspan(min, min);
					bb = add.subspan(0, min);
					dd = add.subspan(min, min);
				}
				else
				{
					cc = mult.subspan(0, min);
					aa = mult.subspan(min, min);
					dd = add.subspan(0, min);
					bb = add.subspan(min, min);
				}

				// we copy the triples into the current batch.
				std::copy(aa.begin(), aa.end(), a.begin() + j);
				std::copy(bb.begin(), bb.end(), b.begin() + j);
				std::copy(cc.begin(), cc.end(), c.begin() + j);
				std::copy(dd.begin(), dd.end(), d.begin() + j);

				//if (mNextBatchIdx == 0)
				//{
				//    std::cout << "0 a " << a[j] << " * c = b " << b[j] << " ^ d" << std::endl;
				//    std::cout << "0 a * c " << c[j] << " = b ^ d " << d[j] << std::endl;
				//}
				//else
				//{
				//    std::cout << "1 a * c " << c[j] << " = b ^ d " << d[j] << std::endl;
				//    std::cout << "1 a " << a[j] << " * c = b " << b[j] << " ^ d" << std::endl;
				//}

				mult = mult.subspan(min * 2);
				add = add.subspan(min * 2);
				j += min;
			}

			if (mO.mDebug)
			{
				for (u64 i = 0; i < a.size(); ++i)
				{
					debugCheckSums[0].a ^= a[i];
					debugCheckSums[0].b ^= b[i];
					debugCheckSums[0].c ^= c[i];
					debugCheckSums[0].d ^= d[i];
				}
			}

			// now process the round.
			j = 0;
			for (gate = gates.begin(); gate < gates.end(); ++gate)
			{
				assert(mWords[gate->mInput[0]]);
				assert(mWords[gate->mInput[1]]);
				assert(mWords[gate->mOutput]);
				in[0] = mWords[gate->mInput[0]];
				in[1] = mWords[gate->mInput[1]];
				out = mWords[gate->mOutput];


				// check that inputs to this level are non-linear outputs also computed this round.
				// this isn't allows because we still have not received the other share of the output.
				if (mO.mDebug)
				{
					if (dirtyBits[gate->mInput[0]] ||
						(dirtyBits[gate->mInput[1]] && gate->mType != GateType::a))
					{
						throw std::runtime_error("incorrect levelization, input to current gate depends on the output of the current round. " LOCATION);
					}

					if (pinnedInputs[gate->mOutput])
					{
						throw std::runtime_error("incorrect levelization, overwriting an input which is being used in the current round. " LOCATION);
					}
				}

				// copy gates.
				if (gate->mType == GateType::a)
				{
					for (u64 i = 0; i < mN128; ++i)
						out[i] = in[0][i];
				}
				else if (gate->mType == GateType::na_And ||
					gate->mType == GateType::nb_And ||
					gate->mType == GateType::And ||
					gate->mType == GateType::Nand ||
					gate->mType == GateType::Nor ||
					gate->mType == GateType::nb_Or ||
					gate->mType == GateType::Or)
				{

					if (buff.size() == 0 && roundRem)
					{
						auto min = roundUpTo(std::min<u64>(batchSize, roundRem), mN128 * 2);
						buff.resize(min);
						roundRem -= min;
						buffIter = buff.data();
					}

					// compute the first half of the protocol.
					buffIter = multSend(
						in[0], in[1],
						gate->mType,
						a.data() + j,
						c.data() + j,
						buffIter, mRole);

					j += mN128;

					if (mO.mDebug)
					{
						pinnedInputs[gate->mInput[0]] = 1;
						pinnedInputs[gate->mInput[1]] = 1;
						dirtyBits[gate->mOutput] = 1;
					}

					if (buffIter == buff.data() + buff.size())
						co_await chl.send(std::move(buff));

				}
				else if (gate->mType == GateType::Xor ||
					gate->mType == GateType::Nxor)
				{

					for (u64 i = 0; i < mN128; ++i)
						out[i] = in[0][i] ^ in[1][i];

					if (gate->mType == GateType::Nxor && mRole)
					{
						for (u64 i = 0; i < mN128; ++i)
							out[i] = out[i] ^ AllOneBlock;
					}
				}
				else
					throw RTE_LOC;

			}

			assert(roundRem == 0 && buff.size() == 0);
			roundRem = mN128 * mCir.mLevelAndCounts[roundIdx] * 2;

			j = 0;
			for (gate = gates.begin(); gate < gates.end(); ++gate)
			{
				if (gate->mType == GateType::na_And ||
					gate->mType == GateType::nb_And ||
					gate->mType == GateType::nb_Or ||
					gate->mType == GateType::And ||
					gate->mType == GateType::Nand ||
					gate->mType == GateType::Or ||
					gate->mType == GateType::Nor)
				{

					if ((roundRem && buff.size() == 0) || buffIter == buff.data() + buff.size())
					{
						buff.resize(roundUpTo(std::min<u64>(batchSize, roundRem), mN128 * 2));
						roundRem -= buff.size();
						buffIter = buff.data();
						co_await chl.recv(buff);
					}


					assert(mWords[gate->mInput[0]]);
					assert(mWords[gate->mInput[1]]);
					assert(mWords[gate->mOutput]);
					in[0] = mWords[gate->mInput[0]];
					in[1] = mWords[gate->mInput[1]];
					out = mWords[gate->mOutput];

					buffIter = multRecv(in[0], in[1], out, gate->mType,
						b.data() + j,
						c.data() + j,
						d.data() + j,
						buffIter, mRole);

					j += mN128;
				}
			}

			assert(roundRem == 0);
			buff.resize(0);

			if (mO.mDebug)
			{
				print = [&](u64 gIdx) {
					while (
						mDebugPrintIdx < mN &&
						mPrint != mCir.mPrints.end() &&
						mPrint->mGateIdx <= gIdx &&
						mRole)
					{
						auto wireIdx = mPrint->mWire;
						auto invert = mPrint->mInvert;

						if (wireIdx != ~u32(0))
						{
							BitIterator iter((u8*)mO.mWords[wireIdx].data(), mDebugPrintIdx);
							auto mem = u64(*iter);
							std::cout << (u64)(mem ^ (invert ? 1 : 0));
						}
						if (mPrint->mMsg.size())
							std::cout << mPrint->mMsg;

						++mPrint;
					}
					};

				for (auto& gate : gates)
				{

					auto gIdx = &gate - mCir.mGates.data();
					print(gIdx);

					for (u64 i = 0; i < mN128; ++i)
					{
						auto& a = mO.mWords(gate.mInput[0], i);
						auto& b = mO.mWords(gate.mInput[1], i);
						auto& c = mO.mWords(gate.mOutput, i);
						//if (gate.mOutput == 129)
						//{
						//    auto cc=
						//        (AllOneBlock ^ a) & b;
						//    std::cout << "~" << a << " & " << b << " -> " << cc << std::endl;
						//}

						switch (gate.mType)
						{
						case GateType::a:
							c = a;
							break;
						case GateType::And:
							c = a & b;
							break;
						case GateType::Nand:
							c = (a & b) ^ AllOneBlock;
							break;
						case GateType::Or:
							c = a | b;
							break;
						case GateType::nb_Or:
							c = a | (AllOneBlock ^ b);
							break;
						case GateType::Nor:
							c = (a | b) ^ AllOneBlock;
							break;
						case GateType::nb_And:
							//lout << "* ~" << a << " & " << b << " -> " << ((AllOneBlock ^ a) & b) << std::endl;
							c = a & (AllOneBlock ^ b);
							break;
						case GateType::na_And:
							//lout << "* ~" << a << " & " << b << " -> " << ((AllOneBlock ^ a) & b) << std::endl;
							c = (AllOneBlock ^ a) & b;
							break;
						case GateType::Xor:
							c = a ^ b;
							break;
						case GateType::Nxor:
							c = a ^ b ^ AllOneBlock;
							break;
						default:
							throw RTE_LOC;
						}
					}
				}

				if (mGates.size() == 0)
				{
					print(mCir.mGates.size());
				}

				ww.resize(mWords.size() * mN128);
				for (u64 i = 0; i < mWords.size(); ++i)
					for (u64 j = 0; j < mN128; ++j)
						ww[i * mN128 + j] = mWords[i][j];
				co_await chl.send(std::move(ww));
				co_await chl.send(std::move(debugCheckSums[0]));

				ww.resize(mWords.size() * mN128);
				co_await chl.recv(ww);
				co_await chl.recv(debugCheckSums[1]);

				if ((debugCheckSums[0].b ^ debugCheckSums[1].d) != (debugCheckSums[0].a & debugCheckSums[1].c))
					throw RTE_LOC;
				if ((debugCheckSums[1].b ^ debugCheckSums[0].d) != (debugCheckSums[1].a & debugCheckSums[0].c))
					throw RTE_LOC;

				for (u64 i = 0; i < mWords.size(); ++i)
				{
					for (u64 j = 0; j < mN128; ++j)
					{

						auto exp = mO.mWords(i, j);
						auto act = ww[i * mN128 + j] ^ mWords[i][j];

						if (neq(exp, act))
						{
							auto row = i;
							auto col = j;

							lout << "p" << mRole << " mem[" << row << ", " << col <<
								"] exp: " << exp <<
								", act: " << act <<
								"\ndiff:" << (exp ^ act) << std::endl;

							throw RTE_LOC;
						}
					}
				}
			}

		}
	}

	BitVector view(block v, u64 l = 10)
	{
		return BitVector((u8*)&v, l);
	}

	namespace {
		bool invertA(GateType gt)
		{
			bool invertX;
			switch (gt)
			{
			case osuCrypto::GateType::na_And:
			case osuCrypto::GateType::Or:
			case osuCrypto::GateType::Nor:
			case osuCrypto::GateType::nb_Or:
				invertX = true;
				break;
			case osuCrypto::GateType::And:
			case osuCrypto::GateType::Nand:
			case osuCrypto::GateType::nb_And:
				invertX = false;
				break;
			default:
				throw RTE_LOC;
			}

			return invertX;
		}
		bool invertB(GateType gt)
		{
			bool invertX;
			switch (gt)
			{
			case osuCrypto::GateType::nb_And:
			case osuCrypto::GateType::Nor:
			case osuCrypto::GateType::Or:
				invertX = true;
				break;
			case osuCrypto::GateType::na_And:
			case osuCrypto::GateType::And:
			case osuCrypto::GateType::Nand:
			case osuCrypto::GateType::nb_Or:
				invertX = false;
				break;
			default:
				throw RTE_LOC;
			}

			return invertX;
		}
		bool invertC(GateType gt)
		{
			bool invertX;
			switch (gt)
			{
			case osuCrypto::GateType::Or:
			case osuCrypto::GateType::Nand:
			case osuCrypto::GateType::nb_Or:
				invertX = true;
				break;
			case osuCrypto::GateType::na_And:
			case osuCrypto::GateType::nb_And:
			case osuCrypto::GateType::Nor:
			case osuCrypto::GateType::And:
				invertX = false;
				break;
			default:
				throw RTE_LOC;
			}

			return invertX;
		}
	}

	// The basic protocol where the inputs are not shared:
	// Sender has 
	//   > input x
	//   > rand  a, b
	// Recver has
	//   > input y
	//   > rand  z, d = ac + b
	//
	// Sender sends u = a + x
	// Recver sends w = z + y
	//
	// Sender outputs z1 = wx + b = cx + yx + b
	// Recver outputs z2 = uc + d = (a + x)z + d
	//                            = ac + xc + (ac + b)
	//                            = cx + b
	// Observer z1 + z2 = xy
	block* Gmw::multSendP1(block* x, GateType gt, block* a, block* u)
	{
		auto width = mN128;
		if (invertA(gt) == false)
		{
			for (u64 i = 0; i < width; ++i)
				u[i] = (a[i] ^ x[i]);
		}
		else
		{
			for (u64 i = 0; i < width; ++i)
				u[i] = (a[i] ^ x[i] ^ AllOneBlock);
		}

		return u + (width);
	}

	block* Gmw::multSendP2(block* y, GateType gt,
		block* c, block* w)
	{
		auto width = mN128;
		//c = mOleAdd+(0, width);
		//mOleAdd = mOleAdd+(width);

		if (invertB(gt) == false)
		{

			for (u64 i = 0; i < width; ++i)
				w[i] = (c[i] ^ y[i]);
		}
		else
		{
			for (u64 i = 0; i < width; ++i)
				w[i] = (c[i] ^ (y[i] ^ AllOneBlock));
		}
		return w + (width);
	}

	block* Gmw::multRecvP1(block* x, block* z, GateType gt,
		block* b, block* w)
	{
		auto width = mN128;

		if (invertA(gt) == false)
		{
			for (u64 i = 0; i < width; ++i)
			{
				z[i] = (x[i] & w[i]) ^ b[i];
			}
		}
		else
		{
			for (u64 i = 0; i < width; ++i)
			{
				z[i] = ((AllOneBlock ^ x[i]) & w[i]) ^ b[i];
			}
		}
		return w + (width);
	}

	block* Gmw::multRecvP2(
		block* y,
		block* z,
		block* c,
		block* d,
		block* u
	)
	{
		auto width = mN128;

		for (u64 i = 0; i < width; ++i)
		{
			z[i] = (c[i] & u[i]) ^ d[i];
		}

		return u + (width);
	}

	block* Gmw::multSendP1(block* x, block* y, GateType gt,
		block* a,
		block* c,
		block* buffIter)
	{
		buffIter = multSendP1(x, gt, a, buffIter);
		buffIter = multSendP2(y, gt, c, buffIter);
		return buffIter;
	}

	block* Gmw::multSendP2(block* x, block* y,
		block* a,
		block* c,
		block* buffIter)
	{
		buffIter = multSendP2(y, GateType::And, c, buffIter);
		buffIter = multSendP1(x, GateType::And, a, buffIter);
		return buffIter;
	}


	block* Gmw::multRecvP1(block* x, block* y, block* z, GateType gt,
		block* b,
		block* c,
		block* d,
		block* buffIter)
	{
		AlignedUnVector<block> zz(mN128);
		AlignedUnVector<block> zz2(mN128);

		buffIter = multRecvP1(x, zz.data(), gt, b, buffIter);
		buffIter = multRecvP2(y, zz2.data(), c, d, buffIter);

		auto xm = invertA(gt) ? AllOneBlock : ZeroBlock;
		auto ym = invertB(gt) ? AllOneBlock : ZeroBlock;
		auto zm = invertC(gt) ? AllOneBlock : ZeroBlock;

		for (u64 i = 0; i < zz.size(); i++)
		{
			auto xx = x[i] ^ xm;
			auto yy = y[i] ^ ym;
			z[i] = xx & yy;
			z[i] = z[i] ^ zz[i];
			z[i] = z[i] ^ zz2[i];
			z[i] = z[i] ^ zm;
		}

		return buffIter;
	}

	block* Gmw::multRecvP2(block* x, block* y, block* z,
		block* b,
		block* c,
		block* d,
		block* buffIter)
	{
		//M_C_BEGIN(coproto::task<>, this, x, y, z, &chl, b, c, d,
		//    zz = std::vector<block>{},
		//    zz2 = std::vector<block>{}
		//);

		AlignedUnVector<block> zz(mN128);
		AlignedUnVector<block> zz2(mN128);

		buffIter = multRecvP2(y, zz.data(), c, d, buffIter);
		buffIter = multRecvP1(x, zz2.data(), GateType::And, b, buffIter);

		for (u64 i = 0; i < zz.size(); i++)
		{
			z[i] = zz2[i] ^ zz[i] ^ (x[i] & y[i]);
		}

		return buffIter;
	}


}
#endif