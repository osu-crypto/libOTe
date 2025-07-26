#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


#include "cryptoTools/Circuit/MxCircuit.h"
#include "cryptoTools/Circuit/BetaCircuit.h"

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <list>
#include <vector>
#include "libOTe/Tools/Coproto.h"

namespace osuCrypto
{

	// The GMW MPC protocol for evaluating binary circuits.
	// Each AND gate consumes two OLE corrleations while
	// XOR gates are free.
	class Gmw final : public TimerAdapter
	{
	public:

		struct Debug
		{
			bool mDebug = false;
			std::vector<block> mOleMult, mB, mOleAdd, mD;
			std::list<std::array<std::vector<block>, 2>> mU, mW;
			Matrix<int> mVals;
			Matrix<block> mWords;
		};


		Debug mO;

		// allow the circuit to be reordered into levels
		// based on their AND depth.
		BetaCircuit::LevelizeType mLevelize = BetaCircuit::LevelizeType::Reorder;

		// the number of SIMD circuits to eval.
		u64 mN = 0;
		// the number of 128 chunks to evaluate
		u64 mN128 = 0;

		// when setting the wires memory, this records how many remain unmapped.
		u64 mRemainingMappings = 0;

		u64 mRole = ~0ull;

		// points to the i'th wire memory.
		std::vector<block*> mWords;

		// internal wire memory
		std::vector<Matrix<block>> mMem;

		// total number of rounds.
		u64 mNumRounds = 0;

		// the circuit being evaluated
		BetaCircuit mCir;

		// the remaining gates to be evaluated.
		span<BetaGate> mGates;

		// the index of the circuit to print if debugging is enabled.
		u64 mDebugPrintIdx = ~0ull;

		// the current print statement if debugging is enabled.
		BetaCircuit::PrintIter mPrint;

		u64 mOleIndex = 0;

		// OLE correlation: mOleMult0 * mOleMult1 = mOleAdd0 + mOleAdd1
		std::vector<block> mOleMult, mOleAdd;

		void clear()
		{
			//mTriples.clear();
			mPrint = {};
			mCir = {};
			mGates = {};
			mNumRounds = 0;
			mMem = {};
			mWords = {};
			mO = {};
			mLevelize = BetaCircuit::LevelizeType::Reorder;
			mN = 0;
			mN128 = 0;
			mRemainingMappings = 0;
			mRole = ~0ull;
		}

		// init should be called first. 
		// `n` is the number of independent copies of the circuit 
		// that should be evaluated.
		// `cir` is the binary circuit to be evaluated.
		void init(
			u64 partyIdx,
			u64 n,
			const BetaCircuit& cir);

		// set the i'th input. There should be mN rows of `input`, each row holding
		// mCur.mInput[i].size() bits (rounded up to 8 * sizeof(T)).
		template<typename T>
		void setInput(u64 i, MatrixView<T> input)
		{
			static_assert(std::is_trivially_copyable<T>::value, "expecting trivial");
			MatrixView<u8> ii((u8*)input.data(), input.rows(), input.cols() * sizeof(T));
			implSetInput(i, ii, sizeof(T));
		}

		//// set the i'th input. There should be mN rows of `input`, each row holding
		//// mCur.mInput[i].size() bits
		//void setInput(u64 i, MatrixView<u8> input)
		//{
		//    setInput<u8>(i, input.mData);
		//}

		// Set the i'th input to zero. Useful when only one party has input i (in plaintext).
		void setZeroInput(u64 i);

		// Allows the caller to set the i'th input to d without copying the data.
		// It is required that d is in transposed format.
		void mapInput(u64 i, MatrixView<u8> d)
		{
			if (mCir.mInputs.size() <= i)
				throw std::runtime_error("GMW mapInput for an index that does not exist. " LOCATION);
			if (mCir.mInputs[i].size() != d.rows())
				throw std::runtime_error("GMW mapInput called with incorrect number of wires. " LOCATION);
			if (divCeil(mN, 8) > d.cols())
				throw std::runtime_error("GMW mapInput called with incorrect number of inputs. " LOCATION);
			if (d.cols() % sizeof(block))
				throw std::runtime_error("the alignment of the data must be at least sizeof(block). " LOCATION);

			for (u64 j = 0; j < d.rows(); ++j)
				map(mCir.mInputs[i][j], (block*)d[j].data());
		}

		// Allows the caller to preset the i'th ioutput to d without copying the data.
		// It is required that d is in transposed formapt. This must be called prior 
		// to the protocol being invoked.
		void mapOutput(u64 i, MatrixView<u8> d)
		{
			if (mCir.mOutputs.size() <= i)
				throw std::runtime_error("GMW mapOutput for an index that does not exist. " LOCATION);
			if (mCir.mOutputs[i].size() != d.rows())
				throw std::runtime_error("GMW mapOutput called with incorrect number of wires. " LOCATION);
			if (divCeil(mN, 8) > d.cols())
				throw std::runtime_error("GMW mapOutput called with incorrect number of inputs. " LOCATION);
			if (d.rows() % sizeof(block))
				throw std::runtime_error("the alignment of the data must be at least sizeof(block). " LOCATION);

			for (u64 j = 0; j < d.rows(); ++j)
				map(mCir.mOutputs[i][j], (block*)d[j].data());
		}

		u64 oleCount() const
		{
			return 2 * mCir.mNonlinearGateCount * roundUpTo(mN, 128);
		}

		// set the OLE correlations to be used by the protocol.
		// party i will hold ai,ci such that mult0 * mult1 = add0 + add0
		void setOle(span<block> mult, span<block> add)
		{
			auto count = oleCount();
			if (count / 128 != mult.size() || mult.size() != add.size())
				throw RTE_LOC;

			mOleMult.assign(mult.begin(), mult.end());
			mOleAdd.assign(add.begin(), add.end());
		}


		// run the gmw protocol.
		task<> run(coproto::Socket& chl);

		//// copy the i'th output to `out`
		//void getOutput(u64 i, Matrix& out)
		//{
		//    if (i > mCir.mOutputs.size() || out.bitsPerEntry() != mCir.mOutputs[i].size())
		//        throw RTE_LOC;
		//    getOutput(i, out.mData);
		//}

		// get the i'th output. There should be mN rows of `out`, each row holding
		// mCur.mOutput[i].size() bits (rounded up to 8 * sizeof(T)).
		template<typename T>
		void getOutput(u64 i, MatrixView<T> out)
		{
			static_assert(std::is_trivially_copyable<T>::value, "expecting trivial");
			MatrixView<u8> ii((u8*)out.data(), out.rows(), out.cols() * sizeof(T));
			implGetOutput(i, ii, sizeof(T));
		}

		// return the number of rounds the GMW protocol will require.
		u64 numRounds()
		{
			return mNumRounds;
		}

		void implSetInput(u64 i, MatrixView<u8> input, u64 alignment);
		void implGetOutput(u64 i, MatrixView<u8> out, u64 alignment);

		MatrixView<u8> getInputView(u64 i);
		MatrixView<u8> getOutputView(u64 i);
		MatrixView<u8> getMemView(BetaBundle& wires);


		block* multSendP1(block* x, GateType gt,
			block* a, block* sendIter);

		block* multSendP2(block* x, GateType gt,
			block* c, block* sendIter);


		block* multRecvP1(block* x, block* z, GateType gt,
			block* b, block* recvIter);

		block* multRecvP2(block* x, block* z,
			block* c,
			block* d,
			block* recvIter);


		block* multSend(block* x, block* y, GateType gt,
			block* a,
			block* c,
			block* sendIter,
			u64 idx)
		{
			if (idx == 0)
				return multSendP1(x, y, gt, a, c, sendIter);
			else
				return multSendP2(x, y, a, c, sendIter);
		}\

			block* multSendP1(block* x, block* y, GateType gt,
				block* a,
				block* c,
				block* sendIter);

		block* multSendP2(block* x, block* y,
			block* a,
			block* c,
			block* sendIter);


		block* multRecv(block* x, block* y, block* z, GateType gt,
			block* b,
			block* c,
			block* d,
			block* recvIter,
			u64 idx)
		{
			if (idx == 0)
				return multRecvP1(x, y, z, gt, b, c, d, recvIter);
			else
				return multRecvP2(x, y, z, b, c, d, recvIter);
		}

		block* multRecvP1(block* x, block* y, block* z, GateType gt,
			block* b,
			block* c,
			block* d,
			block* recvIter);

		block* multRecvP2(block* x, block* y, block* z,
			block* b,
			block* c,
			block* d,
			block* recvIter);


		// The `wire` wire will use the memory pointed to by `data`.
		// `data` must be mN128 blocks long.
		void map(u64 wire, block* data)
		{
			if (mWords.size() <= wire)
				throw RTE_LOC;
			if (mWords[wire])
				throw RTE_LOC;
			if ((u64)data % sizeof(block))
				throw RTE_LOC;

			mWords[wire] = data;
			assert(mRemainingMappings);
			--mRemainingMappings;
		}

		// an internal function used to allocate memory 
		//for any wires that have not been mapped.
		void finalizeMapping()
		{
			for (u64 i = 0; i < mCir.mInputs.size(); ++i)
				for (u64 j = 0; j < mCir.mInputs[i].size(); ++j)
					if (mWords[mCir.mInputs[i][j]] == nullptr)
						throw std::runtime_error("GMW input wire not set. input: " + std::to_string(i) + "\n" + LOCATION);
			if (mRemainingMappings)
			{
				mMem.emplace_back();
				mMem.back().resize(mRemainingMappings, mN128, AllocType::Uninitialized);
				for (u64 i = 0, j = 0; i < mCir.mWireCount; ++i)
				{
					if (mWords[i] == nullptr)
						map(i, mMem.back().data(j++));
				}

				assert(mRemainingMappings == 0);
			}
		}

	};
}