
#pragma once
#include "cryptoTools/Common/Defines.h"
#include "macoro/task.h"
#include "Equality.h"
#include "libOTe/Dpf/DpfMult.h"
#include "libOTe/Tools/Coproto.h"

namespace osuCrypto
{
	// This class is used to deduplicate the input data for the DMPF protocol.
	//
	// the output will consist of the first occurrence of each key, and the sum of the values for each key.
	// if key k[i] is a duplicate and not the first occurrence, in the output it will be replaced
	// by the alternate key a[i] and the associated value will be zero.
	// 
	// for example, if the input is:
	//	k1, k2, k1, k3, k2
	//  v1, v2, v3, v4, v5
	//  a1, a2, a3, a4, a5
	// 
	// the output will be:
	//  k1,      k2,      a3, k3, a4
	//  v1 + v3, v2 + v5, 0,  v4, 0
	// 
	class Dedup
	{
	public:
		u64 mPartyIdx = 0;
		u64 mN = 0; // The number of input elements.
		u64 mKeyBitCount = 0; // The bit count of the keys.
		u64 mValueBitCount = 0; // The bit count of the values.

		HybEquality mEq;
		DpfMult mMult;

		std::vector<std::array<block, 2>> mOtSend;
		std::vector<block> mOtRecv;
		BitVector mChoice;


		// Deduplicate the input data.
		void init(u64 partyIdx, u64 n, u64 keyBitCount, u64 valueBitCount)
		{
			mPartyIdx = partyIdx;
			mN = n;
			mKeyBitCount = keyBitCount;
			mValueBitCount = valueBitCount;

			auto count = mN * (mN - 1) / 2;
			// Initialize the equality component with keyBitCount
			mEq.init(partyIdx, count, keyBitCount);

			// Compute the total number of multiplications needed.
			// In findFirst, for each i from 1 to mN-2, we use (mN-i-1) multiplications.
			// Total in findFirst is sum_{i=1}^{mN-2} (mN-i-1) = (mN-2)*(mN-1)/2.
			// Additionally, dedup calls two multiplies on the full vector (mN each).
			// So the total is ((mN-2)*(mN-1))/2 + 2*mN.
			//u64 totalMults = ((n > 2) ? ((n - 2) * (n - 1) / 2) : 0) + 2 * n;

			mMult.init(partyIdx, 2 * count + n);
		}


		struct BaseOtCount
		{
			u64 mRecvCount = 0; // number of receive OTs
			u64 mSendCount = 0; // number of send OTs 
		};

		// Returns the total number of base OTs required by dedup.
		// It simply adds the requirements of mEq (the equality check) and mMult (the multiplication).
		BaseOtCount baseOtCount() const
		{
			// Get the base OT count needed by the equality component.
			auto eqCount = mEq.baseOtCount();
			// Get the base OT count needed by the multiplication component.
			u64 multCount = mMult.baseOtCount();

			BaseOtCount tot;
			tot.mRecvCount = eqCount.mRecvCount + multCount;
			tot.mSendCount = eqCount.mSendCount + multCount;
			return tot;
		}

		// Forwards the provided base OTs to mEq and mMult.
		// It splits the provided base OT messages according
		// to the requirements of the equality and multiplication parts.
		void setBaseOts(
			span<const std::array<block, 2>> baseSendOts,
			span<const block> recvBaseOts,
			const oc::BitVector& baseChoices)
		{
			// Check that the provided base OT arrays match the total count.
			BaseOtCount tot = baseOtCount();
			if (baseSendOts.size() != tot.mSendCount ||
				recvBaseOts.size() != tot.mRecvCount ||
				baseChoices.size() != tot.mRecvCount)
			{
				throw std::runtime_error("base OTs size mismatch. " LOCATION);
			}

			// First, split off the part for mEq.
			auto eqCount = mEq.baseOtCount();
			auto baseSendOts_eq = baseSendOts.subspan(0, eqCount.mSendCount);
			auto recvBaseOts_eq = recvBaseOts.subspan(0, eqCount.mRecvCount);
			auto baseChoices_eq = baseChoices.subvec(0, eqCount.mRecvCount);

			// Then, use the remaining OTs for mMult.
			u64 multCount = mMult.baseOtCount();
			auto baseSendOts_mult = baseSendOts.subspan(eqCount.mSendCount, multCount);
			auto recvBaseOts_mult = recvBaseOts.subspan(eqCount.mRecvCount, multCount);
			auto baseChoices_mult = baseChoices.subvec(eqCount.mRecvCount, multCount);

			// Forward to the equality component.
			mEq.setBaseOts(baseSendOts_eq, recvBaseOts_eq, baseChoices_eq);
			// Forward to the multiplication component.
			mMult.setBaseOts(baseSendOts_mult, recvBaseOts_mult, baseChoices_mult);
		}
		macoro::task<> multiplyDC(BitVector& d, BitVector& c, PRNG& prng, Socket& socket);

		macoro::task<> orTree(BitVector& c, BitVector& d, PRNG& prng, Socket& socket)
		{
			if (c.size() != mN * (mN - 1) / 2)
				throw RTE_LOC;
			if (d.size() != mN - 1)
				throw RTE_LOC;
			std::vector<std::vector<u8>> C(mN - 1);
			auto iter = c.begin();
			for (u64 i = 0; i < mN; ++i)
			{
				for (u64 j = i; j < mN - 1; ++j)
				{
					C[j].push_back(*iter++);
				}
			}
			//for(auto & row : C)
			//	co_await socket.send(coproto::copy(row));
			//auto C2 = C;
			//for (auto& row : C2)
			//	co_await socket.recv(row);
			//if (mPartyIdx)
			//{
			//	std::cout << "C " << std::endl;

			//	for (u64 i = 0; i < C2.size(); ++i)
			//	{
			//		for (u64 j = 0; j < C2[i].size(); ++j)
			//		{
			//			std::cout << (int)(C2[i][j] ^ C[i][j]) << " ";
			//		}
			//		std::cout << std::endl;
			//	}
			//}

			while (std::max_element(C.begin(), C.end(), [](auto& a, auto& b) { return a.size() < b.size(); })->size() > 1)
			{
				BitVector x;
				std::vector<u8> y, z;
				for (u64 i = 0; i < C.size(); ++i)
				{
					for (u64 j = 0; j + 1 < C[i].size(); j += 2)
					{
						x.pushBack(C[i][j]);
						y.push_back(C[i][j + 1]);
					}
				}

				z.resize(y.size());
				co_await mMult.multiply(
					1,
					x.getSpan<u8>(),
					MatrixView<u8>(y.data(), y.size(), 1),
					MatrixView<u8>(z.data(), z.size(), 1),
					socket);

				std::vector<std::vector<u8>> C2;
				for (u64 i = 0, idx = 0; i < C.size(); ++i)
				{
					C2.emplace_back();

					for (u64 j = 0; j + 1 < C[i].size(); j += 2)
					{
						// C[i][j] OR C[i][j+1] 
						C2.back().push_back(x[idx] ^ y[idx] ^ z[idx]);
						++idx;
					}

					if (C[i].size() % 2)
					{
						C2.back().push_back(C[i].back());
					}
				}
				C = std::move(C2);

				//{
				//	for (auto& row : C)
				//		co_await socket.send(coproto::copy(row));
				//	auto C2 = C;
				//	for (auto& row : C2)
				//		co_await socket.recv(row);
				//	if (mPartyIdx)
				//	{
				//		std::cout << "C " << std::endl;

				//		for (u64 i = 0; i < C2.size(); ++i)
				//		{
				//			for (u64 j = 0; j < C2[i].size(); ++j)
				//			{
				//				std::cout << (int)(C2[i][j] ^ C[i][j]) << " ";
				//			}
				//			std::cout << std::endl;
				//		}
				//	}
				//}
			}

			iter = d.begin();
			for (u64 i = 0; i < mN - 1; ++i)
			{
				*iter++ ^= C[i][0];
			}
		}


		macoro::task<void> dedup(
			span<u32> keys, // The input keys to deduplicate.
			span<u32> values, // The input values to deduplicate.
			span<u32> altKeys,  // The output indices of the deduplicated keys
			PRNG& prng, Socket& socket)
		{
			std::vector<u32> Ai, Aj, BB;
			Ai.reserve(mN * (mN - 1) / 2);
			Aj.reserve(mN * (mN - 1) / 2);
			BB.reserve(mN * (mN - 1) / 2);
			for (u64 i = 0; i < mN; ++i)
			{
				for (u64 j = i + 1; j < mN; ++j)
				{
					Ai.push_back(keys[i]);
					Aj.push_back(keys[j]);
					BB.push_back(values[j]);
				}
			}



			// cij = eq(Ai, Aj)
			BitVector c(Ai.size());
			co_await mEq.equal<u32>(Ai, Aj, c, socket, prng);

			const bool print = false;
			if(print)
			{
				BitVector C(c.size());
				co_await socket.send(coproto::copy(c));
				co_await socket.recv(C);
				C ^= c;
				auto b = C.begin();
				if (mPartyIdx)
				{
					for (u64 i = 0; i < mN; ++i)
					{
						for (u64 j = 0; j < i + 1; ++j)
						{
							std::cout << "  ";
						}
						for (u64 j = i + 1; j < mN; ++j)
						{
							std::cout << *b++ << " ";
						}
						std::cout << "\n";
					}
				}

			}

			// di =  OR_{k\in [i-1]} cki
			BitVector d(mN - 1);
			co_await orTree(c, d, prng, socket);

			if (mPartyIdx)
				for (u64 i = 0; i < d.sizeBytes(); ++i)
					d.getSpan<u8>()[i] ^= -1;

			if(print)
			{
				co_await socket.send(coproto::copy(d));
				BitVector D(mN - 1);
				co_await socket.recv(D);

				D ^= d;
				if (mPartyIdx)
				{
					std::cout << "d\n1\n";
					for (u64 i = 0; i < D.size(); ++i)
						std::cout << D[i] << std::endl;
				}
			}


			auto iter = c.begin() + (mN -1);
			Matrix<u8> diff(mN - 1, sizeof(keys[0]) + sizeof(values[0]) + divCeil(mN - 2, 8));
			for (u64 i = 1; i < mN; ++i)
			{

				auto k = keys[i] ^ altKeys[i];
				auto v = values[i];
				auto ddi = diff[i-1];
				copyBytes(ddi.subspan(0, sizeof(k)), k);
				ddi = ddi.subspan(sizeof(k));
				copyBytes(ddi.subspan(0, sizeof(v)), v);
				ddi = ddi.subspan(sizeof(v));
				for (u64 j = i + 1, k = 0; j < mN; ++j, ++k)
					bit(ddi, k) = *iter++;

			}
			if (iter != c.end())
				throw RTE_LOC;

			co_await mMult.multiply(diff.cols() * 8,
				d.getSpan<u8>(), diff, diff, socket);

			iter = c.begin() + (mN - 1);
			for (u64 i = 1; i < mN; ++i)
			{
				u32 k, v;
				auto ddi = diff[i-1];
				copyBytes(k, ddi.subspan(0, sizeof(k)));
				ddi = ddi.subspan(sizeof(k));
				copyBytes(v, ddi.subspan(0, sizeof(v)));
				ddi = ddi.subspan(sizeof(v));

				for (u64 j = i + 1, k = 0; j < mN; ++j, ++k)
					*iter++ = bit(ddi, k);

				keys[i] = k ^ altKeys[i];
				values[i] = v;
			}
			if (iter != c.end())
				throw RTE_LOC;

			if (print)
			{
				BitVector C(c.size());
				co_await socket.send(coproto::copy(c));
				co_await socket.recv(C);
				C ^= c;
				auto b = C.begin();

				if (mPartyIdx)
				{
					for (u64 i = 0; i < mN; ++i)
					{
						for (u64 j = 0; j < i + 1; ++j)
						{
							std::cout << "  ";
						}
						for (u64 j = i + 1; j < mN; ++j)
						{
							std::cout << *b++ << " ";
						}
						std::cout << "\n";
					}
				}

			}

			MatrixView<u8> BB8((u8*)BB.data(), BB.size(), sizeof(BB[0]));
			co_await mMult.multiply(sizeof(values[0]) * 8,
				c.getSpan<u8>(), BB8, BB8, socket);

			if (print)
			{
				auto B = BB;
				co_await socket.send(coproto::copy(B));
				co_await socket.recv(B);
				if (mPartyIdx)
				{
					auto BIter = B.begin();
					auto BBIter = BB.begin();
					for (u64 i = 0; i < mN; ++i)
					{
						for (u64 j = 0; j < i + 1; ++j)
						{
							std::cout << "  ";
						}
						for (u64 j = i + 1; j < mN; ++j)
						{
							std::cout << (*BIter++ ^  *BBIter++) << " ";
						}
						std::cout << "\n";
					}
				}
			}

			auto BBIter = BB.begin();
			for (u64 i = 0; i < mN; ++i)
			{
				//values[i] = 0;
				for (u64 j = i + 1; j < mN; ++j)
					values[i] ^= *BBIter++;
			}

		}



	};
}