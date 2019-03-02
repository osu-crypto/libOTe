#pragma once
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include <boost/multiprecision/cpp_int.hpp>

namespace osuCrypto
{

	class BgiPirServer
	{
	public:
		typedef boost::multiprecision::uint128_t uint128_t;

		u64 mKDepth, mGroupBlkSize;

		void init(u64 depth, u64 groupByteSize);

		void serve(Channel chan, span<block> data);

		static u8 evalOne(span<u8> idx, span<block> k, span<block> g, block* = nullptr, block* = nullptr, u8* tt = nullptr);
		static u8 evalOne(uint128_t idx, span<block> k, span<block> g, block* = nullptr, block* = nullptr, u8* tt = nullptr);
		static block traversePath(u64 depth, uint128_t idx, span<block> k);
		static block traverseOne(const block &s, const block&k, const osuCrypto::u8 &keep, bool print = false);
		static block fullDomainNaive(span<block> data, span<block> k, span<block> g);
		static block fullDomain(span<block> data, span<block> k, span<block> g);
		//static BitVector BgiPirServer_bv;



		struct FullDomainGenerator
		{
			span<block> k, g;
			u64 kDepth;
			std::vector<block> prev, next;
			bool mHasMore;


			struct State
			{
				State()
					: kIdx(0)
					, d(0)
				{}

				u64 kIdx, d, dEnd;
				std::vector<block> expandedS;// (8 * g.size());
				std::vector<std::pair<u64, span<u8>>> mByteView;

				std::vector<std::array<block, 8>> ss;

				std::array<AES, 2> aes;

				std::vector<std::array<block, 8>> temp, enc;
				std::vector<std::array<block, 2>> t_cw;

			};

			State state;

			void init(span<block> kk, span<block> gg);



			u64 size();
			bool hasMore() { return mHasMore; }
			span<std::pair<u64, span<u8>>> yeild();
		};

		struct MultiKey
		{
			void init(span<std::vector<block>> kk, span<std::vector<block>> gg);
			void init(u64 numKeys, u64 kSize, u64 gSize);
            void setKey(u64 i, span<block>k, span<block> g);
            void setKey(u64 i, span<block>kg);
            void setKeys(MatrixView<block>kg);

			span<u8> yeild();

			std::array<AES, 2> aes;




			u64 mD, mLeafIdx, mGIdx, mBIdx, mNumKeysRound8, mDEnd;
			Matrix<u8> mBuff;
			Matrix<block> mS, mK, mG;
			Matrix<std::array<block, 2>> mTcw;



			std::vector<block> getK(u64 i);
		};
	};

}
