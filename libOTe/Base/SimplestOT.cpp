#include "SimplestOT.h"

#include <tuple>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#ifdef ENABLE_SIMPLESTOT

#include "libOTe/Tools/DefaultCurve.h"

namespace osuCrypto
{
	task<> SimplestOT::receive(
		const BitVector& choices,
		span<block> msg,
		PRNG& prng,
		Socket& chl)
	{
		using namespace DefaultCurve;
		Curve curve;
		MC_BEGIN(task<>, this, &choices, msg, &prng, &chl,
			n = u64{},
			buff = std::vector<u8>{},
			comm = std::array<u8, RandomOracle::HashSize>{},
			seed = block{},
			b = std::vector<Number>{},
			B = std::array<Point, 2>{},
			A = Point{}
		);

		n = msg.size();

		buff.resize(Point::size + RandomOracle::HashSize * mUniformOTs);
		MC_AWAIT(chl.recv(buff));
		Curve{};


		A.fromBytes(buff.data());

		if (mUniformOTs)
			memcpy(&comm, buff.data() + Point::size, RandomOracle::HashSize);

		buff.resize(Point::size * n);

		b.reserve(n);
		for (u64 i = 0; i < n; ++i)
		{
			b.emplace_back(prng);
			B[0] = Point::mulGenerator(b[i]);
			B[1] = A + B[0];

			B[choices[i]].toBytes(&buff[Point::size * i]);
		}

		MC_AWAIT(chl.send(std::move(buff)));

		if (mUniformOTs)
		{
			MC_AWAIT(chl.recv(seed));

			RandomOracle ro;
			std::array<u8, RandomOracle::HashSize> comm2;
			ro.Update(seed);
			ro.Final(comm2);

			if (comm != comm2)
				throw std::runtime_error("bad decommitment " LOCATION);
		}

		Curve{};
		for (u64 i = 0; i < n; ++i)
		{
			B[0] = A * b[i];
			RandomOracle ro(sizeof(block));
			ro.Update(B[0]);
			ro.Update(i);
			if (mUniformOTs) ro.Update(seed);
			ro.Final(msg[i]);
		}

		MC_END();
	}

	task<> SimplestOT::send(
		span<std::array<block, 2>> msg,
		PRNG& prng,
		Socket& chl)
	{
		using namespace DefaultCurve;
		Curve{};


		MC_BEGIN(task<>, this, msg, &prng, &chl,
			n = u64{},
			a = Number{},
			A = Point{},
			B = Point{},
			buff = std::vector<u8>{},
			seed = block{}
		);

		Curve{};
		n = msg.size();

		a.randomize(prng);
		A = Point::mulGenerator(a);

		buff.resize(Point::size + RandomOracle::HashSize * mUniformOTs);
		A.toBytes(buff.data());

		if (mUniformOTs)
		{
			// commit to the seed
			seed = prng.get<block>();
			std::array<u8, RandomOracle::HashSize> comm;
			RandomOracle ro;
			ro.Update(seed);
			ro.Final(comm);
			memcpy(buff.data() + Point::size, comm.data(), comm.size());
		}


		MC_AWAIT(chl.send(std::move(buff)));

		buff.resize(Point::size * n);
		MC_AWAIT(chl.recv(buff));

		if (mUniformOTs)
		{
			// decommit to the seed now that we have their messages.
			MC_AWAIT(chl.send(std::move(seed)));
		}

		Curve{};
		A *= a;
		for (u64 i = 0; i < n; ++i)
		{
			B.fromBytes(&buff[Point::size * i]);

			B *= a;
			RandomOracle ro(sizeof(block));
			ro.Update(B);
			ro.Update(i);
			if (mUniformOTs) ro.Update(seed);
			ro.Final(msg[i][0]);

			B -= A;
			ro.Reset();
			ro.Update(B);
			ro.Update(i);
			if (mUniformOTs) ro.Update(seed);
			ro.Final(msg[i][1]);
		}


		MC_END();
	}
}
#endif
#ifdef ENABLE_SIMPLESTOT_ASM
extern "C"
{
#include "SimplestOT/ot_sender.h"
#include "SimplestOT/ot_receiver.h"
#include "SimplestOT/ot_config.h"
#include "SimplestOT/cpucycles.h"
#include "SimplestOT/randombytes.h"
}
namespace osuCrypto
{

	namespace
	{
		rand_source makeRandSource(PRNG& prng)
		{
			rand_source rand;
			rand.get = [](void* ctx, unsigned char* dest, unsigned long long length) {
				PRNG& prng = *(PRNG*)ctx;
				prng.get(dest, length);
			};
			rand.ctx = &prng;

			return rand;
		}

		//std::string hexPrnt(span<u8> d)
		//{
		//	std::stringstream ss;
		//	for (auto dd : d)
		//	{
		//		ss << std::setw(2) << std::setfill('0') << std::hex
		//			<< int(dd);
		//	}
		//	return ss.str();
		//}

		//std::mutex _gmtx;

		struct SendState
		{
			SENDER sender;

			u8 S_pack[SIMPLEST_OT_PACK_BYTES];
			u8 Rs_pack[4 * SIMPLEST_OT_PACK_BYTES];
			u8 keys[2][4][SIMPLEST_OT_HASHBYTES];
			rand_source rand;

			SendState()
			{

				memset(&sender, 0, sizeof(sender));
				memset(&S_pack, 0, sizeof(S_pack));
				memset(&Rs_pack, 0, sizeof(Rs_pack));
				memset(&keys, 0, sizeof(keys));
			}

			SendState(SendState&& o) = delete;

			std::vector<u8> init(PRNG& prng)
			{
				//std::lock_guard<std::mutex>l(_gmtx);
				//std::cout << "S0 " << hash() << std::endl;
				rand = makeRandSource(prng);
				//std::cout << "S1 " << hash() << std::endl;
				sender_genS(&sender, S_pack, rand);
				//std::cout << "S2 " << hash() << std::endl;
				//_gMtx.unlock();
				return { (u8*)S_pack, (u8*)S_pack + sizeof(S_pack) };
			}

			span<u8> recv4()
			{
				return { (u8*)Rs_pack, (u8*)Rs_pack + sizeof(Rs_pack) };
			}


			void gen4(u64 i, span<std::array<block, 2>> msg)
			{

				//std::lock_guard<std::mutex>l(_gmtx);
				sender_keygen(&sender, Rs_pack, keys);

				auto min = std::min<u32>(4, msg.size() - i);
				for (u32 j = 0; j < min; j++)
				{
					memcpy(&msg[i + j][0], keys[0][j], sizeof(block));
					memcpy(&msg[i + j][1], keys[1][j], sizeof(block));
				}
			}
		};

		struct RecvState
		{
			RECEIVER receiver;

			u8 Rs_pack[4 * SIMPLEST_OT_PACK_BYTES];
			u8 keys[4][SIMPLEST_OT_HASHBYTES];
			u8 cs[4];
			rand_source rand;

			RecvState()
			{
				memset(&receiver, 0, sizeof(RECEIVER));
				memset(&Rs_pack, 0, sizeof(Rs_pack));
				memset(&keys, 0, sizeof(keys));
				memset(&cs, 0, sizeof(cs));
			}

			RecvState(RecvState&& o) = delete;

			block hash()
			{
				RandomOracle ro(sizeof(block));
				ro.Update(receiver);
				ro.Update(Rs_pack);
				ro.Update(keys);
				ro.Update(cs);

				block ret;
				ro.Final(ret);
				return ret;
			}

			span<u8> recvData()
			{
				memset(&receiver, 0, sizeof(RECEIVER));
				memset(&Rs_pack, 0, sizeof(Rs_pack));
				memset(&keys, 0, sizeof(keys));
				memset(&cs, 0, sizeof(cs));
				return { receiver.S_pack, sizeof(receiver.S_pack) };
			}

			void init(PRNG& prng)
			{
				//std::lock_guard<std::mutex>l(_gmtx);
				receiver_procS(&receiver);
				receiver_maketable(&receiver);
				rand = makeRandSource(prng);
			}

			std::vector<u8> send4(u64 i, const BitVector& choices)
			{
				//std::lock_guard<std::mutex>l(_gmtx);
				auto min = std::min<u32>(4, choices.size() - i);

				for (u32 j = 0; j < min; j++)
					cs[j] = choices[i + j];

				receiver_rsgen(&receiver, Rs_pack, cs, rand);

				return { (u8*)Rs_pack, (u8*)Rs_pack + sizeof(Rs_pack) };
			}

			void gen4(u64 i, span<block> msg)
			{
				//std::lock_guard<std::mutex>l(_gmtx);
				auto min = std::min<u32>(4, msg.size() - i);

				receiver_keygen(&receiver, keys);

				for (u32 j = 0; j < min; j++)
					memcpy(&msg[i + j], keys[j], sizeof(block));
			}
		};

		template<typename State>
		struct AlginedState
		{
			State* ptr = nullptr;
			AlginedState()
			{
				ptr = new (AlignedAllocator<char>{}.aligned_malloc(sizeof(State), 32)) State;
			}
			AlginedState(AlginedState&& o)
				: ptr(std::exchange(o.ptr, nullptr))
			{}

			~AlginedState()
			{
				if (ptr)
				{
					ptr->~State();
					AlignedAllocator<char>{}.aligned_free(ptr);
				}
			}

			State* operator->()
			{
				return ptr;
			}
		};

	}


	void AsmSimplestOTTest()
	{

		for (u64 j = 0; j < 1; ++j)
		{


			u64 n = 16;

			BitVector choices(n);
			RecvState recv;
			SendState send;
			std::vector<std::array<block, 2>> sMsg(n);
			std::vector<block> rMsg(n);

			PRNG sprng(ZeroBlock);

			auto sd = send.init(sprng);
			//std::cout << "send 1 " << hexPrnt(sd) << std::endl;
			auto rd = recv.recvData();

			if (sd.size() != rd.size())
				throw RTE_LOC;
			memcpy(rd.data(), sd.data(), sd.size());

			// recv
			PRNG rprng(ZeroBlock);
			recv.init(rprng);

			for (auto i = 0ull; i < sMsg.size(); i += 4)
			{
				sd = recv.send4(i, choices);
				rd = send.recv4();


				if (sd.size() != rd.size())
					throw RTE_LOC;
				memcpy(rd.data(), sd.data(), sd.size());

				//std::cout << "send 2 " << i << std::endl;
				send.gen4(i, sMsg);

				//MC_AWAIT(chl.send(sd));
				//std::cout << "recv 3 " << i << std::endl;
				recv.gen4(i, rMsg);
				//std::cout << "recv 4 " << i << std::endl;
			}
		}
	}

	//void AsmSimplestOT::receive(
	//	const BitVector& choices,
	//	span<block> msg,
	//	PRNG& prng,
	//	Channel& chl)
	//{
	//	RecvState rs;
	//	auto buff = rs.recvData();
	//	chl.recv(buff);
	//	//std::cout << "Recv 1 " << hexPrnt(buff) << std::endl;
	//	rs.init(prng);

	//	for (u32 i = 0; i < msg.size(); i += 4)
	//	{
	//		auto sendData = rs.send4(i, choices);
	//		chl.asyncSend(std::move(sendData));
	//		rs.gen4(i, msg);
	//	}

	//}


	task<> AsmSimplestOT::receive(
		const BitVector& choices,
		span<block> msg,
		PRNG& prng,
		Socket& chl)
	{

		MC_BEGIN(task<>, this, &choices, msg, &prng, &chl,
			rs = AlginedState<RecvState>(),
			i = u64{},
			rd = span<u8>{},
			sd = std::vector<u8>{}
		);

		//prng.SetSeed(ZeroBlock);
		//std::cout << "recv 0" << std::endl;
		rd = rs->recvData();
		MC_AWAIT(chl.recv(rd));
		//std::cout << "recv 1 " << hexPrnt(rd) << std::endl;
		rs->init(prng);
		//std::cout << "recv 2" << std::endl;

		for (i = 0; i < msg.size(); i += 4)
		{
			sd = rs->send4(i, choices);
			MC_AWAIT(chl.send(sd));
			//std::cout << "recv 3 " << i << std::endl;
			rs->gen4(i, msg);
			//std::cout << "recv 4 " << i << std::endl;
		}
		MC_END();
	}

	task<> AsmSimplestOT::send(
		span<std::array<block, 2>> msg,
		PRNG& prng,
		Socket& chl)
	{
		MC_BEGIN(task<>, this, msg, &prng, &chl,
			ss = AlginedState<SendState>(),
			i = u64{},
			rd = span<u8>{},
			sd = std::vector<u8>{}
		);

		//prng.SetSeed(ZeroBlock);

		//std::cout << "send 0" << std::endl;
		sd = ss->init(prng);
		//std::cout << "send 1 " << hexPrnt(sd) << std::endl;
		MC_AWAIT(chl.send(sd));

		for (i = 0; i < msg.size(); i += 4)
		{
			rd = ss->recv4();
			MC_AWAIT(chl.recv(rd));
			//std::cout << "send 2 " << i << std::endl;
			ss->gen4(i, msg);
			//std::cout << "send 3 " << i << std::endl;
		}
		MC_END();
	}

	//void AsmSimplestOT::send(
	//	span<std::array<block, 2>> msg,
	//	PRNG& prng,
	//	Channel& chl)
	//{

	//	SendState ss;
	//	auto sendData = ss.init(prng);
	//	chl.asyncSend(std::move(sendData));

	//	for (u32 i = 0; i < msg.size(); i += 4)
	//	{
	//		auto buff = ss.recv4();
	//		chl.recv(buff);

	//		ss.gen4(i, msg);
	//	}
	//}
}
#endif
