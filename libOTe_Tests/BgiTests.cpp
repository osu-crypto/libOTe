#include "BgiTests.h"
#include "libOTe/DPF/BgiGenerator.h"
#include "libOTe/DPF/BgiEvaluator.h"
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>

using namespace osuCrypto;

void Bgi_keyGen_128_test()
{
	std::vector<block> vv{ CCBlock, OneBlock, AllOneBlock, AllOneBlock };

	u64 depth = 128;
	u64 groupBlkSize = 1;
	PRNG prng(ZeroBlock);

	std::vector<block> k0(depth + 1), k1(depth + 1);
	std::vector<block> g0(groupBlkSize), g1(groupBlkSize);

    block val = prng.get<block>();
	block idx = prng.get<block>();
	span<u8> ib((u8*)&idx, sizeof(block));

	BgiGenerator::keyGen(ib, val, toBlock(1), k0, g0, k1, g1);

	block target = idx;
	for (u64 j = 0; j < 4; ++j)
	{
		span<u8> jb((u8*)&target, sizeof(block));
		auto b0 = BgiEvaluator::evalOne(jb, k0, g0);
		auto b1 = BgiEvaluator::evalOne(jb, k1, g1);
        auto v = b0 ^ b1;
        auto e = (j == 0) ? val : ZeroBlock;



		if (eq(e,v)== false)
		{
			std::cout << "\n\n ======================= try  cur " << j << " " << b0 << " ^ " << b1 << " = " << v << " != "<<e<<" ====================================\n\n\n";
			//throw std::runtime_error(LOCATION);
		}

		target = prng.get<block>();
	}
}

void Bgi_keyGen_test()
{
	std::vector<block> vv{ CCBlock, OneBlock, AllOneBlock, AllOneBlock };

	u64 depth = 3;
	u64 groupBlkSize = 1;
	u64 domain = (1ull << depth) *  groupBlkSize;
	PRNG prng(ZeroBlock);
    PRNG::AnyPOD a = prng.get();
    block val = prng.get();
    for (u64 seed = 0; seed < 2; ++seed)
	{
		for (u64 ii = 0; ii < 2; ++ii)
		{
			auto i = prng.get<u64>() % domain;
			std::vector<block> k0(depth + 1), k1(depth + 1);
			std::vector<block> g0(groupBlkSize), g1(groupBlkSize);

			span<u8> ib((u8*)&i, sizeof(u64));

			BgiGenerator::keyGen(ib, val, toBlock(seed), k0, g0, k1, g1);


			for (u64 j = 0; j < domain; ++j)
			{
				span<u8> jb((u8*)&j, (log2ceil(domain) + 7) / 8);
				auto b0 = BgiEvaluator::evalOne(jb, k0, g0);
				auto b1 = BgiEvaluator::evalOne(jb, k1, g1);

                block exp = (i == j) ? val : ZeroBlock;
				if (neq(exp, b0 ^ b1))
				{
					std::cout << "\n\n ======================= try " << seed << " " << ii << " target " << i << " cur " << j << " "
                        << b0 << " ^ " << b1 << " = " << (b0 ^ b1) << " != "<<exp<<" ====================================\n\n\n";
					throw std::runtime_error(LOCATION);
				}
			}
		}
	}
}

//void Bgi_PIR_test()
//{
//
//	BgiGenerator client;
//	BgiEvaluator s0, s1;
//	u64 depth = 5, groupSize = 1;
//	auto domain = (1ull << depth) * groupSize * 128;
//	auto tt = std::min<u64>(1000, domain);
//	std::vector<block> vv(domain);
//
//	// fill "database" with increasind block numbers up to 2^depth
//	for (u64 i = 0; i < vv.size(); ++i)
//	{
//		vv[i] = toBlock(i);
//	}
//
//	client.init(depth, groupSize);
//	s0.init(depth, groupSize);
//	s1.init(depth, groupSize);
//
//	IOService ios;
//
//	auto thrd = std::thread([&]() {
//
//		Endpoint srv0Ep(ios, "localhost", EpMode::Client, "srv0");
//		Endpoint srv1Ep(ios, "localhost", EpMode::Client, "srv1");
//		auto chan0 = srv0Ep.addChannel("chan");
//		auto chan1 = srv1Ep.addChannel("chan");
//
//		for (u64 i = 0; i < tt; ++i)
//		{
//			s0.serve(chan0, vv);
//			s1.serve(chan1, vv);
//		}
//
//	});
//
//	Endpoint srv0Ep(ios, "localhost", EpMode::Server, "srv0");
//	Endpoint srv1Ep(ios, "localhost", EpMode::Server, "srv1");
//	auto chan0 = srv0Ep.addChannel("chan");
//	auto chan1 = srv1Ep.addChannel("chan");
//	PRNG prng(ZeroBlock);
//
//	std::vector<block> rets(tt);
//	std::vector<u64> idxs(tt);
//	for (u64 i = 0; i < tt; ++i)
//	{
//		idxs[i] = prng.get<u64>() % domain;
//		rets[i] = client.query(idxs[i], chan0, chan1, toBlock(i));
//	}
//
//	thrd.join();
//
//	for (u64 i = 0; i < tt; ++i)
//	{
//		if (neq(rets[i], vv[idxs[i]]))
//		{
//			std::cout << i << "  " << rets[i] << std::endl;
//			throw std::runtime_error(LOCATION);
//		}
//	}
//}
//
//void Bgi_FullDomain_test()
//{
//	std::vector<std::array<u64, 2>> params{ {2,1}, {2, 6}, {5, 1}, {5, 5 }, {5,8} };
//
//	for (auto param : params)
//	{
//
//		u64 depth = param[0], groupBlkSize = param[1];
//		u64 domain = (1ull << depth) * groupBlkSize * 128;
//		u64 trials = 10;
//
//		std::vector<block> data(domain);
//		for (u64 i = 0; i < data.size(); ++i)
//			data[i] = toBlock(i);
//
//
//
//		std::vector<block> k0(depth + 1), k1(depth + 1);
//		std::vector<block> g0(groupBlkSize), g1(groupBlkSize);
//
//		PRNG prng(ZeroBlock);
//		for (u64 i = 0; i < trials; ++i)
//		{
//			//i = 1024;
//
//			for (u64 j = 0; j < 2; ++j)
//			{
//				auto idx = (i + j * prng.get<int>()) % domain;
//				BgiGenerator::keyGen(idx, toBlock(idx), k0, g0, k1, g1);
//
//				auto b0 = BgiEvaluator::fullDomain(data, k0, g0);
//				auto b1 = BgiEvaluator::fullDomain(data, k1, g1);
//
//				if (neq(b0 ^ b1, data[idx]))
//				{
//					//auto vv = bv0 ^ bv1;
//					std::cout << "target " << data[idx] << " " << idx <<
//						"\n  " << (b0^b1) << "\n = " << b0 << " ^ " << b1 <<
//						//"\n   weight " << vv.hammingWeight() <<
//						//"\n vv[target] = " << vv[idx] <<
//						std::endl;
//					throw std::runtime_error(LOCATION);
//				}
//
//			}
//		}
//	}
//}
//
//


void Bgi_FullDomain_iterator_test()
{
	std::vector<std::array<u64, 2>> params{ { 2,1 },{ 2, 6 },{ 5, 1 },{ 5, 5 } };

	for (auto param : params)
	{

		u64 depth = param[0], groupBlkSize = param[1];
		u64 domain = (1ull << depth) * groupBlkSize * 128;
		u64 trials = 10;

		std::vector<block> data(domain);
		for (u64 i = 0; i < data.size(); ++i)
			data[i] = toBlock(i);



		std::vector<block> k0(depth + 1), k1(depth + 1);
		std::vector<block> g0(groupBlkSize), g1(groupBlkSize);

		PRNG prng(ZeroBlock);
        block val = prng.get<block>();
		for (u64 i = 0; i < trials; ++i)
		{
			//i = 1024;

			for (u64 j = 0; j < 2; ++j)
			{
				auto idx = (i + j * prng.get<u64>()) % domain;
				BgiGenerator::keyGen(idx, val, toBlock(idx), k0, g0, k1, g1);


				BgiEvaluator::SingleKey gen0;
				BgiEvaluator::SingleKey gen1;


				gen0.init(k0, g0);
				gen1.init(k1, g1);

				u64 dd = 0;
				std::vector<u8> d0(domain), d1(domain);
				block s0 = ZeroBlock, s1 = ZeroBlock;

				while (gen0.hasMore())
				{
					auto r0 = gen0.yeild();
					for (auto& p : r0) memcpy(d0.data() + p.first, p.second.data(), p.second.size());

					for (auto& p : r0)
					{
						dd += p.second.size();
						for (u64 j = 0; j < p.second.size(); ++j)
						{
							s0 = s0 ^ (data[p.first + j] & zeroAndAllOne[p.second[j]]);
						}
					}
				}

				while (gen1.hasMore()) {
					auto r1 = gen1.yeild();
					for (auto& p : r1) memcpy(d1.data() + p.first, p.second.data(), p.second.size());
					for (auto& p : r1)
						for (u64 j = 0; j < p.second.size(); ++j)
							s1 = s1 ^ (data[p.first + j] & zeroAndAllOne[p.second[j]]);


				}
				if (dd != domain) throw std::runtime_error(LOCATION);


				//auto b0 = BgiEvaluator::fullDomain(data, k0, g0);
				//auto b1 = BgiEvaluator::fullDomain(data, k1, g1);

				////std::cout <<"b " << b0 << " " << b1 << " " << (b0 ^ b1) << std::endl;

				//if (neq(b0, s0))
				//	throw std::runtime_error(LOCATION);
				//if (neq(b1, s1))
				//	throw std::runtime_error(LOCATION);

				//if (neq(b0 ^ b1, data[idx]))
				//{
				//	//auto vv = bv0 ^ bv1;
				//	std::cout << "target b " << data[idx] << " " << idx <<
				//		"\n  " << (b0^b1) << "\n = " << b0 << " ^ " << b1 <<
				//		//"\n   weight " << vv.hammingWeight() <<
				//		//"\n vv[target] = " << vv[idx] <<
				//		std::endl;
				//	throw std::runtime_error(LOCATION);
				//}
				//if (neq(s0 ^ s1, data[idx]))
				//{
				//	std::cout << "target s " << data[idx] << " " << idx <<
				//		"\n  " << (s0^s1) << "\n = " << s0 << " ^ " << s1 <<
				//		std::endl;
				//	throw std::runtime_error(LOCATION);
				//}

			}
		}
	}
}




void Bgi_FullDomain_multikey_test()
{
	std::vector<std::array<u64, 2>> params{ { 2,1 },{ 2, 6 },{ 5, 1 },{ 5, 5 } };

	for (auto param : params)
	{
		u64 depth = param[0], groupBlkSize = param[1];
		u64 domain = (1ull << depth) * groupBlkSize;
		u64 numKeys = 13;

		std::vector<std::vector<block>> k0(numKeys), k1(numKeys);
		std::vector<std::vector<block>> g0(numKeys), g1(numKeys);
		//std::vector<std::vector<block>> d0(numKeys), d1(numKeys);


		PRNG prng(ZeroBlock);
        block val = prng.get<block>();
		std::vector<u64> idx(numKeys);

		for (u64 k = 0; k < numKeys; ++k)
		{
			idx[k] = prng.get<u64>() % domain;

			k0[k].resize(depth + 1);
			k1[k].resize(depth + 1);
			g0[k].resize(groupBlkSize);
			g1[k].resize(groupBlkSize);
			//d0[k].resize(domain);
			//d1[k].resize(domain);

			BgiGenerator::keyGen(idx[k], val, toBlock(k), k0[k], g0[k], k1[k], g1[k]);

		//	BgiEvaluator::SingleKey gen0;
		//	BgiEvaluator::SingleKey gen1;

		//	gen0.init(k0[k], g0[k]);
		//	gen1.init(k1[k], g1[k]);

		//	block s0 = ZeroBlock, s1 = ZeroBlock;

		//	while (gen0.hasMore())
		//	{
		//		auto r0 = gen0.yeild();
		//		for (auto& p : r0) memcpy(d0[k].data() + p.first, p.second.data(), p.second.size());
		//		for (auto& p : r0)
		//			for (u64 j = 0; j < p.second.size(); ++j)
		//				s0 = s0 ^ (data[p.first + j] & zeroAndAllOne[p.second[j]]);

		//		auto r1 = gen1.yeild();
		//		for (auto& p : r1) memcpy(d1[k].data() + p.first, p.second.data(), p.second.size());
		//		for (auto& p : r1)
		//			for (u64 j = 0; j < p.second.size(); ++j)
		//				s1 = s1 ^ (data[p.first + j] & zeroAndAllOne[p.second[j]]);
		//	}



		}

		BgiEvaluator::MultiKey mk0, mk1;
		mk0.init(k0, g0);
		mk1.init(k1, g1);


		for (u64 i = 0; i < domain; ++i)
		{
			auto bits0 = mk0.yeild();
			auto bits1 = mk1.yeild();

			if (bits0.size() != numKeys) throw std::runtime_error(LOCATION);
			if (bits1.size() != numKeys) throw std::runtime_error(LOCATION);

			for (u64 k = 0; k < numKeys; ++k)
			{
                if (eq(bits0[k], ZeroBlock))
                    throw RTE_LOC;
                if (eq(bits1[k], ZeroBlock))
                    throw RTE_LOC;

                if (i == idx[k])
                {
                    if (neq(bits0[k] ^ bits1[k], val))
                    {
                        std::cout << "bad on index " << std::endl;
                        throw RTE_LOC;
                    }

                    //if(!k)
                    //    std::cout << Color::Green;
                }
                else
                {
                    if (neq(bits0[k] ^ bits1[k], ZeroBlock))
                    {
                        std::cout << "--------------\n" << i << " " << k << std::endl;
                        std::cout << bits0[k] << " ^ " << bits1[k] << std::endl;
                        std::cout << (bits0[k] ^ bits1[k]) << std::endl;
                        throw RTE_LOC;
                    }
                }
				//if (neq(d0[k][i], bits0[k])) throw std::runtime_error(LOCATION);
				//if (neq(d1[k][i], bits1[k])) throw std::runtime_error(LOCATION);

                //if (!k)
                //{
                //    std::cout << (bits0[k] ^ bits1[k]) << Color::Default << std::endl;

                //}
			}
		}

	}
}



