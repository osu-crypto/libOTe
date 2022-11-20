
#include "Tungsten_Tests.h"
#include "libOTe/Tools/Tungsten/TungstenEncoder.h"
#include <iomanip>
#include "cryptoTools/Common/Timer.h"
using namespace oc;

namespace tests_libOTe
{
	void Tungsten_encode_basic_test(const oc::CLP& cmd)
	{
		auto k = cmd.getOr("k", 10);
		auto n = cmd.getOr("n", k * 2);
		auto bw = cmd.getOr("bw", 7);
		auto aw = cmd.getOr("aw", 10);
		auto sticky = cmd.getOr("ns", 1);
		auto skip = cmd.isSet("skip");
		auto reuse = (Tungsten::RNG)cmd.getOr("rng", 2);
		bool permute = cmd.isSet("permute");

		bool v = cmd.isSet("v");

		if (reuse != Tungsten::RNG::gf128mul &&
			reuse != Tungsten::RNG::prng &&
			reuse != Tungsten::RNG::xoshiro256Plus
			)
			throw RTE_LOC;

		Tungsten code;
		code.config(k, n, bw, aw, reuse, permute, sticky);
		
		auto A = code.getA();
		auto B = code.getB();
		auto G = B * A;
		if (v)
		{
			std::cout << "B\n" << B << std::endl << std::endl;
			std::cout << "A'\n" << code.getAPar() << std::endl << std::endl;
			std::cout << "A\n" << A << std::endl << std::endl;
			std::cout << "G\n" << G << std::endl;
		}

		std::vector<u8> m0(k), m1(k), c0(n), a1(n);

		PRNG prng(ZeroBlock);
		prng.get(c0.data(), c0.size());

		auto a0 = c0;
		code.uniformAccumulate<u8>(a0);
		A.multAdd(c0, a1);
		//A.leftMultAdd(c0, a1);
		if (a0 != a1)
		{
			if (v)
			{

				for (u64 i = 0; i < k; ++i)
					std::cout <<std::hex<<std::setw(2)<< std::setfill('0')<< int(a0[i]) << " ";
				std::cout << "\n";
				for (u64 i = 0; i < k; ++i)
					std::cout << std::hex << std::setw(2) << std::setfill('0') << int(a1[i]) << " ";
				std::cout << "\n";
			}

			throw RTE_LOC;
		}

		G.multAdd(c0, m0);

		code.cirTransEncode<u8>(c0, m1);

		if (m0 != m1)
			throw RTE_LOC;

	} 

	void perm_bench(const oc::CLP& cmd)
	{
		auto n = cmd.getOr("n", 1 << cmd.getOr("nn", 20));
		auto binSize = 1 << cmd.getOr("mm", 10);
		auto tt = cmd.getOr("t",10);
		PRNG prng(ZeroBlock);
		SqrtPerm sp;
		Perm p;
		static constexpr int step = 8;

		AlignedUnVector<block> x(n);
		sp.init(n, binSize, prng);
		p.init(n / step, prng);
		Timer t, t2;
		sp.setTimer(t2);
		std::cout << n / binSize << " bins of size " << binSize << std::endl;
		t.setTimePoint("b");



		for(u64 i =0; i < tt; ++i)
			sp.apply<block>(x);
		auto b = t.setTimePoint("sp");
		std::vector<u64> diffs;
		for (u64 i = 0; i < tt; ++i)
		{
			span<std::array<block, step>> x8((std::array<block, step>*)x.data(), x.size() / step);
			p.apply<std::array<block, step>>(x8);
			//p.apply<block>(x);
			auto e = t2.setTimePoint("p");
			diffs.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(e - b).count());
			b = e;

		}
		t.setTimePoint("p");
		std::cout << t << std::endl;
		std::cout << t2 << std::endl;
		for (u64 i = 0; i < tt; ++i)
			std::cout << diffs[i] / double(n) << " " << diffs[i] << std::endl;
		

	}


	void Tungsten_encode_basic_bench(const oc::CLP& cmd)
	{
		auto k = cmd.getOr("k", 1<< cmd.getOr("kk", 10));
		auto n = cmd.getOr("n", k * 2);
		auto bw = cmd.getOr("bw", 5);
		auto aw = cmd.getOr("aw", 10);
		auto sticky = cmd.getOr("ns", 1);
		auto reuse = (Tungsten::RNG)cmd.getOr("rng", 2);
		auto skip = cmd.isSet("skip");
		auto permute = cmd.getOr("permute",0);
		auto tt = cmd.getOr("trials", 1);

		bool v = cmd.isSet("v");

		if (reuse != Tungsten::RNG::gf128mul &&
			reuse != Tungsten::RNG::prng &&
			reuse != Tungsten::RNG::xoshiro256Plus
			)
			throw RTE_LOC;

		u64 step = 1 << cmd.getOr("step", 14);

		if (n % step)
			throw RTE_LOC;
		if (cmd.isSet("or"))
		{
			Tungsten code;
			code.config(k, n, bw, aw, reuse, permute, sticky);
			code.mAccumulatorWeight = cmd.getOr("aaw", 4);
			AlignedUnVector<block> m1(k), c0(n);

			oc::Timer timer;
			code.setTimer(timer);
			for (auto t : rng(tt))
			{
				code.cirTransEncode<block>(c0, m1);
			}
			std::cout << timer << std::endl;
		}
		else
		{

			//Tungsten code;
			//code.config(k, n, bw, aw, reuse, permute, sticky);
			//code.mAccumulatorWeight = cmd.getOr("aaw", 4);
			AlignedUnVector<block> m1(k)/*, c0(n)*/;
		
			TungstenAccumulator code(TungstenBinPermuter{ (u64)n, (u64)bw });
			oc::Timer timer;
			code.mNext.setTimer(timer);
			//code.setTimer(timer);
			std::vector<block> c0(step, ZeroBlock);
			c0[0] = OneBlock;
			for (auto t : rng(tt))
			{
				code.reset();
				timer.setTimePoint("reset");
				for (u64 j = 0; j < n; j += step)
				{
					span<block> buff(c0.data(), step);
					code.update(buff);
				}

				timer.setTimePoint("acc");

				code.finalize(m1);

				timer.setTimePoint("expand");
				//code.cirTransEncode<block>(c0, m1);
			}


			if(!cmd.isSet("quiet"))
				std::cout << timer << std::endl;
		}
	}


}