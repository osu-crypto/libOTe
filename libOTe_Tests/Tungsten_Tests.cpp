
#include "Tungsten_Tests.h"
#include "libOTe/Tools/Tungsten/TungstenEncoder.h"
#include <iomanip>

using namespace oc;

namespace tests_libOTe
{
	void Tungsten_encode_basic_test(const oc::CLP& cmd)
	{
		auto k = cmd.getOr("k", 10);
		auto n = cmd.getOr("n", k * 2);
		auto bw = cmd.getOr("bw", 7);
		auto aw = cmd.getOr("aw", 5);
		auto sticky = cmd.getOr("ns", 1);
		auto skip = cmd.isSet("skip");

		Tungsten code;
		code.config(k, n, bw, aw, sticky);
		
		auto A = code.getA();
		auto B = code.getB();

		std::cout << "B\n" << B << std::endl << std::endl;
		std::cout << "A'\n" << code.getAPar() << std::endl << std::endl;
		std::cout << "A\n" << A << std::endl << std::endl;

		auto G = B * A;
		std::cout << "G\n" << G << std::endl;


		std::vector<u8> m0(k), m1(k), c0(n), a1(n);

		PRNG prng(ZeroBlock);
		prng.get(c0.data(), c0.size());

		auto a0 = c0;
		code.accumulate<u8>(a0);
		A.multAdd(c0, a1);
		//A.leftMultAdd(c0, a1);
		if (a0 != a1)
		{
			for (u64 i = 0; i < k; ++i)
				std::cout <<std::hex<<std::setw(2)<< std::setfill('0')<< int(a0[i]) << " ";
			std::cout << "\n";
			for (u64 i = 0; i < k; ++i)
				std::cout << std::hex << std::setw(2) << std::setfill('0') << int(a1[i]) << " ";
			std::cout << "\n";

			throw RTE_LOC;
		}

		G.multAdd(c0, m0);

		code.cirTransEncode<u8>(c0, m1);

		if (m0 != m1)
			throw RTE_LOC;

	}
}