#include "libOTe_Tests/RingLpn_Tests.h"
#include <iostream>

int main(int argc, char** argv)
{
	osuCrypto::CLP cmd;
	cmd.parse(argc, argv);
	try
	{
		const auto run = [&](const char* name, auto test) {
			std::cout << name << std::flush;
			test(cmd);
			std::cout << " passed\n";
		};
		run("RingLpn_SupportFilter", osuCrypto::RingLpn_SupportFilter_test);
		run("RingLpn_Audit", osuCrypto::RingLpn_Audit_test);
		run("RingLpn_stationary", osuCrypto::RingLpn_stationary_test);
		run("RingLpn_ole", osuCrypto::RingLpn_ole_test);
	}
	catch (const std::exception& error)
	{
		std::cerr << " failed: " << error.what() << '\n';
		return 1;
	}
}
