#include "BaseOT_Tests.h"

#include <exception>
#include <iostream>

namespace
{
    template<typename Test>
    void run(const char* name, Test&& test)
    {
        test();
        std::cout << name << " passed\n";
    }
}

int main()
{
    try
    {
        run("SimplestOT", tests_libOTe::Bot_Simplest_Test);
        run("Masny-Rindal", tests_libOTe::Bot_MasnyRindal_Test);
        run("McRosRoy Ristretto F", tests_libOTe::Bot_McQuoidRR_Ristrestto_F_Test);
        run("McRosRoy Ristretto FM", tests_libOTe::Bot_McQuoidRR_Ristrestto_FM_Test);
        run("McRosRoy Montgomery F", tests_libOTe::Bot_McQuoidRR_Moeller_F_Test);
        run("McRosRoy Montgomery FM", tests_libOTe::Bot_McQuoidRR_Moeller_FM_Test);
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
