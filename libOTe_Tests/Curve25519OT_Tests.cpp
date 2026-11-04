#include "BaseOT_Tests.h"

#include <cryptoTools/Common/TestCollection.h>

#include <exception>
#include <iostream>

namespace
{
    template<typename Test>
    void run(const char* name, Test&& test)
    {
        // A protocol that is not enabled in this build is a notice, not a
        // failure, matching how the main unit test runner treats skips.
        try
        {
            test();
            std::cout << name << " passed\n";
        }
        catch (const osuCrypto::UnitTestSkipped& skip)
        {
            std::cout << name << " skipped: " << skip.what() << "\n";
        }
    }
}

int main()
{
    try
    {
        run("SimplestOT", tests_libOTe::Bot_Simplest_Test);
        run("Masny-Rindal", tests_libOTe::Bot_MasnyRindal_Test);
        run("Badrinarayanan-Masny-Mukherjee", tests_libOTe::Bot_BadMasMuk_Test);
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
