#include "BaseOT_Tests.h"

#include <cryptoTools/Common/TestCollection.h>

int main()
{
    osuCrypto::TestCollection tests;
    tests.add("SimplestOT", tests_libOTe::Bot_Simplest_Test);
    tests.add("Masny-Rindal", tests_libOTe::Bot_MasnyRindal_Test);
    tests.add("Badrinarayanan-Masny-Mukherjee", tests_libOTe::Bot_BadMasMuk_Test);
    tests.add("McRosRoy Ristretto F", tests_libOTe::Bot_McQuoidRR_Ristrestto_F_Test);
    tests.add("McRosRoy Ristretto FM", tests_libOTe::Bot_McQuoidRR_Ristrestto_FM_Test);
    tests.add("McRosRoy Montgomery F", tests_libOTe::Bot_McQuoidRR_Moeller_F_Test);
    tests.add("McRosRoy Montgomery FM", tests_libOTe::Bot_McQuoidRR_Moeller_FM_Test);
    return tests.runAll() == osuCrypto::TestCollection::Result::passed ? 0 : 1;
}
