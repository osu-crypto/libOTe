#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/TestCollection.h"
#include "libOTe_Tests/LogVole_Tests.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#include <iostream>
#include "libOTe_Tests/UInt_Tests.h"
int main(int argc, char** argv)
{
    osuCrypto::CLP cmd(argc, argv);
    osuCrypto::TestCollection tests;
#define ADD_TEST(suite, name) tests.add("LogVole_" #suite "_" #name, LogVole_##suite##_##name);
#define ADD_EXTENDED(suite, name) tests.addExtended("LogVole_" #suite "_" #name, LogVole_##suite##_##name);
    LIBOTE_LOGVOLE_TESTS(ADD_TEST)
    LIBOTE_LOGVOLE_EXTENDED_TESTS(ADD_EXTENDED)
#undef ADD_TEST
#undef ADD_EXTENDED
    tests.add("UInt_Basics_Test", UInt_Basics_Test);
    tests.add("UInt_Bitwise_Test", UInt_Bitwise_Test);
    tests.add("UInt_Shifts_Test", UInt_Shifts_Test);
    tests.add("UInt_AddSub_Test", UInt_AddSub_Test);
    tests.add("UInt_MulU64_Test", UInt_MulU64_Test);
    tests.add("UInt_MulFull_Test", UInt_MulFull_Test);
    tests.add("UInt_DivBasic_Test", UInt_DivBasic_Test);
    tests.add("UInt_DivMultilimb_Test", UInt_DivMultilimb_Test);
    tests.add("UInt_Stream_Test", UInt_Stream_Test);
    tests.add("UInt_Conversions_Test", UInt_Conversions_Test);
    tests.add("UInt_WordArithmetic_Test", UInt_WordArithmetic_Test);
    const auto result = tests.runIf(cmd);
    return result == osuCrypto::TestCollection::Result::passed ? 0 : 1;
}
