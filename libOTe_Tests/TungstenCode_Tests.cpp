#include "cryptoTools/Common/CLP.h"
#include "libOTe/Tools/TungstenCode/TungstenCode.h"
#include "cryptoTools/Crypto/PRNG.h"

using namespace oc;
using namespace oc::experimental;
namespace tests_libOTe
{
    void TungstenCode_encode_test(const oc::CLP& cmd)
    {

        auto K = cmd.getManyOr<u64>("k", { 256, 3333 });
        auto R = cmd.getManyOr<double>("R", { 2.0 });

        for (auto k : K) for (auto r : R) for (auto sys : { false, true })
        {
            u64 n = k * r;

            TungstenCode encoder;

            encoder.config(k, n);
            PRNG prng(CCBlock);

            AlignedUnVector<block> x(n);
            prng.get<block>(x);

            encoder.dualEncode<block>(x.data());


        }

    }
}