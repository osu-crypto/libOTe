#include "Test.h"
#include "LdpcEncoder.h"
#include "LdpcDecoder.h"
#include "LdpcSampler.h"
#include "Util.h"
#include "cryptoTools/Common/TestCollection.h"
//#include "LinearSolver.h"

namespace osuCrypto
{



    void printGen(oc::CLP& cmd)
    {

    }

    void ldpcMain(oc::CLP& cmd)
    {

        if (cmd.isSet("sample"))
            return sampleExp(cmd);


        tests::LdpcDecode_impulse_test(cmd);

        return;
    }
}
