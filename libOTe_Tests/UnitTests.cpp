#include <cryptoTools/Common/Log.h>
#include <functional>


#include "libOTe_Tests/AknOt_Tests.h"
#include "libOTe_Tests/BaseOT_Tests.h"
#include "libOTe_Tests/OT_Tests.h"
#include "libOTe_Tests/NcoOT_Tests.h"
#include "libOTe_Tests/AknOt_Tests.h"


using namespace osuCrypto;
namespace tests_libOTe
{

    void run(std::string name, std::function<void(void)> func)
    {
        std::cout << name << std::flush;

        auto start = std::chrono::high_resolution_clock::now();
        try
        {
            func(); std::cout << Color::Green << "  Passed" << ColorDefault;
        }
        catch (const std::exception& e)
        {
            std::cout << Color::Red << "Failed - " << e.what() << ColorDefault;
        }

        auto end = std::chrono::high_resolution_clock::now();

        u64 time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << "   " << time << "ms" << std::endl;

    }


    void tests_OT_all()
    {
        std::cout << std::endl;


        run("TransposeMatrixView_Test_Impl           ", TransposeMatrixView_Test_Impl);
        run("Transpose_Test_Impl                     ", Transpose_Test_Impl);
        run("KosOtExt_100Receive_Test_Impl           ", KosOtExt_100Receive_Test_Impl);
        run("KosDotExt_100Receive_Test_Impl          ", KosDotExt_100Receive_Test_Impl);
        run("IknpOtExt_100Receive_Test_Impl          ", IknpOtExt_100Receive_Test_Impl);
        run("AknOt_sendRecv1000_Test                 ", AknOt_sendRecv1000_Test);
        run("KkrtNcoOt_Test                          ", KkrtNcoOt_Test_Impl);
        run("OosNcoOt_Test_Impl                      ", OosNcoOt_Test_Impl);
        run("Rr17NcoOt_Test_Impl                     ", Rr17NcoOt_Test_Impl);
        run("LinearCode_Test_Impl                    ", LinearCode_Test_Impl);
        run("LinearCode_subBlock_Test_Impl           ", LinearCode_subBlock_Test_Impl);
        run("LinearCode_repetition_Test_Impl         ", LinearCode_repetition_Test_Impl);
        run("NaorPinkasOt_Test                       ", NaorPinkasOt_Test_Impl);
    }




    void tests_all()
    {

        tests_OT_all();

    }
}
