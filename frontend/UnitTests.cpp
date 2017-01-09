#include "cryptoTools/Common/Log.h"
#include <functional>

#include "libOTe_Tests/AES_Tests.h"
#include "libOTe_Tests/AknOt_Tests.h"
#include "libOTe_Tests/BtChannel_Tests.h"
#include "libOTe_Tests/BaseOT_Tests.h"
#include "libOTe_Tests/OT_Tests.h"
#include "libOTe_Tests/NcoOT_Tests.h"
#include "libOTe_Tests/AknOt_Tests.h"
#include "libOTe_Tests/Ecc_Tests.h"


using namespace osuCrypto;

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


void NetWork_all()
{
    std::cout << std::endl;
    run("BtNetwork_Connect1_Boost_Test        ", BtNetwork_Connect1_Boost_Test);
    run("BtNetwork_OneMegabyteSend_Boost_Test ", BtNetwork_OneMegabyteSend_Boost_Test);
    run("BtNetwork_ConnectMany_Boost_Test     ", BtNetwork_ConnectMany_Boost_Test);
    run("BtNetwork_CrossConnect_Test          ", BtNetwork_CrossConnect_Test);
    run("BtNetwork_ManyEndpoints_Test         ", BtNetwork_ManyEndpoints_Test);

}

void bitVec_all()
{
    std::cout << std::endl;
    run("BitVector_Indexing_Test                 ", BitVector_Indexing_Test_Impl);
    run("BitVector_Parity                        ", BitVector_Parity_Test_Impl);
    run("BitVector_Append_Test                   ", BitVector_Append_Test_Impl);
    run("BitVector_Copy_Test                     ", BitVector_Copy_Test_Impl);
}

void OT_all()
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
    run("LinearCode_Test_Impl                    ", LinearCode_Test_Impl);
    run("LinearCode_repetition_Test_Impl         ", LinearCode_repetition_Test_Impl);
    run("NaorPinkasOt_Test                       ", NaorPinkasOt_Test_Impl);
}


void Ecc_all()
{
    std::cout << std::endl;

    run("Ecc2mNumber_Test                        ", Ecc2mNumber_Test);
    run("Ecc2mPoint_Test                         ", Ecc2mPoint_Test);
    run("EccpNumber_Test                         ", EccpNumber_Test);
    run("EccpPoint_Test                          ", EccpPoint_Test);

}


void run_all()
{

    NetWork_all();
    bitVec_all();
    Ecc_all();
    OT_all();
    
}
