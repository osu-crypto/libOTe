#include "Common/Log.h"
#include <functional>

#include "AES_Tests.h"
#include "AknOt_Tests.h"
#include "BtChannel_Tests.h"
#include "BaseOT_Tests.h"
#include "OT_Tests.h"
#include "NcoOT_Tests.h"
#include "AknOt_Tests.h"
#include "Ecc_Tests.h"


using namespace osuCrypto;

void run(std::string name, std::function<void(void)> func)
{
    Log::out << name;

    auto start = std::chrono::high_resolution_clock::now();
    try
    {
        func(); Log::out << Log::Color::Green << "  Passed" << Log::ColorDefault;
    }
    catch (const std::exception& e)
    {
        Log::out << Log::Color::Red << "Failed - " << e.what() << Log::ColorDefault;
    }

    auto end = std::chrono::high_resolution_clock::now();

    u64 time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    Log::out << "   " << time << "ms" << Log::endl;


    if (Log::out.mSink != &std::cout)
        throw std::runtime_error("");
}


void NetWork_all()
{
    Log::out << Log::endl;
    run("BtNetwork_Connect1_Boost_Test        ", BtNetwork_Connect1_Boost_Test);
    run("BtNetwork_OneMegabyteSend_Boost_Test ", BtNetwork_OneMegabyteSend_Boost_Test);
    run("BtNetwork_ConnectMany_Boost_Test     ", BtNetwork_ConnectMany_Boost_Test);
    run("BtNetwork_CrossConnect_Test          ", BtNetwork_CrossConnect_Test);
    run("BtNetwork_ManyEndpoints_Test         ", BtNetwork_ManyEndpoints_Test);

}

void bitVec_all()
{
    Log::out << Log::endl;
    run("BitVector_Indexing_Test                 ", BitVector_Indexing_Test_Impl);
    run("BitVector_Parity                        ", BitVector_Parity_Test_Impl);
    run("BitVector_Append_Test                   ", BitVector_Append_Test_Impl);
    run("BitVector_Copy_Test                     ", BitVector_Copy_Test_Impl);
}

void OT_all()
{
    Log::out << Log::endl;

    run("Transpose_Test_Impl                     ", Transpose_Test_Impl);
    run("KosOtExt_100Receive_Test_Impl           ", KosOtExt_100Receive_Test_Impl);
    run("IknpOtExt_100Receive_Test_Impl          ", IknpOtExt_100Receive_Test_Impl);
    run("AknOt_sendRecv1000_Test                 ", AknOt_sendRecv1000_Test);
    run("KkrtNcoOt_Test                          ", KkrtNcoOt_Test_Impl);
    run("OosNcoOt_Test_Impl                      ", OosNcoOt_Test_Impl);
    run("BchCode_Test_Impl                       ", BchCode_Test_Impl);
    run("NaorPinkasOt_Test                       ", NaorPinkasOt_Test_Impl);
}


void Ecc_all()
{
    Log::out << Log::endl;

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
