#include "OT_Tests.h"

#include "TwoChooseOne/OTExtInterface.h"

#include "Tools/Tools.h"
#include "Tools/LinearCode.h"
#include "Network/BtChannel.h"
#include "Network/BtEndpoint.h"
#include "Common/Log.h"
 
#include "NChooseOne/KkrtNcoOtReceiver.h"
#include "NChooseOne/KkrtNcoOtSender.h"

#include "NChooseOne/Oos/OosNcoOtReceiver.h"
#include "NChooseOne/Oos/OosNcoOtSender.h"

#include "Common.h"
#include <thread>
#include <vector>


using namespace osuCrypto;




void KkrtNcoOt_Test_Impl()
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 numOTs = 128;

    KkrtNcoOtSender sender;
    KkrtNcoOtReceiver recv;
    u64 codeSize, baseCount;
    sender.getParams(false,128, 40, 128, numOTs, codeSize, baseCount);
    
    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }

    std::string name = "n";
    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, true, name);
    BtEndpoint ep1(ios, "localhost", 1212, false, name);
    auto &recvChl = ep1.addChannel(name, name);
    auto &sendChl = ep0.addChannel(name, name);




    sender.setBaseOts(baseRecv, baseChoice);
    recv.setBaseOts(baseSend);

    std::vector<block> codeword(codeSize), correction(codeSize);
    for (size_t j = 0; j < 10; j++)
    {
        sender.init(numOTs);

        recv.init(numOTs);

        for (u64 i = 0; i < numOTs; ++i)
        {
            prng0.get((u8*)codeword.data(), codeSize * sizeof(block));

            block encoding1, encoding2;
            recv.encode(i, codeword, encoding1);

            recv.sendCorrection(recvChl, 1);
            sender.recvCorrection(sendChl, 1);

            sender.encode(i, codeword,  encoding2);

            if (neq(encoding1, encoding2))
                throw UnitTestFail();

            prng0.get((u8*)codeword.data(), codeSize * sizeof(block));

            sender.encode(i, codeword,  encoding2);

            if (eq(encoding1, encoding2))
                throw UnitTestFail();
        }

    }

    sendChl.close();
    recvChl.close();

    ep0.stop();
    ep1.stop();
    ios.stop();
}

void OosNcoOt_Test_Impl()
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 numOTs = 128 * 8;


    std::string name = "n";
    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, true, name);
    BtEndpoint ep1(ios, "localhost", 1212, false, name);
    auto &recvChl = ep1.addChannel(name, name);
    auto &sendChl = ep0.addChannel(name, name);


    LinearCode code;
    code.loadBinFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/bch511.bin");

    OosNcoOtSender sender(code);
    OosNcoOtReceiver recv(code);


    u64 ncoinputBlkSize, baseCount;
    sender.getParams(true, 128, 40, 128, numOTs, ncoinputBlkSize, baseCount);
    u64 codeSize = (baseCount + 127) / 128;

    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }

    sender.setBaseOts(baseRecv, baseChoice);
    recv.setBaseOts(baseSend);

    std::vector<block> choice(ncoinputBlkSize), correction(codeSize);
    for (size_t j = 0; j < 2; j++)
    {

        sender.init(numOTs);
        recv.init(numOTs);

        for (u64 i = 0; i < numOTs; ++i)
        {
            prng0.get((u8*)choice.data(), ncoinputBlkSize * sizeof(block));


            bool skip = prng0.getBit();

            block encoding1, encoding2;
            if (skip)
            {
                recv.zeroEncode(i);
            }
            else
            {
                recv.encode(i, choice,  encoding1);
            }

            recv.sendCorrection(recvChl, 1);
            sender.recvCorrection(sendChl, 1);

            sender.encode(i, choice, encoding2);

            if (!skip && neq(encoding1, encoding2))
                throw UnitTestFail();

            prng0.get((u8*)choice.data(), ncoinputBlkSize * sizeof(block));

            sender.encode(i, choice, encoding2);

            if (!skip && eq(encoding1, encoding2))
                throw UnitTestFail();
        }

        auto thrd = std::thread([&]() {recv.check(recvChl); });

        sender.check(sendChl);

        thrd.join();
    }

    sendChl.close();
    recvChl.close();

    ep0.stop();
    ep1.stop();
    ios.stop();
}


void LinearCode_Test_Impl()
{
    LinearCode code;


    code.loadTxtFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/bch511.txt");
    code.writeBinFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/bch511.bin");
    code.loadBinFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/bch511.bin");
    //std::cout << code.codewordBitSize() << "  " << code.codewordBlkSize() <<
    //    "\n  " << code.plaintextBitSize() << "  " << code.plaintextBlkSize() << std::endl;


    //for (u64 i = 0; i < code.mG.size(); ++i)
    //    std::cout << code.mG[i] << std::endl;

    std::vector<block> 
        plainText(code.plaintextBlkSize(), AllOneBlock),
        codeword(code.codewordBlkSize());

    code.encode(plainText, codeword);

    BitVector cw((u8*)codeword.data(), code.codewordBitSize());

    // expect all ones
    for (size_t i = 0; i < cw.size(); i++)
    {
        if (cw[i] == 0)
        {
            std::cout << cw << std::endl;
            std::cout << "expecting all ones" << std::endl;
            throw UnitTestFail();
        }
    }

    BitVector pt("1111111111111111111111111111111111111111111111111101111111111101111111111111");
    memset(plainText.data(), 0, plainText.size() * sizeof(block));
    memcpy(plainText.data(), pt.data(), pt.sizeBytes());


    code.encode(plainText, codeword);
    cw.resize(0);
    cw.append((u8*)codeword.data(), code.codewordBitSize());


    BitVector expected("1111111111111111111111111111111111111111111111111101111111111101111111111111101000010001110100011100010110011111110010011010001010000111111001101101110101100000100010010101000110011001111101111100100111000101110000101000000011000100011110011100001101100111111001001011010100010010110001010011000011111010101010010010011101001001100001100010100101001100111000010110011110011110001110001011111101010001101000101010110100011000000011010011110101011001100011111111101001101111001111111101000010000011010111100011100");

    if (cw != expected)
    {
        std::cout << cw << std::endl;
        std::cout << expected << std::endl;
        throw UnitTestFail();
    }

}


