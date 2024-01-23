#include "cryptoTools/Common/CLP.h"
#include "coproto/Socket/BufferingSocket.h"
#include <fstream>
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"

namespace osuCrypto
{

    // This example demonstates how one can get and manually send the protocol messages
    // that are generated. This communicate method is one possible way of doing this.
    // It takes a protocol that has been started and coproto buffering socket as input.
    // It alternates between "sending" and "receiving" protocol messages. Instead of
    // sending the messages on a socket, this program writes them to a file and the other
    // party reads that file to get the message. In a real program the communication could 
    // handled in any way the user decides.
    auto communicate(
        macoro::eager_task<>& protocol,
        bool sender,
        coproto::BufferingSocket& sock,
        bool verbose)
    {

        int s = 0, r = 0;
        std::string me = sender ? "sender" : "recver";
        std::string them = !sender ? "sender" : "recver";

        // write any outgoing data to a file me_i.bin where i in the message index.
        auto write = [&]()
            {
                // the the outbound messages that the protocol has generated.
                // This will consist of all the outbound messages that can be 
                // generated without receiving the next inbound message.
                auto b = sock.getOutbound();

                // If we do have outbound messages, then lets write them to a file.
                if (b && b->size())
                {
                    std::ofstream message;
                    auto temp = me + ".tmp";
                    auto file = me + "_" + std::to_string(s) + ".bin";
                    message.open(temp, std::ios::binary | std::ios::trunc);
                    message.write((char*)b->data(), b->size());
                    message.close();

                    if (verbose)
                    {
                        // optional for debug purposes.
                        RandomOracle hash(16);
                        hash.Update(b->data(), b->size());
                        block h; hash.Final(h);

                        std::cout << me << " write " << std::to_string(s) << " " << h << "\n";
                    }

                    if (rename(temp.c_str(), file.c_str()) != 0)
                        std::cout << me << " file renamed failed\n";
                    else if (verbose)
                        std::cout << me << " file renamed successfully\n";

                    ++s;
                }

            };

        // write incoming data from a file them_i.bin where i in the message index.
        auto read = [&]() {

            std::ifstream message;
            auto file = them + "_" + std::to_string(r) + ".bin";
            while (message.is_open() == false)
            {
                message.open(file, std::ios::binary);
                if ((message.is_open() == false))
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            auto fsize = message.tellg();
            message.seekg(0, std::ios::end);
            fsize = message.tellg() - fsize;
            message.seekg(0, std::ios::beg);
            std::vector<u8> buff(fsize);
            message.read((char*)buff.data(), fsize);
            message.close();
            std::remove(file.c_str());

            if (verbose)
            {
                RandomOracle hash(16);
                hash.Update(buff.data(), buff.size());
                block h; hash.Final(h);

                std::cout << me << " read " << std::to_string(r) << " " << h << "\n";
            }
            ++r;

            // This gives this socket the message which forwards it to the protocol and
            // run the protocol forward, possibly generating more outbound protocol
            // messages.
            sock.processInbound(buff);
            };

        // The sender we generate the first message.
        if (!sender)
            write();

        // While the protocol is not done we alternate between reading and writing messages.
        while (protocol.is_ready() == false)
        {
            read();
            write();
        }
    }

    void messagePassingExampleRun(CLP& cmd)
    {
#ifdef ENABLE_SILENTOT
        auto isReceiver = cmd.get<int>("r");

        // The number of OTs.
        auto n = cmd.getOr("n", 100);

        auto verbose = cmd.isSet("v");

        // A buffering socket. This socket type internally buffers the 
        // protocol messages. It is then up to the user to manually send
        // and receive messages via the getOutbond(...) and processInbount(...)
        // methods.
        coproto::BufferingSocket sock;

        // randomness source
        PRNG prng(sysRandomSeed());

        // Sets are always represented as 16 byte values. To support longer elements one can hash them.
        if (!isReceiver)
        {
            SilentOtExtSender sender;

            std::vector<std::array<block, 2>> senderOutput(n);


            if (verbose)
                std::cout << "sender start\n";

            // Eagerly start the protocol. This will run the protocol up to the point
            // that it need to receive a message from the other party.
            auto protocol =
                sender.silentSend(senderOutput, prng, sock)
                | macoro::make_eager();

            // Perform the communication and complete the protocol.
            communicate(protocol, true, sock, verbose);

            std::cout << "sender done\n";

            for (u64 i = 0; i < std::min<u64>(10, n); ++i)
                std::cout << "sender.msg[" << i << "] = { " << senderOutput[i][0] << ", " << senderOutput[i][1] << "}" << std::endl;
            if (n > 10)
                std::cout << "..." << std::endl;
        }
        else
        {
            std::vector<block> receiverOutputMsg(n);
            BitVector receiverOutputBits(n);

            SilentOtExtReceiver receiver;

            if (verbose)
                std::cout << "recver start\n";

            // Eagerly start the protocol. This will run the protocol up to the point
            // that it need to receive a message from the other party.
            auto protocol =
                receiver.silentReceive(receiverOutputBits, receiverOutputMsg, prng, sock)
                | macoro::make_eager();

            // Perform the communication and complete the protocol.
            communicate(protocol, false, sock, verbose);

            std::cout << "recver done\n";

            for (u64 i = 0; i < std::min<u64>(10, n); ++i)
                std::cout << "receiver.msg[" << i << "] = " << receiverOutputMsg[i] << " = sender.msg[" << i << "][" << receiverOutputBits[i] << "]" << std::endl;
            if (n > 10)
                std::cout << "..." << std::endl;
        }
#else
        std::cout << "ENABLE_SILENTOT is not defined. Rebuilt with -DENABLE_SILENTOT=true" << std::endl;
#endif
    }


    void messagePassingExample(CLP& cmd)
    {
        // If the user specified -r, then run that party.
        // Otherwise run both parties.
        if (cmd.hasValue("r"))
        {
            messagePassingExampleRun(cmd);
        }
        else
        {
            auto s = cmd;
            s.setDefault("r", 0);
            cmd.setDefault("r", 1);
            auto a = std::async([&]() {messagePassingExampleRun(s); });
            messagePassingExampleRun(cmd);
            a.get();
        }
    }

}