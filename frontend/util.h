#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.



#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/config.h"
#include <functional>
#include <string>
#include "libOTe/Tools/Coproto.h"
#include <vector>

namespace osuCrypto
{


    static const std::vector<std::string>
        unitTestTag{ "u", "unitTest" },
        kos{ "k", "kos" },
        dkos{ "d", "dkos" },
        ssdelta{ "ssd", "ssdelta" },
        sshonest{ "ss", "sshonest" },
        smleakydelta{ "smld", "smleakydelta" },
        smalicious{ "sm", "smalicious" },
        kkrt{ "kk", "kkrt" },
        iknp{ "i", "iknp" },
        diknp{ "diknp" },
        oos{ "o", "oos" },
        moellerpopf{ "p", "moellerpopf" },
        ristrettopopf{ "r", "ristrettopopf" },
        mr{ "mr" },
        mrb{ "mrb" },
        Silent{ "s", "Silent" },
        vole{ "vole" },
        akn{ "a", "akn" },
        np{ "np" },
        simple{ "simplest" },
        simpleasm{ "simplest-asm" };
    enum class Role
    {
        Sender,
        Receiver
    };

#ifdef ENABLE_BOOST
    void senderGetLatency(Channel& chl);

    void recverGetLatency(Channel& chl);
    void getLatency(CLP& cmd);
    void sync(Channel& chl, Role role);
#endif

    task<> sync(Socket& chl, Role role);



    //using ProtocolFunc = std::function<void(Role, int, int, std::string, std::string, CLP&)>;

    template<typename ProtocolFunc>
    inline bool runIf(ProtocolFunc protocol, const CLP & cmd, std::vector<std::string> tag,
                      std::vector<std::string> tag2 = std::vector<std::string>())
    {
        auto n = cmd.isSet("nn")
            ? (1 << cmd.get<int>("nn"))
            : cmd.getOr("n", 0);

        auto t = cmd.getOr("t", 1);
        auto ip = cmd.getOr<std::string>("ip", "localhost:1212");

        if (!cmd.isSet(tag))
            return false;

        if (!tag2.empty() && !cmd.isSet(tag2))
            return false;

        if (cmd.hasValue("r"))
        {
            auto role = cmd.get<int>("r") ? Role::Sender : Role::Receiver;
            protocol(role, n, t, ip, tag.back(), cmd);
        }
        else
        {
            auto thrd = std::thread([&] {
                try { protocol(Role::Sender, n, t, ip, tag.back(), cmd); }
                catch (std::exception& e)
                {
                    lout << e.what() << std::endl;
                }
                });

            try { protocol(Role::Receiver, n, t, ip, tag.back(), cmd); }
            catch (std::exception& e)
            {
                lout << e.what() << std::endl;
            }
            thrd.join();
        }

        return true;
    }




#define LINE "------------------------------------------------------"
#define TOTALOTS 10
#define SETSIZE 2<<10

#ifdef ENABLE_SIMPLESTOT
    const bool spEnabled = true;
#else
    const bool spEnabled = false;
#endif
#ifdef ENABLE_SIMPLESTOT_ASM
    const bool spaEnabled = true;
#else
    const bool spaEnabled = false;
#endif
#ifdef ENABLE_MRR
    const bool popfotRistrettoEnabled = true;
#else
    const bool popfotRistrettoEnabled = false;
#endif
#ifdef ENABLE_MRR_TWIST
    const bool popfotMoellerEnabled = true;
#else
    const bool popfotMoellerEnabled = false;
#endif
#ifdef ENABLE_MR
    const bool mrEnabled = true;
#else
    const bool mrEnabled = false;
#endif
#ifdef ENABLE_IKNP
    const bool iknpEnabled = true;
#else
    const bool iknpEnabled = false;
#endif
#ifdef ENABLE_DELTA_IKNP
    const bool diknpEnabled = true;
#else
    const bool diknpEnabled = false;
#endif
#ifdef ENABLE_KOS
    const bool kosEnabled = true;
#else
    const bool kosEnabled = false;
#endif
#ifdef ENABLE_DELTA_KOS
    const bool dkosEnabled = true;
#else
    const bool dkosEnabled = false;
#endif
#ifdef ENABLE_DELTA_KOS
    const bool softSpokenEnabled = true;
#else
    const bool softSpokenEnabled = false;
#endif
#ifdef ENABLE_NP
    const bool npEnabled = true;
#else
    const bool npEnabled = false;
#endif

#ifdef ENABLE_OOS
    const bool oosEnabled = true;
#else
    const bool oosEnabled = false;
#endif
#ifdef ENABLE_KKRT
    const bool kkrtEnabled = true;
#else
    const bool kkrtEnabled = false;
#endif

#ifdef ENABLE_SILENTOT
    const bool silentEnabled = true;
#else
    const bool silentEnabled = false;
#endif


}
