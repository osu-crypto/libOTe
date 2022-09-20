#include "NcoOtExt.h"

#ifdef LIBOTE_HAS_NCO

#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/Kos/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/Kos/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Network/Channel.h>
namespace osuCrypto
{

    task<> NcoOtExtReceiver::genBaseOts(PRNG& prng, Socket& chl)
    {
        struct TT
        {
#ifdef ENABLE_IKNP
            IknpOtExtSender iknp;
#endif
#ifdef ENABLE_KOS
            KosOtExtSender kos;
#endif
#ifdef LIBOTE_HAS_BASE_OT
            DefaultBaseOT base;
#endif
        };

        MC_BEGIN(task<>,this, &prng, &chl,
            count = getBaseOTCount(),
            msgs = AlignedUnVector<std::array<block, 2>>{},
            sender = std::unique_ptr<TT>(new TT)
        );
        msgs.resize(count);

#ifdef ENABLE_IKNP
        if (!isMalicious())
        {
            MC_AWAIT(sender->iknp.genBaseOts(prng, chl));
            MC_AWAIT(sender->iknp.send(msgs, prng, chl));
            MC_AWAIT(setBaseOts(msgs, prng, chl));
            MC_RETURN_VOID();
        }
#endif

#ifdef ENABLE_KOS

        MC_AWAIT(sender->kos.genBaseOts(prng, chl));
        MC_AWAIT(sender->kos.send(msgs, prng, chl));

#elif defined LIBOTE_HAS_BASE_OT

        MC_AWAIT(sender->base.send(msgs, prng, chl));
#else
        throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif

        MC_AWAIT(setBaseOts(msgs, prng, chl));

        MC_END();
    }


    task<> NcoOtExtSender::genBaseOts(PRNG& prng, Socket& chl)
    {
        struct TT
        {
#ifdef ENABLE_IKNP
            IknpOtExtReceiver iknp;
#endif
#ifdef ENABLE_KOS
            KosOtExtReceiver kos;
#endif
#ifdef LIBOTE_HAS_BASE_OT
            DefaultBaseOT base;
#endif
        };

        MC_BEGIN(task<>,this, &prng, &chl,
            count = getBaseOTCount(),
            msgs = AlignedUnVector<block>{},
            bv = BitVector{},
            recver = std::unique_ptr<TT>(new TT)
        );
        msgs.resize(count);
        bv.resize(count);
        bv.randomize(prng);

#ifdef ENABLE_IKNP
        if (!isMalicious())
        {
            MC_AWAIT(recver->iknp.genBaseOts(prng, chl));
            MC_AWAIT(recver->iknp.receive(bv, msgs, prng, chl));
            MC_AWAIT(setBaseOts(msgs, bv, chl));
            MC_RETURN_VOID();
        }
#endif

#ifdef ENABLE_KOS
        MC_AWAIT(recver->kos.genBaseOts(prng, chl));
        MC_AWAIT(recver->kos.receive(bv, msgs, prng, chl));

#elif defined LIBOTE_HAS_BASE_OT

        MC_AWAIT(recver->base.receive(bv, msgs, prng, chl));
#else 
        throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif

        MC_AWAIT(setBaseOts(msgs, bv, chl));

        MC_END();
    }

    task<> NcoOtExtSender::sendChosen(MatrixView<block> messages, PRNG& prng, Socket& chl)
    {
        MC_BEGIN(task<>,this, messages, &prng, &chl,
            temp = Matrix<block>{});

        if (hasBaseOts() == false)
            throw std::runtime_error("call configure(...) and genBaseOts(...) first.");

        MC_AWAIT(init(messages.rows(), prng, chl));

        MC_AWAIT(recvCorrection(chl, messages.rows()));

        MC_AWAIT(check(chl, prng.get<block>()));

        {

            auto numMsgsPerOT = messages.cols();
            std::array<u64, 2> choice{ 0,0 };
            u64& j = choice[0];

            temp.resize(messages.rows(), numMsgsPerOT);
            for (u64 i = 0; i < messages.rows(); ++i)
            {
                for (j = 0; j < messages.cols(); ++j)
                {
                    encode(i, choice.data(), &temp(i, j));
                    temp(i, j) = temp(i, j) ^ messages(i, j);
                }
            }
        }


        MC_AWAIT(chl.send(std::move(temp)));

        MC_END();
    }

    task<> NcoOtExtReceiver::receiveChosen(
        u64 numMsgsPerOT,
        span<block> messages,
        span<u64> choices, PRNG& prng, Socket& chl)
    {
        MC_BEGIN(task<>,this, numMsgsPerOT, messages, choices, &prng, &chl,
            temp = Matrix<block>{});

        if (hasBaseOts() == false)
            throw std::runtime_error("call configure(...) and genBaseOts(...) first.");

        MC_AWAIT(init(messages.size(), prng, chl));

        {
            // must be at least 128 bits.
            std::array<u64, 2> choice{ 0,0 };
            auto& j = choice[0];

            for (u64 i = 0; i < messages.size(); ++i)
            {
                j = choices[i];
                encode(i, &j, &messages[i]);
            }
        }

        MC_AWAIT(sendCorrection(chl, messages.size()));
        temp.resize(messages.size(), numMsgsPerOT);

        MC_AWAIT(check(chl, prng.get<block>()));

        MC_AWAIT(chl.recv(temp));

        for (u64 i = 0; i < messages.size(); ++i)
        {
            messages[i] = messages[i] ^ temp(i, choices[i]);
        }

        MC_END();
    }
}
#endif
