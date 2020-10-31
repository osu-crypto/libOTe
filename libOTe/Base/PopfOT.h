#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_POPF

// #include "Popf.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Crypto/Rijndael256.h>


namespace osuCrypto
{

    // Parameterized on "T eval(U)"
    template <class T, class U>
    class Popf
    {
        public:
            Popf() {}
            virtual u64 sizeBytes() const = 0;
            virtual void toBytes(u8* dest) const = 0;
            virtual void fromBytes(u8* src) = 0;
            virtual T eval(U x) = 0;
            virtual void program(U x, T y) = 0; // Maybe make this static and return a popf object? Or make a factory class?
            virtual ~Popf() = default;
    };

    class EKEPopf : public Popf<oc::REccPoint,bool>
    {
        public:
            EKEPopf()
            {
                IC[0].setKey({toBlock(0,0),toBlock(0,0)});
                IC[1].setKey({toBlock(0,0),toBlock(1ull)});
                ICinv[0].setKey({toBlock(0,0),toBlock(0,0)});
                ICinv[1].setKey({toBlock(0,0),toBlock(1ull)});

                oc::REccPoint point;
                u64 pointSize = point.sizeBytes();
                aesBlocks = (pointSize + 31) / 32;
                size = aesBlocks * sizeof(Rijndael256Enc::Block);
                popfBuff.resize(size);
            }
            u64 sizeBytes() const { return size; }
            void toBytes(u8* dest) const;
            void fromBytes(u8* src);
            oc::REccPoint eval(bool x);
            void program(bool x, oc::REccPoint y);
        private:
            u64 size;
            u64 aesBlocks;
            std::array<Rijndael256Enc, 2> IC;
            std::array<Rijndael256Dec, 2> ICinv;
            std::vector<u8> popfBuff;
    };

    // class MRPopf : public Popf<oc::REccPoint,bool>
    // {
        
    // };

    // template<class T>
    class PopfOT : public OtReceiver, public OtSender
    {
    public:
        // PopfOT()
        // {
        //     popf = new EKEPopf();
        // }
        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl,
            u64 numThreads)
        {
            receive(choices, messages, prng, chl);
        }

        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl,
            u64 numThreads)
        {
            send(messages, prng, chl);
        }

        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl) override;

        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl) override;
        
        // ~PopfOT()
        // {
        //     delete popf;
        // }
        
        private:
            // Popf<oc::REccPoint, bool>* popf;
    };

}
#endif