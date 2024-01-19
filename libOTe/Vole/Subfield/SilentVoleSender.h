#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// This code implements features described in [Silver: Silent VOLE and Oblivious Transfer from Hardness of Decoding Structured LDPC Codes, https://eprint.iacr.org/2021/1150]; the paper is licensed under Creative Commons Attribution 4.0 International Public License (https://creativecommons.org/licenses/by/4.0/legalcode).

#include <libOTe/config.h>
#ifdef ENABLE_SILENT_VOLE

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Aligned.h>
#include "libOTe/Tools/Subfield/SubfieldPprf.h"
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h>
#include <libOTe/Tools/ExConvCode/ExConvCode2.h>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/Vole/Subfield/NoisyVoleReceiver.h>
#include <libOTe/Vole/Subfield/NoisyVoleSender.h>
//#define NO_HASH

namespace osuCrypto
{
    template<
        typename F,
        typename G = F,
        typename CoeffCtx = DefaultCoeffCtx<F, G>
    >
    class SilentSubfieldVoleSender : public TimerAdapter
    {
    public:
        static constexpr u64 mScaler = 2;

        enum class State
        {
            Default,
            Configured,
            HasBase
        };

        using VecF = typename CoeffCtx::template Vec<F>;
        using VecG = typename CoeffCtx::template Vec<G>;

        State mState = State::Default;

        SilentSubfieldPprfSender<F, G, CoeffCtx> mGen;

        u64 mRequestedNumOTs = 0;
        u64 mN2 = 0;
        u64 mN = 0;
        u64 mNumPartitions = 0;
        u64 mSizePer = 0;
        u64 mNumThreads = 1;
        SilentBaseType mBaseType;
        VecF mNoiseDeltaShares;

        SilentSecType mMalType = SilentSecType::SemiHonest;

#ifdef ENABLE_SOFTSPOKEN_OT
        SoftSpokenMalOtSender mOtExtSender;
        SoftSpokenMalOtReceiver mOtExtRecver;
#endif

        MultType mMultType = DefaultMultType;

        ExConvCode2 mExConvEncoder;

        VecF mB;


        u64 baseVoleCount() const {
            return mNumPartitions + 1 * (mMalType == SilentSecType::Malicious);
        }

        // Generate the silent base OTs. If the Iknp 
        // base OTs are set then we do an IKNP extend,
        // otherwise we perform a base OT protocol to
        // generate the needed OTs.
        task<> genSilentBaseOts(PRNG& prng, Socket& chl, cp::optional<F> delta = {})
        {
            using BaseOT = DefaultBaseOT;


            MC_BEGIN(task<>, this, delta, &prng, &chl,
                msg = AlignedUnVector<std::array<block, 2>>(silentBaseOtCount()),
                baseOt = BaseOT{},
                prng2 = std::move(PRNG{}),
                xx = BitVector{},
                chl2 = Socket{},
                nv = NoisySubfieldVoleSender<F, G, CoeffCtx>{},
                noiseDeltaShares = std::vector<F>{}
            );
            setTimePoint("SilentVoleSender.genSilent.begin");

            if (isConfigured() == false)
                throw std::runtime_error("configure must be called first");

            if(!delta)
                CoeffCtx::fromBlock(*delta, prng.get<block>());

            xx = CoeffCtx::binaryDecomposition<F>(*delta);

            // compute the correlation for the noisy coordinates.
            noiseDeltaShares.resize(baseVoleCount());


            if (mBaseType == SilentBaseType::BaseExtend)
            {
#ifdef ENABLE_SOFTSPOKEN_OT

                if (mOtExtRecver.hasBaseOts() == false)
                {
                    msg.resize(msg.size() + mOtExtRecver.baseOtCount());
                    MC_AWAIT(mOtExtSender.send(msg, prng, chl));

                    mOtExtRecver.setBaseOts(
                        span<std::array<block, 2>>(msg).subspan(
                            msg.size() - mOtExtRecver.baseOtCount(),
                            mOtExtRecver.baseOtCount()));
                    msg.resize(msg.size() - mOtExtRecver.baseOtCount());

                    MC_AWAIT(nv.send(*delta, noiseDeltaShares, prng, mOtExtRecver, chl));
                }
                else
                {
                    chl2 = chl.fork();
                    prng2.SetSeed(prng.get());

                    MC_AWAIT(
                        macoro::when_all_ready(
                            nv.send(*delta, noiseDeltaShares, prng2, mOtExtRecver, chl2),
                            mOtExtSender.send(msg, prng, chl)));
                }
#else

#endif
            }
            else
            {
                chl2 = chl.fork();
                prng2.SetSeed(prng.get());
                MC_AWAIT(baseOt.send(msg, prng, chl));
                MC_AWAIT(nv.send(*delta, noiseDeltaShares, prng2, baseOt, chl2));
                //                 MC_AWAIT(
                //                     macoro::when_all_ready(
                //                         nv.send(*delta, noiseDeltaShares, prng2, baseOt, chl2),
                //                         baseOt.send(msg, prng, chl)));
            }


            setSilentBaseOts(msg, noiseDeltaShares);
            setTimePoint("SilentVoleSender.genSilent.done");
            MC_END();
        }

        // configure the silent OT extension. This sets
        // the parameters and figures out how many base OT
        // will be needed. These can then be ganerated for
        // a different OT extension or using a base OT protocol.
        void configure(
            u64 numOTs,
            SilentBaseType type = SilentBaseType::BaseExtend,
            u64 secParam = 128)
        {
            mBaseType = type;

            switch (mMultType)
            {
            case osuCrypto::MultType::ExConv7x24:
            case osuCrypto::MultType::ExConv21x24:

                ExConvConfigure(numOTs, 128, mMultType, mRequestedNumOTs, mNumPartitions, mSizePer, mN2, mN, mExConvEncoder);
                break;
            default:
                throw RTE_LOC;
                break;
            }

            mGen.configure(mSizePer, mNumPartitions);

            mState = State::Configured;
        }

        // return true if this instance has been configured.
        bool isConfigured() const { return mState != State::Default; }

        // Returns how many base OTs the silent OT extension
        // protocol will needs.
        u64 silentBaseOtCount() const
        {
            if (isConfigured() == false)
                throw std::runtime_error("configure must be called first");

            return mGen.baseOtCount();
        }

        // Set the externally generated base OTs. This choice
        // bits must be the one return by sampleBaseChoiceBits(...).
        void setSilentBaseOts(
            span<std::array<block, 2>> sendBaseOts,
            span<F> noiseDeltaShares)
        {
            if ((u64)sendBaseOts.size() != silentBaseOtCount())
                throw RTE_LOC;

            if (noiseDeltaShares.size() != baseVoleCount())
                throw RTE_LOC;

            mGen.setBase(sendBaseOts);
            mNoiseDeltaShares.resize(noiseDeltaShares.size());
            std::copy(noiseDeltaShares.begin(), noiseDeltaShares.end(), mNoiseDeltaShares.begin());
        }

        // The native OT extension interface of silent
        // OT. The receiver does not get to specify 
        // which OT message they receiver. Instead
        // the protocol picks them at random. Use the 
        // send(...) interface for the normal behavior.
        task<> silentSend(
            F delta,
            span<F> b,
            PRNG& prng,
            Socket& chl)
        {
            MC_BEGIN(task<>, this, delta, b, &prng, &chl);

            MC_AWAIT(silentSendInplace(delta, b.size(), prng, chl));

            CoeffCtx::copy(mB.begin(), mB.begin() + b.size(), b.begin());
            //std::memcpy(b.data(), mB.data(), b.size() * CoeffCtx::bytesF);
            clear();

            setTimePoint("SilentVoleSender.expand.ldpc.msgCpy");
            MC_END();
        }

        // The native OT extension interface of silent
        // OT. The receiver does not get to specify 
        // which OT message they receiver. Instead
        // the protocol picks them at random. Use the 
        // send(...) interface for the normal behavior.
        task<> silentSendInplace(
            F delta,
            u64 n,
            PRNG& prng,
            Socket& chl)
        {
            MC_BEGIN(task<>, this, delta, n, &prng, &chl,
                deltaShare = block{},
                X = block{},
                hash = std::array<u8, 32>{}
            );
            setTimePoint("SilentVoleSender.ot.enter");


            if (isConfigured() == false)
            {
                // first generate 128 normal base OTs
                configure(n, SilentBaseType::BaseExtend);
                //                 configure(n, SilentBaseType::Base);
            }

            if (mRequestedNumOTs != n)
                throw std::invalid_argument("n does not match the requested number of OTs via configure(...). " LOCATION);

            if (mGen.hasBaseOts() == false)
            {
                // recvs data
                MC_AWAIT(genSilentBaseOts(prng, chl, delta));
            }

            setTimePoint("SilentVoleSender.start");
            //gTimer.setTimePoint("SilentVoleSender.iknp.base2");

            //if (mMalType == SilentSecType::Malicious)
            //{
            //  deltaShare = mNoiseDeltaShares.back();
            //  mNoiseDeltaShares.pop_back();
            //}

            // allocate B
            CoeffCtx::resize(mB, 0);
            CoeffCtx::resize(mB, mN2);

            if (mTimer)
                mGen.setTimer(*mTimer);

            // program the output the PPRF to be secret shares of
            // our secret share of delta * noiseVals. The receiver
            // can then manually add their shares of this to the
            // output of the PPRF at the correct locations.
            MC_AWAIT(mGen.expand(chl, mNoiseDeltaShares, prng.get(), mB,
                PprfOutputFormat::Interleaved, true, mNumThreads));
            setTimePoint("SilentVoleSender.expand.pprf");

            if (mDebug)
            {
                MC_AWAIT(checkRT(chl, delta));
                setTimePoint("SilentVoleSender.expand.checkRT");
            }

            //if (mMalType == SilentSecType::Malicious)
            //{
            //  MC_AWAIT(chl.recv(X));
            //  hash = ferretMalCheck(X, deltaShare);
            //  MC_AWAIT(chl.send(std::move(hash)));
            //}

            switch (mMultType)
            {
            case osuCrypto::MultType::ExConv7x24:
            case osuCrypto::MultType::ExConv21x24:
                if (mTimer) {
                    mExConvEncoder.setTimer(getTimer());
                }
                mExConvEncoder.dualEncode<F, CoeffCtx>(mB.begin());
                break;
            default:
                throw RTE_LOC;
                break;
            }

            CoeffCtx::resize(mB, mRequestedNumOTs);


            mState = State::Default;
            mNoiseDeltaShares.clear();

            MC_END();
        }

        bool mDebug = false;

        task<> checkRT(Socket& chl, F delta) const
        {
            MC_BEGIN(task<>, this, &chl, delta);
            MC_AWAIT(chl.send(delta));
            MC_AWAIT(chl.send(mB));
            MC_AWAIT(chl.send(mNoiseDeltaShares));
            MC_END();
        }

        std::array<u8, 32> ferretMalCheck(block X, block deltaShare)
        {

            auto xx = X;
            block sum0 = ZeroBlock;
            block sum1 = ZeroBlock;
            for (u64 i = 0; i < (u64)mB.size(); ++i)
            {
                block low, high;
                xx.gf128Mul(mB[i], low, high);
                sum0 = sum0 ^ low;
                sum1 = sum1 ^ high;

                xx = xx.gf128Mul(X);
            }

            block mySum = sum0.gf128Reduce(sum1);

            std::array<u8, 32> myHash;
            RandomOracle ro(32);
            ro.Update(mySum ^ deltaShare);
            ro.Final(myHash);

            return myHash;
            //chl.send(myHash);
        }

        void clear()
        {
            mB = {};
            mGen.clear();
        }
    };

}

#endif