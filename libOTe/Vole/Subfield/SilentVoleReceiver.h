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
#include <cryptoTools/Common/Timer.h>
#include <libOTe/Tools/Tools.h>
#include "libOTe/Tools/Subfield/SubfieldPprf.h"
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h>
#include <libOTe/Tools/LDPC/LdpcEncoder.h>
#include <libOTe/Tools/Coproto.h>
#include <libOTe/Tools/Subfield/ExConvCode.h>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/Vole/Subfield/NoisyVoleReceiver.h>
#include <libOTe/Vole/Subfield/NoisyVoleSender.h>

namespace osuCrypto::Subfield
{


    template<typename TypeTrait>
    class SilentSubfieldVoleReceiver : public TimerAdapter
    {
    public:
        using F = typename TypeTrait::F;
        using G = typename TypeTrait::G;

        static constexpr u64 mScaler = 2;

        enum class State
        {
            Default,
            Configured,
            HasBase
        };

        // The current state of the protocol
        State mState = State::Default;

        // The number of OTs the user requested.
        u64 mRequestedNumOTs = 0;

        // The number of OTs actually produced (at least the number requested).
        u64 mN = 0;

        // The length of the noisy vectors (2 * mN for the silver codes).
        u64 mN2 = 0;

        // We perform regular LPN, so this is the
        // size of the each chunk. 
        u64 mSizePer = 0;

        u64 mNumPartitions = 0;

        // The noisy coordinates.
        std::vector<u64> mS;

        // What type of Base OTs should be performed.
        SilentBaseType mBaseType;

        // The matrix multiplication type which compresses 
        // the sparse vector.
        MultType mMultType = DefaultMultType;

        ExConvCode<TypeTrait> mExConvEncoder;

        // The multi-point punctured PRF for generating
        // the sparse vectors.
        SilentSubfieldPprfReceiver<TypeTrait> mGen;

        // The internal buffers for holding the expanded vectors.
        // mA + mB = mC * delta
        AlignedUnVector<F> mA;

        // mA + mB = mC * delta
        AlignedUnVector<G> mC;

        std::vector<block> mGapOts;

        u64 mNumThreads = 1;

        bool mDebug = false;

        BitVector mIknpSendBaseChoice, mGapBaseChoice;

        SilentSecType mMalType = SilentSecType::SemiHonest;

        block mMalCheckSeed, mMalCheckX, mDeltaShare;

        AlignedVector<F> mNoiseDeltaShare;
        AlignedVector<G> mNoiseValues;


#ifdef ENABLE_SOFTSPOKEN_OT
        SoftSpokenMalOtSender mOtExtSender;
        SoftSpokenMalOtReceiver mOtExtRecver;
#endif

        //        // sets the Iknp base OTs that are then used to extend
        //        void setBaseOts(
        //            span<std::array<block, 2>> baseSendOts);
        //
        //        // return the number of base OTs IKNP needs
        //        u64 baseOtCount() const;

        u64 baseVoleCount() const
        {
            return mNumPartitions + mGapOts.size() + 1 * (mMalType == SilentSecType::Malicious);
        }

        //        // returns true if the IKNP base OTs are currently set.
        //        bool hasBaseOts() const;
        //
                // returns true if the silent base OTs are set.
        bool hasSilentBaseOts() const {
            return mGen.hasBaseOts();
        };
        //
        //        // Generate the IKNP base OTs
        //        task<> genBaseOts(PRNG& prng, Socket& chl) ;

        // Generate the silent base OTs. If the Iknp 
        // base OTs are set then we do an IKNP extend,
        // otherwise we perform a base OT protocol to
        // generate the needed OTs.
        task<> genSilentBaseOts(PRNG& prng, Socket& chl)
        {
            using BaseOT = DefaultBaseOT;


            MC_BEGIN(task<>, this, &prng, &chl,
                choice = BitVector{},
                bb = BitVector{},
                msg = AlignedUnVector<block>{},
                baseVole = std::vector<block>{},
                baseOt = BaseOT{},
                chl2 = Socket{},
                prng2 = std::move(PRNG{}),
                noiseVals = std::vector<G>{},
                noiseDeltaShares = std::vector<F>{},
                nv = NoisySubfieldVoleReceiver<TypeTrait>{}

            );

            setTimePoint("SilentVoleReceiver.genSilent.begin");
            if (isConfigured() == false)
                throw std::runtime_error("configure must be called first");

            choice = sampleBaseChoiceBits(prng);
            msg.resize(choice.size());

            // sample the noise vector noiseVals such that we will compute
            //
            //  C = (000 noiseVals[0] 0000 ... 000 noiseVals[p] 000)
            //
            // and then we want secret shares of C * delta. As a first step
            // we will compute secret shares of
            //
            // delta * noiseVals
            //
            // and store our share in voleDeltaShares. This party will then
            // compute their share of delta * C as what comes out of the PPRF
            // plus voleDeltaShares[i] added to the appreciate spot. Similarly, the
            // other party will program the PPRF to output their share of delta * noiseVals.
            //
            noiseVals = sampleBaseVoleVals(prng);
            noiseDeltaShares.resize(noiseVals.size());
            if (mTimer)
                nv.setTimer(*mTimer);

            if (mBaseType == SilentBaseType::BaseExtend)
            {
#ifdef ENABLE_SOFTSPOKEN_OT

                if (mOtExtSender.hasBaseOts() == false)
                {
                    msg.resize(msg.size() + mOtExtSender.baseOtCount());
                    bb.resize(mOtExtSender.baseOtCount());
                    bb.randomize(prng);
                    choice.append(bb);

                    MC_AWAIT(mOtExtRecver.receive(choice, msg, prng, chl));

                    mOtExtSender.setBaseOts(
                        span<block>(msg).subspan(
                            msg.size() - mOtExtSender.baseOtCount(),
                            mOtExtSender.baseOtCount()),
                        bb);

                    msg.resize(msg.size() - mOtExtSender.baseOtCount());
                    MC_AWAIT(nv.receive(noiseVals, noiseDeltaShares, prng, mOtExtSender, chl));
                }
                else
                {
                    chl2 = chl.fork();
                    prng2.SetSeed(prng.get());


                    MC_AWAIT(
                        macoro::when_all_ready(
                            nv.receive(noiseVals, noiseDeltaShares, prng2, mOtExtSender, chl2),
                            mOtExtRecver.receive(choice, msg, prng, chl)
                        ));
                }
#else
                throw std::runtime_error("soft spoken must be enabled");
#endif
            }
            else
            {
                chl2 = chl.fork();
                prng2.SetSeed(prng.get());
                MC_AWAIT(baseOt.receive(choice, msg, prng, chl));
                MC_AWAIT(nv.receive(noiseVals, noiseDeltaShares, prng2, baseOt, chl2));
            }

            setSilentBaseOts(msg, noiseDeltaShares);
            setTimePoint("SilentVoleReceiver.genSilent.done");
            MC_END();
        };

        // configure the silent OT extension. This sets
        // the parameters and figures out how many base OT
        // will be needed. These can then be ganerated for
        // a different OT extension or using a base OT protocol.
        void configure(
            u64 numOTs,
            SilentBaseType type = SilentBaseType::BaseExtend,
            u64 secParam = 128)
        {
            mState = State::Configured;
            u64 gap = 0;
            mBaseType = type;

            switch (mMultType)
            {
            case osuCrypto::MultType::ExConv7x24:
            case osuCrypto::MultType::ExConv21x24:

                SubfieldExConvConfigure(numOTs, 128, mMultType, mRequestedNumOTs, mNumPartitions, mSizePer, mN2, mN, mExConvEncoder);
                break;
            default:
                throw RTE_LOC;
                break;
            }

            mGapOts.resize(gap);
            mGen.configure(mSizePer, mNumPartitions);
        }

        // return true if this instance has been configured.
        bool isConfigured() const { return mState != State::Default; }

        // Returns how many base OTs the silent OT extension
        // protocol will needs.
        u64 silentBaseOtCount() const
        {
            if (isConfigured() == false)
                throw std::runtime_error("configure must be called first");

            return mGen.baseOtCount() + mGapOts.size();

        }

        // The silent base OTs must have specially set base OTs.
        // This returns the choice bits that should be used.
        // Call this is you want to use a specific base OT protocol
        // and then pass the OT messages back using setSilentBaseOts(...).
        BitVector sampleBaseChoiceBits(PRNG& prng) {

            if (isConfigured() == false)
                throw std::runtime_error("configure(...) must be called first");

            auto choice = mGen.sampleChoiceBits(mN2, getPprfFormat(), prng);

            mGapBaseChoice.resize(mGapOts.size());
            mGapBaseChoice.randomize(prng);
            choice.append(mGapBaseChoice);

            return choice;
        }

        std::vector<G> sampleBaseVoleVals(PRNG& prng)
        {
            if (isConfigured() == false)
                throw RTE_LOC;
            if (mGapBaseChoice.size() != mGapOts.size())
                throw std::runtime_error("sampleBaseChoiceBits must be called before sampleBaseVoleVals. " LOCATION);

            // sample the values of the noisy coordinate of c
            // and perform a noicy vole to get x+y = mD * c
            auto w = mNumPartitions + mGapOts.size();
            //std::vector<block> y(w);
            mNoiseValues.resize(w);
            prng.get(mNoiseValues.data(), mNoiseValues.size());

            mS.resize(mNumPartitions);
            mGen.getPoints(mS, getPprfFormat());

            // todo
            std::vector<u64> tmp = mS;
            std::sort(tmp.begin(), tmp.end());

            auto j = mNumPartitions * mSizePer;

            for (u64 i = 0; i < (u64)mGapBaseChoice.size(); ++i)
            {
                if (mGapBaseChoice[i])
                {
                    mS.push_back(j + i);
                }
            }

            //          if (mMalType == SilentSecType::Malicious)
            //          {
            //
            //            mMalCheckSeed = prng.get();
            //            mMalCheckX = ZeroBlock;
            //            auto yIter = mNoiseValues.begin();
            //
            //            for (u64 i = 0; i < mNumPartitions; ++i)
            //            {
            //              auto s = mS[i];
            //              auto xs = mMalCheckSeed.gf128Pow(s + 1);
            //              mMalCheckX = mMalCheckX ^ xs.gf128Mul(*yIter);
            //              ++yIter;
            //            }
            //
            //            auto sIter = mS.begin() + mNumPartitions;
            //            for (u64 i = 0; i < mGapBaseChoice.size(); ++i)
            //            {
            //              if (mGapBaseChoice[i])
            //              {
            //                auto s = *sIter;
            //                auto xs = mMalCheckSeed.gf128Pow(s + 1);
            //                mMalCheckX = mMalCheckX ^ xs.gf128Mul(*yIter);
            //                ++sIter;
            //              }
            //              ++yIter;
            //            }
            //
            //
            //            std::vector<block> y(mNoiseValues.begin(), mNoiseValues.end());
            //            y.push_back(mMalCheckX);
            //            return y;
            //          }

            return std::vector<G>(mNoiseValues.begin(), mNoiseValues.end());
        }

        // Set the externally generated base OTs. This choice
        // bits must be the one return by sampleBaseChoiceBits(...).
        void setSilentBaseOts(span<block> recvBaseOts,
            span<F> noiseDeltaShare)
        {
            if (isConfigured() == false)
                throw std::runtime_error("configure(...) must be called first.");

            if (static_cast<u64>(recvBaseOts.size()) != silentBaseOtCount())
                throw std::runtime_error("wrong number of silent base OTs");

            auto genOts = recvBaseOts.subspan(0, mGen.baseOtCount());
            auto gapOts = recvBaseOts.subspan(mGen.baseOtCount(), mGapOts.size());

            mGen.setBase(genOts);
            std::copy(gapOts.begin(), gapOts.end(), mGapOts.begin());

            //          if (mMalType == SilentSecType::Malicious)
            //          {
            //            mDeltaShare = noiseDeltaShare.back();
            //            noiseDeltaShare = noiseDeltaShare.subspan(0, noiseDeltaShare.size() - 1);
            //          }

            mNoiseDeltaShare = AlignedVector<F>(noiseDeltaShare.begin(), noiseDeltaShare.end());

            mState = State::HasBase;
        }

        // Perform the actual OT extension. If silent
        // base OTs have been generated or set, then
        // this function is non-interactive. Otherwise
        // the silent base OTs will automatically be performed.
        task<> silentReceive(
            span<G> c,
            span<F> b,
            PRNG& prng,
            Socket& chl)
        {
            MC_BEGIN(task<>, this, c, b, &prng, &chl);
            if (c.size() != b.size())
                throw RTE_LOC;

            MC_AWAIT(silentReceiveInplace(c.size(), prng, chl));

            std::memcpy(c.data(), mC.data(), c.size() * TypeTrait::bytesG);
            std::memcpy(b.data(), mA.data(), b.size() * TypeTrait::bytesF);
            clear();
            MC_END();
        }

        // Perform the actual OT extension. If silent
        // base OTs have been generated or set, then
        // this function is non-interactive. Otherwise
        // the silent base OTs will automatically be performed.
        task<> silentReceiveInplace(
            u64 n,
            PRNG& prng,
            Socket& chl)
        {
            MC_BEGIN(task<>, this, n, &prng, &chl,
                gapVals = std::vector<F>{},
                myHash = std::array<u8, 32>{},
                theirHash = std::array<u8, 32>{}
            );
            gTimer.setTimePoint("SilentVoleReceiver.ot.enter");

            if (isConfigured() == false)
            {
                // first generate 128 normal base OTs
                configure(n, SilentBaseType::BaseExtend);
                //                 configure(n, SilentBaseType::Base);
            }

            if (mRequestedNumOTs != n)
                throw std::invalid_argument("n does not match the requested number of OTs via configure(...). " LOCATION);

            if (hasSilentBaseOts() == false)
            {
                MC_AWAIT(genSilentBaseOts(prng, chl));
            }

            // allocate mA
            mA.resize(0);
            mA.resize(mN2);

            setTimePoint("SilentVoleReceiver.alloc");

            // allocate the space for mC
            mC.resize(0);
            mC.resize(mN2, AllocType::Zeroed);
            setTimePoint("SilentVoleReceiver.alloc.zero");

            // derandomize the random OTs for the gap
            // to have the desired correlation.
            gapVals.resize(mGapOts.size());

            if (gapVals.size())
                MC_AWAIT(chl.recv(gapVals));

            for (auto g : rng(mGapOts.size()))
            {
                auto aa = mA.subspan(mNumPartitions * mSizePer);
                auto cc = mC.subspan(mNumPartitions * mSizePer);

                auto noise = mNoiseValues.subspan(mNumPartitions);
                auto noiseShares = mNoiseDeltaShare.subspan(mNumPartitions);

                if (mGapBaseChoice[g])
                {
                    cc[g] = noise[g];
                    aa[g] = TypeTrait::minus(
                            TypeTrait::minus(gapVals[g], TypeTrait::fromBlock(AES(mGapOts[g]).ecbEncBlock(ZeroBlock))),
                            noiseShares[g]);
                }
                else
                {
                    aa[g] = TypeTrait::fromBlock(mGapOts[g]);
                }
            }

            setTimePoint("SilentVoleReceiver.recvGap");



            if (mTimer)
                mGen.setTimer(*mTimer);
            // expand the seeds into mA
            MC_AWAIT(mGen.expand(chl, prng, mA.subspan(0, mNumPartitions * mSizePer), PprfOutputFormat::Interleaved, true, mNumThreads));

            setTimePoint("SilentVoleReceiver.expand.pprf_transpose");

            // populate the noisy coordinates of mC and
            // update mA to be a secret share of mC * delta
            for (u64 i = 0; i < mNumPartitions; ++i)
            {
                auto pnt = mS[i];
                mC[pnt] = mNoiseValues[i];
                mA[pnt] = TypeTrait::minus(mA[pnt], mNoiseDeltaShare[i]);
            }


            if (mDebug)
            {
                MC_AWAIT(checkRT(chl));
                setTimePoint("SilentVoleReceiver.expand.checkRT");
            }


            //               if (mMalType == SilentSecType::Malicious)
            //               {
            //                 MC_AWAIT(chl.send(std::move(mMalCheckSeed)));
            //
            //                 myHash = ferretMalCheck(mDeltaShare, mNoiseValues);
            //
            //                 MC_AWAIT(chl.recv(theirHash));
            //
            //                 if (theirHash != myHash)
            //                   throw RTE_LOC;
            //               }

            switch (mMultType)
            {
            case osuCrypto::MultType::ExConv7x24:
            case osuCrypto::MultType::ExConv21x24:
                if (mTimer) {
                    mExConvEncoder.setTimer(getTimer());
                }

                mExConvEncoder.template dualEncode2<F, G>(
                    mA.subspan(0, mExConvEncoder.mCodeSize),
                    mC.subspan(0, mExConvEncoder.mCodeSize)
                    );

                break;
            default:
                throw RTE_LOC;
                break;
            }

            // resize the buffers down to only contain the real elements.
            mA.resize(mRequestedNumOTs);
            mC.resize(mRequestedNumOTs);

            mNoiseValues = {};
            mNoiseDeltaShare = {};

            // make the protocol as done and that
            // mA,mC are ready to be consumed.
            mState = State::Default;

            MC_END();
        }



        // internal.
        task<> checkRT(Socket& chl) const
        {
            MC_BEGIN(task<>, this, &chl,
                B = AlignedVector<F>(mA.size()),
                sparseNoiseDelta = std::vector<F>(mA.size()),
                noiseDeltaShare2 = std::vector<F>(),
                delta = F{}
            );
            //std::vector<block> mB(mA.size());
            MC_AWAIT(chl.recv(delta));
            MC_AWAIT(chl.recv(B));
            MC_AWAIT(chl.recvResize(noiseDeltaShare2));

            for (u64 i = 0; i < mA.size(); i++) {
                F left = TypeTrait::mul(delta, mC[i]);
                F right = TypeTrait::minus(mA[i], B[i]);
                if (left != right) {
                    throw RTE_LOC;
                }
            }

            //check that at locations  mS[0],...,mS[..]
            // that we hold a sharing mA, mB of
            //
            //  delta * mC = delta * (00000 noiseDeltaShare2[0] 0000 .... 0000 noiseDeltaShare2[m] 0000)
            //
            // where noiseDeltaShare2[i] is at position mS[i] of mC
            //
            // That is, I hold mA, mC s.t.
            //
            //  delta * mC = mA + mB
            //

//               if (noiseDeltaShare2.size() != mNoiseDeltaShare.size())
//                 throw RTE_LOC;
//
//               for (auto i : rng(mNoiseDeltaShare.size()))
//               {
//                 if ((mNoiseDeltaShare[i] ^ noiseDeltaShare2[i]) != mNoiseValues[i].gf128Mul(delta))
//                   throw RTE_LOC;
//               }
//
//               {
//
//                 for (auto i : rng(mNumPartitions* mSizePer))
//                 {
//                   auto iter = std::find(mS.begin(), mS.end(), i);
//                   if (iter != mS.end())
//                   {
//                     auto d = iter - mS.begin();
//
//                     if (mC[i] != mNoiseValues[d])
//                       throw RTE_LOC;
//
//                     if (mNoiseValues[d].gf128Mul(delta) != (mA[i] ^ B[i]))
//                     {
//                       std::cout << "bad vole base correlation, mA[i] + mB[i] != mC[i] * delta" << std::endl;
//                       std::cout << "i     " << i << std::endl;
//                       std::cout << "mA[i] " << mA[i] << std::endl;
//                       std::cout << "mB[i] " << B[i] << std::endl;
//                       std::cout << "mC[i] " << mC[i] << std::endl;
//                       std::cout << "delta " << delta << std::endl;
//                       std::cout << "mA[i] + mB[i] " << (mA[i] ^ B[i]) << std::endl;
//                       std::cout << "mC[i] * delta " << (mC[i].gf128Mul(delta)) << std::endl;
//
//                       throw RTE_LOC;
//                     }
//                   }
//                   else
//                   {
//                     if (mA[i] != B[i])
//                     {
//                       std::cout << mA[i] << " " << B[i] << std::endl;
//                       throw RTE_LOC;
//                     }
//
//                     if (mC[i] != oc::ZeroBlock)
//                       throw RTE_LOC;
//                   }
//                 }
//
//                 u64 d = mNumPartitions;
//                 for (auto j : rng(mGapBaseChoice.size()))
//                 {
//                   auto idx = j + mNumPartitions * mSizePer;
//                   auto aa = mA.subspan(mNumPartitions * mSizePer);
//                   auto bb = B.subspan(mNumPartitions * mSizePer);
//                   auto cc = mC.subspan(mNumPartitions * mSizePer);
//                   auto noise = mNoiseValues.subspan(mNumPartitions);
//                   //auto noiseShare = mNoiseValues.subspan(mNumPartitions);
//                   if (mGapBaseChoice[j])
//                   {
//                     if (mS[d++] != idx)
//                       throw RTE_LOC;
//
//                     if (cc[j] != noise[j])
//                     {
//                       std::cout << "sparse noise vector mC is not the expected value" << std::endl;
//                       std::cout << "i j      " << idx << " " << j << std::endl;
//                       std::cout << "mC[i]    " << cc[j] << std::endl;
//                       std::cout << "noise[j] " << noise[j] << std::endl;
//                       throw RTE_LOC;
//                     }
//
//                     if (noise[j].gf128Mul(delta) != (aa[j] ^ bb[j]))
//                     {
//
//                       std::cout << "bad vole base GAP correlation, mA[i] + mB[i] != mC[i] * delta" << std::endl;
//                       std::cout << "i     " << idx << std::endl;
//                       std::cout << "mA[i] " << aa[j] << std::endl;
//                       std::cout << "mB[i] " << bb[j] << std::endl;
//                       std::cout << "mC[i] " << cc[j] << std::endl;
//                       std::cout << "delta " << delta << std::endl;
//                       std::cout << "mA[i] + mB[i] " << (aa[j] ^ bb[j]) << std::endl;
//                       std::cout << "mC[i] * delta " << (cc[j].gf128Mul(delta)) << std::endl;
//                       std::cout << "noise * delta " << (noise[j].gf128Mul(delta)) << std::endl;
//                       throw RTE_LOC;
//                     }
//
//                   }
//                   else
//                   {
//                     if (aa[j] != bb[j])
//                       throw RTE_LOC;
//
//                     if (cc[j] != oc::ZeroBlock)
//                       throw RTE_LOC;
//                   }
//                 }
//
//                 if (d != mS.size())
//                   throw RTE_LOC;
//               }


               //{

               //	auto cDelta = B;
               //	for (u64 i = 0; i < cDelta.size(); ++i)
               //		cDelta[i] = cDelta[i] ^ mA[i];

               //	std::vector<block> exp(mN2);
               //	for (u64 i = 0; i < mNumPartitions; ++i)
               //	{
               //		auto j = mS[i];
               //		exp[j] = noiseDeltaShare2[i];
               //	}

               //	auto iter = mS.begin() + mNumPartitions;
               //	for (u64 i = 0, j = mNumPartitions * mSizePer; i < mGapOts.size(); ++i, ++j)
               //	{
               //		if (mGapBaseChoice[i])
               //		{
               //			if (*iter != j)
               //				throw RTE_LOC;
               //			++iter;

               //			exp[j] = noiseDeltaShare2[mNumPartitions + i];
               //		}
               //	}

               //	if (iter != mS.end())
               //		throw RTE_LOC;

               //	bool failed = false;
               //	for (u64 i = 0; i < mN2; ++i)
               //	{
               //		if (neq(cDelta[i], exp[i]))
               //		{
               //			std::cout << i << " / " << mN2 <<
               //				" cd = " << cDelta[i] <<
               //				" exp= " << exp[i] << std::endl;
               //			failed = true;
               //		}
               //	}

               //	if (failed)
               //		throw RTE_LOC;

               //	std::cout << "debug check ok" << std::endl;
               //}

            MC_END();
        }

        std::array<u8, 32> ferretMalCheck(
            block deltaShare,
            span<block> y)
        {

            block xx = mMalCheckSeed;
            block sum0 = ZeroBlock;
            block sum1 = ZeroBlock;


            for (u64 i = 0; i < (u64)mA.size(); ++i)
            {
                block low, high;
                xx.gf128Mul(mA[i], low, high);
                sum0 = sum0 ^ low;
                sum1 = sum1 ^ high;
                //mySum = mySum ^ xx.gf128Mul(mA[i]);

                // xx = mMalCheckSeed^{i+1}
                xx = xx.gf128Mul(mMalCheckSeed);
            }
            block mySum = sum0.gf128Reduce(sum1);

            std::array<u8, 32> myHash;
            RandomOracle ro(32);
            ro.Update(mySum ^ deltaShare);
            ro.Final(myHash);
            return myHash;
        }

        PprfOutputFormat getPprfFormat()
        {
            return PprfOutputFormat::Interleaved;
        }

        void clear()
        {
            mS = {};
            mA = {};
            mC = {};
            mGen.clear();
            mGapBaseChoice = {};
        }
    };
}
#endif