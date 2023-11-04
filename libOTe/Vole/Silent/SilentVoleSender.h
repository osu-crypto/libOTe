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
#include <libOTe/Tools/SilentPprf.h>
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h>
#include <libOTe/Tools/LDPC/LdpcEncoder.h>
#include <libOTe/Tools/QuasiCyclicCode.h>
#include <libOTe/Tools/EACode/EACode.h>
#include <libOTe/Tools/ExConvCode/ExConvCode.h>
//#define NO_HASH

namespace osuCrypto
{

    class SilentVoleSender : public TimerAdapter
    {
    public:
        static constexpr u64 mScaler = 2;

        enum class State
        {
            Default,
            Configured,
            HasBase
        };


        State mState = State::Default;

        SilentMultiPprfSender mGen;

        u64 mRequestedNumOTs = 0;
        u64 mN2 = 0;
        u64 mN = 0;
        u64 mNumPartitions = 0;
        u64 mSizePer = 0;
        u64 mNumThreads = 1;
        std::vector<std::array<block, 2>> mGapOts;
        SilentBaseType mBaseType;
        //block mDelta;
        std::vector<block> mNoiseDeltaShares;

        SilentSecType mMalType = SilentSecType::SemiHonest;

#ifdef ENABLE_SOFTSPOKEN_OT
        SoftSpokenMalOtSender mOtExtSender;
        SoftSpokenMalOtReceiver mOtExtRecver;
#endif

        MultType mMultType = DefaultMultType;
#ifdef ENABLE_INSECURE_SILVER
        SilverEncoder mEncoder;
#endif
        ExConvCode mExConvEncoder;
        EACode mEAEncoder;

#ifdef ENABLE_BITPOLYMUL
        QuasiCyclicCode mQuasiCyclicEncoder;
#endif

        //span<block> mB;
        //u64 mBackingSize = 0;
        //std::unique_ptr<block[]> mBacking;
        AlignedUnVector<block> mB;

        /////////////////////////////////////////////////////
        // The standard OT extension interface
        /////////////////////////////////////////////////////

        // the number of IKNP base OTs that should be set.
        u64 baseOtCount() const;

        // returns true if the IKNP base OTs are currently set.
        bool hasBaseOts() const;

        // sets the IKNP base OTs that are then used to extend
        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices);

        // use the default base OT class to generate the
        // IKNP base OTs that are required.
        task<> genBaseOts(PRNG& prng, Socket& chl)
        {
            return mOtExtSender.genBaseOts(prng, chl);
        }

        /////////////////////////////////////////////////////
        // The native silent OT extension interface
        /////////////////////////////////////////////////////

        u64 baseVoleCount() const {
            return mNumPartitions + mGapOts.size() + 1 * (mMalType == SilentSecType::Malicious);
        }

        // Generate the silent base OTs. If the Iknp 
        // base OTs are set then we do an IKNP extend,
        // otherwise we perform a base OT protocol to
        // generate the needed OTs.
        task<> genSilentBaseOts(PRNG& prng, Socket& chl, cp::optional<block> delta = {});

        // configure the silent OT extension. This sets
        // the parameters and figures out how many base OT
        // will be needed. These can then be ganerated for
        // a different OT extension or using a base OT protocol.
        void configure(
            u64 n,
            SilentBaseType baseType = SilentBaseType::BaseExtend,
            u64 secParam = 128);

        // return true if this instance has been configured.
        bool isConfigured() const { return mState != State::Default; }

        // Returns how many base OTs the silent OT extension
        // protocol will needs.
        u64 silentBaseOtCount() const;

        // Set the externally generated base OTs. This choice
        // bits must be the one return by sampleBaseChoiceBits(...).
        void setSilentBaseOts(
            span<std::array<block, 2>> sendBaseOts,
            span<block> sendBaseVole);

        // The native OT extension interface of silent
        // OT. The receiver does not get to specify 
        // which OT message they receiver. Instead
        // the protocol picks them at random. Use the 
        // send(...) interface for the normal behavior.
        task<> silentSend(
            block delta,
            span<block> b,
            PRNG& prng,
            Socket& chls);

        // The native OT extension interface of silent
        // OT. The receiver does not get to specify 
        // which OT message they receiver. Instead
        // the protocol picks them at random. Use the 
        // send(...) interface for the normal behavior.
        task<> silentSendInplace(
            block delta,
            u64 n,
            PRNG& prng,
            Socket& chls);

        bool mDebug = false;

        task<> checkRT(Socket& chl, block delta) const;

        std::array<u8,32> ferretMalCheck(block X, block deltaShare);

        void clear();
    };

}

#endif