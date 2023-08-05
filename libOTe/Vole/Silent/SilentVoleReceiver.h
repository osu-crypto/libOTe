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
#include <libOTe/Tools/SilentPprf.h>
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h>
#include <libOTe/Tools/LDPC/LdpcEncoder.h>
#include <libOTe/Tools/EACode/EACode.h>
#include <libOTe/Tools/Coproto.h>
#include <libOTe/Tools/QuasiCyclicCode.h>
#include <libOTe/Tools/ExConvCode/ExConvCode.h>

namespace osuCrypto
{


    // For more documentation see SilentOtExtSender.
    class SilentVoleReceiver : public TimerAdapter
    {
    public:
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

#ifdef ENABLE_INSECURE_SILVER
        // The silver encoder.
        SilverEncoder mEncoder;
#endif

        ExConvCode mExConvEncoder;
        EACode mEAEncoder;

#ifdef ENABLE_BITPOLYMUL
        QuasiCyclicCode mQuasiCyclicEncoder;
#endif

        // The multi-point punctured PRF for generating
        // the sparse vectors.
        SilentMultiPprfReceiver mGen;

        // The internal buffers for holding the expanded vectors.
        // mA + mB = mC * delta
        AlignedUnVector<block> mA;

        // mA + mB = mC * delta
        AlignedUnVector<block> mC;

        std::vector<block> mGapOts;

        u64 mNumThreads = 1;

        bool mDebug = false;

        BitVector mIknpSendBaseChoice, mGapBaseChoice;

        SilentSecType mMalType  = SilentSecType::SemiHonest;

        block mMalCheckSeed, mMalCheckX, mDeltaShare;
        
        AlignedVector<block> mNoiseDeltaShare, mNoiseValues;


#ifdef ENABLE_SOFTSPOKEN_OT
        SoftSpokenMalOtSender mOtExtSender;
        SoftSpokenMalOtReceiver mOtExtRecver;
#endif

        // sets the Iknp base OTs that are then used to extend
        void setBaseOts(
            span<std::array<block, 2>> baseSendOts);

        // return the number of base OTs IKNP needs
        u64 baseOtCount() const;

        u64 baseVoleCount() const
        {
            return mNumPartitions + mGapOts.size() + 1 * (mMalType == SilentSecType::Malicious);
        }

        // returns true if the IKNP base OTs are currently set.
        bool hasBaseOts() const;

        // returns true if the silent base OTs are set.
        bool hasSilentBaseOts() const {
            return mGen.hasBaseOts();
        };

        // Generate the IKNP base OTs
        task<> genBaseOts(PRNG& prng, Socket& chl) ;

        // Generate the silent base OTs. If the Iknp 
        // base OTs are set then we do an IKNP extend,
        // otherwise we perform a base OT protocol to
        // generate the needed OTs.
        task<> genSilentBaseOts(PRNG& prng, Socket& chl);
        
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

        // The silent base OTs must have specially set base OTs.
        // This returns the choice bits that should be used.
        // Call this is you want to use a specific base OT protocol
        // and then pass the OT messages back using setSilentBaseOts(...).
        BitVector sampleBaseChoiceBits(PRNG& prng);

        std::vector<block> sampleBaseVoleVals(PRNG& prng);

        // Set the externally generated base OTs. This choice
        // bits must be the one return by sampleBaseChoiceBits(...).
        void setSilentBaseOts(span<block> recvBaseOts,
            span<block> voleBase);

        // Perform the actual OT extension. If silent
        // base OTs have been generated or set, then
        // this function is non-interactive. Otherwise
        // the silent base OTs will automatically be performed.
        task<> silentReceive(
            span<block> c,
            span<block> a,
            PRNG & prng,
            Socket & chl);

        // Perform the actual OT extension. If silent
        // base OTs have been generated or set, then
        // this function is non-interactive. Otherwise
        // the silent base OTs will automatically be performed.
        task<> silentReceiveInplace(
            u64 n,
            PRNG& prng,
            Socket& chl);



        // internal.
        task<> checkRT(Socket& chls) const;

        std::array<u8, 32> ferretMalCheck(
            block deltaShare,
            span<block> y);

        PprfOutputFormat getPprfFormat()
        {
            return PprfOutputFormat::Interleaved;
        }

        void clear();
    };
}
#endif