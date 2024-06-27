#pragma once
#include "cryptoTools/Common/Defines.h"
#include <vector>
#include <unordered_map>
#include "cryptoTools/Common/CLP.h"
#include "EnumeratorTools.h"


#ifdef ENABLE_BOOST
#include <boost/multiprecision/cpp_bin_float.hpp> 
#include <boost/multiprecision/cpp_int.hpp>
#ifdef ENABLE_GMP
#include <boost/multiprecision/gmp.hpp>
#include "gmp.h"
#include "gmpxx.h"
#endif

namespace osuCrypto
{

    template<typename T>
    struct EnumOne
    {
        // length of the code
        i64 n = 0;

        // input weight
        i64 w = 0;

        // output weight
        i64 h = 0;

        // the state size of the convolution
        i64 stateSize = 0;

        // verbose
        u64 verbose = 0;

        // the number of input zeros each almost termination requires.
        i64 inZerosPerAlmostTerm = 1;

        // the number of output ones each almost termination requires.
        i64 outOnesPerAlmostTerm = 0;

        // the number of output zeros each almost termination requires.
        i64 outZerosPerAlmostTerm = 0;


        i64 bMax = 0;

        void init(i64 n_, i64 w_, i64 h_, i64 stateSize_, u64 v_)
        {
            n = n_;
            w = w_;
            h = h_;
            stateSize = stateSize_;
            verbose = v_;

            if (stateSize < 0)
                throw RTE_LOC;

            // one or two.
            outOnesPerAlmostTerm = std::min<i64>(2, stateSize);

            outZerosPerAlmostTerm = stateSize - 1;

            bMax = outOnesPerAlmostTerm;
        }
        struct VParam;
        struct RParam;


        struct BParam : EnumOne
        {
            // does the last run terminate?
            i64 b = 0;

            // 1 if the last run has special termination.
            i64 d = 0;

            // the maximum number of almost terminations
            u64 vMax = 0;


            BParam(EnumOne& e, i64 b_)
                : EnumOne(e)
            {
                if (n == 0)
                    throw RTE_LOC;
                if (b_ > bMax)
                    throw RTE_LOC;

                b = b_ ? 1 : 0;
                d = b_ / 2;

                if (e.stateSize == 1)
                {
                    vMax = h - 1;
                }
                else
                {
                    auto inputZeros = n - w;
                    auto outputZeros = n - h - d * (e.stateSize - 1);
                    auto outputOnes = h - d;


                    vMax = std::min<i64>(
                        inputZeros / inZerosPerAlmostTerm,
                        outputOnes / outOnesPerAlmostTerm);

                    vMax = std::min<i64>(
                        vMax,
                        outputZeros / outZerosPerAlmostTerm);
                }
            }

            VParam setV(i64 v)
            {
                return VParam(*this, v);
            }
        };

        BParam setB(i64 b)
        {
            return BParam(*this, b);
        }

        struct VParam : BParam
        {
            // the number of almost terminations
            u64 v = 0;

            // rMax: the maximum number of runs we need to consider.
            i64 rMax = 0;


            // set the number of almost terminations.
            // This is turn determines rMax.
            VParam(BParam& bp, u64 v_)
                : BParam(bp)
            {
                if (v_ > this->vMax)
                    throw RTE_LOC;

                v = v_;

                auto inputZeros = this->n - this->w - v * this->inZerosPerAlmostTerm;
                auto inputOnes = this->w;
                auto outputZeros = this->n - this->h - this->d * (this->stateSize - 1) - v * this->outZerosPerAlmostTerm;
                auto outputOnes = this->h - this->d - v * this->outOnesPerAlmostTerm;

                // rMax: the maximum number of runs we need to consider.
                // if the output looks like 10000 10000 10000 ...
                rMax = divCeil(this->n, this->stateSize + 1);

                // Each run must start and terminate with a 1.
                // We require at least inputOnes >= r+r' = 2 r - 1 + b input ones.
                // (inputOnes + 1-b)/2 >= r
                rMax = std::min<i64>(rMax, (inputOnes + 1 - this->b) / 2);

                // we require at least r ones in the output.
                rMax = std::min<i64>(rMax, outputOnes);

                // we require at least outputZeros>=(r-1+b)*stateSize output zeros
                // outputZeros/stateSize -b + 1 >= r
                rMax = std::min<i64>(rMax, outputZeros / this->stateSize - this->b + 1);
            }


            auto setR(u64 r)
            {
                return RParam(*this, r);
            }

        };


        struct RParam : VParam
        {


            i64 r = 0;

            // the number of runs that terminate.
            i64 terminatingRuns = 0;

            // the number of output k where zeros can be place 
            // that have a cap of stateSize - 1. For each run,
            // all but the last 1 can have stateSize-1 zeros to its 
            // right. There are h - r such ones. If the last run 
            // doesn't terminate, then the last one can also have 
            // stateSize - 1 zeros to its right.
            //u64 numOutputZeroBinsWthCap = 0;

            // the maximum number of free zeros within a run that we need to consider.
            // we have n-h zeros. of these, stateSize * (r - 1 + b) of them go
            //are used to terminate a run.
            i64 t0Max = 0;


            i64 f1 = 0;
            RParam(VParam& vp, i64 r_)
                :VParam(vp)
            {
                if (r_ > this->rMax)
                    throw RTE_LOC;
                r = r_;

                // the number of runs that terminate.
                terminatingRuns = (r - 1 + this->b);

                // the number of off zeros can not be negative.
                // 
                // z = n - h - (v + d) * (stateSize - 1) - terminatingRuns * stateSize - t0;
                // 
                // t0 <= n - h - (v + d) * (stateSize - 1) - terminatingRuns * stateSize
                if (this->stateSize == 1)
                    t0Max = 0;
                else
                {
                    t0Max = this->n - this->h - (this->v + this->d) * this->outZerosPerAlmostTerm - terminatingRuns * this->stateSize;
                    if (t0Max < 0)
                        throw RTE_LOC;
                }

                //f0 = n - r - terminatingRuns;
                f1 = this->w - r - terminatingRuns;
                if (f1 < 0)
                    throw RTE_LOC;
            }

            i64 getZ(i64 t0)
            {
                auto z = this->n - this->h - (this->v + this->d) * (this->stateSize - 1) - terminatingRuns * this->stateSize - t0;
                if (z < 0)
                    throw RTE_LOC;
                return z;
            }

            i64 getF0(i64 t0)
            {
                auto z = getZ(t0);
                auto f0 = this->n - this->w - z - this->v;
                if (f0 < 0)
                    throw RTE_LOC;
                return f0;
            }

            i64 getG(i64 t0)
            {
                return f1 + getF0(t0);
            }


            //i64 gInput()
            //{
            //}

            T enumerate(i64 t0)
            {

                if (t0 > t0Max)
                    throw RTE_LOC;

                auto z = getZ(t0);
                auto f0 = getF0(t0);

                auto t1 = this->h - this->outOnesPerAlmostTerm * this->v - r;
                if (t1 < 0)
                    throw RTE_LOC;
                if (this->stateSize == 1 && t1 > 0)
                    return 0;

                if (z + f0 + this->v * this->inZerosPerAlmostTerm != this->n - this->w)
                    throw RTE_LOC;
                if (r + terminatingRuns + f1 != this->w)
                    throw RTE_LOC;
                if (z + t0 + terminatingRuns * this->stateSize + (this->v + this->d) * this->outZerosPerAlmostTerm != this->n - this->h)
                    throw RTE_LOC;
                if (r + this->outOnesPerAlmostTerm * this->v + t1 != this->h)
                    throw RTE_LOC;

                auto E1 = ballsBins<T>(z, terminatingRuns + 1);
                auto E2 = choose_<T>(f0 + f1, f0);
                auto E3 = ballsBins<T>(this->v, t1 + 1);
                auto E4 = ballBinCap<T>(t0, this->v + t1, this->stateSize - 2);
                auto E5 = ballsBins<T>(t1 + this->v, terminatingRuns+1);
                auto eg = E1 * E2 * E3 * E4 * E5;

                if (this->verbose > 1)
                    std::cout
                    << " r " << r << "." << this->b << " t0 " << t0 << "  "
                    << "  E1 " << E1 << " = B(" << z << ", " << (terminatingRuns + 1) << ") "
                    << ", E2 " << E2 << " = C(" << (f0 + f1) << ", " << (f0) << ") "
                    << ", E3 " << E3 << " = B(" << this->v << ", " << (t1 + 1) << ") "
                    << ", E4 " << E4 << " = N(" << t0 << ", " << (this->v + t1) << ", " << this->stateSize - 2 << ") "
                    << ", E5 " << E5 << " = B(" << t1 + this->v << ", " << terminatingRuns+1 << ")"
                    << " ->      " << eg << " * 2^-" << getG(t0) << std::endl;

                return eg;
                // total number of items in runs.
                // we have g0p random zeros, then there are (h-r) ones.
                // then there are (r-1+b) runs that terminate, each
                // with stateSize zeros at the end.
                //auto runLen = g0p + h - r + terminatingRuns * stateSize;

                //z = n - h - (v)

                //    g = ;
                ////g = runLen - terminatingRuns * (stateSize - 1);

                //if (g >= n || g0p > g)
                //    throw RTE_LOC;

                //// w', the number of input ones that aren't allocated
                //// to the start or end of a run.
                //i64 remainingInputOnes = w - 2 * r + 1 - b;

                //// the number of input zeros
                //i64 inputZeros = n - w;

                //// z1, the number of input zeros while the convolution is on.
                //i64 inputZerosOn = runLen - remainingInputOnes;

                //// z0, the number of input zeros while the convolution is off.
                //i64 inputZerosOff = inputZeros - inputZerosOn;

                //// h', output ones that are not used to start a run.
                //i64 remainingOutputOnes = h - r;

                //// v, the output zeros that are not used within a run.
                //i64 remainingOutputZeros = n - runLen - r;
                ////assert(remainingOutputZeros == (n - h) - terminatingRuns * stateSize - g0p);

                //// (1) output ones can be assigned to any run.
                //T enumOutputOnes = ballsBins<T>(remainingOutputOnes, r);

                //// (2) output zeros that are one can be assigned anywhere so long
                //// as we dont have stateSize zeros in a row. Balls in k with capacity.
                //T enumOuptutZerosOn = ballBinCap<T>(g0p, numOutputZeroBinsWthCap, stateSize - 1);

                //// (3) the remaining output zeros are assigned to before any run or after the 
                //// last if it terminates.
                //T enumOutputZerosOff = ballsBins<T>(remainingOutputZeros, r + b);

                //// (4') input ones are assigned to an run.
                //T enumInputOnes = ballsBins<T>(remainingInputOnes, r);

                //// (5) input zeros that are On can be assigned to come
                //// after any one.
                //T enumInputZerosOn = ballsBins<T>(inputZerosOn, w - r + 1 - b);


                //auto enumOutputZeros = enumOuptutZerosOn * enumOutputZerosOff;

                //auto eg =
                //    enumInputOnes * enumInputZerosOn *
                //    enumOutputOnes * enumOutputZeros;


                //auto egx = enumerateX(n, w, h, stateSize, r, g0p, b);

                //if (v > 1)
                //    std::cout
                //    << " r " << r << "." << b << " g0 " << g0p
                //    << "    in (" << enumInputZerosOn << ", " << enumInputOnes
                //    << ") out (" << enumOuptutZerosOn << ", " << enumOutputOnes
                //    << ") " << enumOutputZerosOff << "     =      " << eg << " * 2^-" << g << std::endl;
                //return eg;
            }

        };

        inline T enumerate()
        {
            if (n == 0)
                throw RTE_LOC;

            if (verbose > 1)
                std::cout << "n " << n << " w " << w << " h " << h << " s " << stateSize << "\n---------------------------------" << std::endl;

            typename RationalOf<T>::type  e = 0;


            // b: do we terminate the last run?
            for (i64 b_ = 0; b_ < 3; ++b_)
            {
                auto B = setB(b_);

                for (u64 v = 0; v <= B.vMax; ++v)
                {

                    auto V = B.setV(v);

                    for (i64 r_ = 1; r_ <= V.rMax; ++r_)
                    {
                        auto R = V.setR(r_);

                        // the number of zeros in the runs.
                        for (i64 t0 = 0; t0 <= R.t0Max; ++t0)
                        {

                            auto eg = R.enumerate(t0);
                            auto g = R.getG(t0);

                            // e += eg / 2^g
                            e += divPow2(eg, g);
                        }
                    }
                }
            }

            return to<T>(e);
        }

    };



    template<typename T>
    void enumerate(u64 n, u64 stateSize, u64 v)
    {
        std::vector<T> in(n), out(n);
        T total = 0;
        for (u64 w = 1; w < n; ++w)
        {
            if (v == 1)
                std::cout << "w[" << w << "] ";

            for (u64 h = 1; h < n; ++h)
            {

                EnumOne<T> e;
                e.init(n, w, h, stateSize, v);
                auto Ewh = e.enumerate();
                //auto Ewh = enumerate<T>(n, w, h, stateSize, v);
                out[h] += Ewh;

                if (v == 1)
                {

                    if (Ewh >= 1)
                        std::cout << " " << log2(Ewh);
                    else
                        std::cout << " - ";
                }

            }
            if (v == 1)
                std::cout << " \t~~\t" << log2(out[w]) << std::endl;
        }
        for (u64 w = 1; w < n; ++w)
            total += out[w];
        std::cout << "total " << log2(total) << " " << total << std::endl;

        //for (u64 i = 1; i < n; ++i)
        //{
        //    in[i] = chooseF(n, i);
        //}

        //if (v)
        //{
        //    for (u64 w = 1; w < n; ++w)
        //    {
        //        std::cout << "w[" << w << "] "  << log2(out[w]) << std::endl;
        //    }
        //}
    }


    inline void enumMain(oc::CLP& cmd)
    {

        u64 n = cmd.getOr("n", 100);
        u64 stateSize = cmd.getOr("s", 4);
        u64 v = cmd.getOr("v", 1);
        //enumerate<Float>(n, stateSize, v);
        //std::cout << "\n\n\n" << std::endl;
        enumerate<Int>(n, stateSize, v);

#ifdef MPZ_ENABLE
        enumerate<MPZ>(n, stateSize, v);
#endif
    }

    template<typename T>
    T accumulate(u64 n, u64 w, u64 h)
    {
        return choose_<T>(n - h, w / 2) * choose_<T>(h - 1, divCeil(w, 2) - 1);
    }


    inline void accumulateTest(const oc::CLP cmd)
    {
        u64 n = cmd.getOr("n", 8);
        u64 w = cmd.getOr("w", 3);
        u64 h = cmd.getOr("h", 3);
        u64 s = 1;
        u64 verbose = cmd.getOr("verbose", 0);

        EnumOne<Int> e;
        e.init(n, w, h, s, verbose);

        u64 r = (w + 1) / 2;
        u64 b = 1 - (w % 2);
        u64 v = cmd.getOr("v", h-r);
        //u64 v = h - r;

        auto p = e.setB(b).setV(v).setR(r);
        //BParam B(e, b);
        //VParam V(B, v);

        //e.setB(b);
        //e.setR(r);


        auto exp = accumulate<Int>(n, w, h);

        u64 f0 = 0;
        //u64 g = h;
        auto act = p.enumerate(f0);


        if (exp != act)
        {
            std::cout << "n " << n << std::endl;
            std::cout << "w " << w << std::endl;
            std::cout << "h " << h << std::endl;
            std::cout << "a " << act << std::endl;
            std::cout << "e " << exp << std::endl;
            throw RTE_LOC;
        }

    }

    inline void convEnumMain(oc::CLP& cmd) {
        // if (cmd.isSet("enum")) {
            enumMain(cmd);
        // }
    }
}

#endif
