#pragma once
#include "cryptoTools/Common/Defines.h"
#include <vector>
#include <unordered_map>
#include "cryptoTools/Common/CLP.h"
#include <boost/multiprecision/cpp_bin_float.hpp> 

namespace osuCrypto
{
    using Float = boost::multiprecision::cpp_bin_float_quad;

    u64 factI(u64 n)
    {
        u64 v = 1;
        for (u64 i = 2; i <= n; ++i)
            v *= i;
        return v;
    }
    Float factF(u64 n)
    {
        Float v = 1;
        for (u64 i = 2; i <= n; ++i)
            v *= i;
        return v;
    }

    inline Float stirlingApprox(u64 n)
    {
        static Float pi = 3.141592653589793238462643383279502884197;
        auto v = sqrt(2 * pi * n) * pow(n / exp(Float(1)), n);
        //auto expansion_ =
        //    double(1) +
        //    double(1) / (12 * n) +
        //    double(1) / (228 * std::pow(n, 2)) +
        //    double(139) / (51840 * std::pow(n, 3)) +
        //    double(571) / (3488320 * std::pow(n, 4));

        std::array<Float, 16> dom{ {
            1, 1, -139, -571, 163879, 5246819,
            -534703531, -4483131259, 432261921612371, 6232523202521089, -25834629665134204969.0,
            -1579029138854919086429.0, 746590869962651602203151.0, 1511513601028097903631961.0, -8849272268392873147705987190261.0,  -142801712490607530608130701097701.0
        } };

        std::array<Float, 16> num{ {
                12, 288, 51840, 2488320, 209018880,
                75246796800, 902961561600, 86684309913600, 514904800886784000, 86504006548979712000.0,
                13494625021640835072000.0, 9716130015581401251840000.0, 116593560186976815022080000.0, 2798245444487443560529920000.0, 299692087104605205332754432000000.0,
                57540880724084199423888850944000000.0} };
        auto expansion = Float(1);
        for (u64 i = 0; i < 14; ++i)
            expansion += dom[i] / (num[i] * pow(Float(n), Float(i + 1)));
        return v * expansion;
    }

    inline Float chooseF(i64 n, i64 k)
    {
        if (n < 0 || k < 0)
            return 0;
        if (k > n)
            return 0;
        if (k == 0 || k == n)
            return 1;

        return stirlingApprox(n) / stirlingApprox(n - k) / stirlingApprox(k);
    }

    //inline Float ballsBins(u64 balls, u64 bins)
    //{
    //    return chooseF()
    //}
    inline void print(std::vector<u64>& stack)
    {
        //char d = '{';
        //for (auto v : stack)
        //{
        //    std::cout << std::exchange(d, ',') << v;
        //}
        //std::cout <<"}\n";
    }


    inline Float ballBinCapX(u64 balls, u64 bins, u64 cap, std::vector<u64>& stack)
    {
        if (balls > bins * cap)
        {
            return 0;

        }
        //if (balls == bins * cap)
        //{
        //    
        //    return 1;
        //}
        if (balls == 0)
        {
            print(stack);
            return 1;
        }
        if (bins == 1)
        {
            if (balls <= cap)
            {
                stack.push_back(balls);
                print(stack);
                stack.pop_back();
                return 1;
            }
            else
                return 0;
        }

        Float r = 0;

        for (u64 i = 0; i <= cap; ++i)
        {
            if (balls >= i)
            {
                stack.push_back(i);
                r += ballBinCapX(balls - i, bins - 1, cap, stack);
                stack.pop_back();
            }
        }
        return r;
    }

    inline Float ballBinCapX(u64 balls, u64 bins, u64 cap)
    {
        std::vector<u64> stack;
        return ballBinCapX(balls, bins, cap, stack);
    }

    inline Float ballBinCap(u64 balls, u64 bins, u64 cap)
    {
        if (balls * 2 > bins * cap)
            balls = bins * cap - balls;

        if (balls < bins * cap)
        {

            Float d = 0;
            for (u64 i = 0; i < bins; ++i)
            {
                Float v = (i & 1) ? -1 : 1;
                auto mt = chooseF(bins, i);

                i64 bb = bins + balls - i64(i) * (cap + 1) - 1;
                if (bb < bins - 1 || bb < 0)
                    break;

                auto r = chooseF(bb, bins - 1);

                if (mt != mt)
                    throw RTE_LOC;
                if (r != r)
                    throw RTE_LOC;
                d += v * mt * r;
            }
            return d;
        }
        else if (balls == bins * cap)
            return 1;
        else
            return 0;

    }
    inline Float ballBinCapA(u64 balls, u64 bins, u64 cap)
    {
        static Float pi = 3.141592653589793238462643383279502884197;
        auto A = std::pow(cap + 1, bins);
        auto c = cap * bins;

        //z 2^{-z^2 / 2} = ((c/2 + 1) sqrt(2 pi)) / A
        //               = v
        auto v = (c / 2.0 + 1) * sqrt(2 * pi) / A;

        std::cout << std::endl;
        std::cout << "A " << A << std::endl;
        std::cout << "c " << c << std::endl;
        std::cout << "v " << v << std::endl;
        double epsilon = 0.000001;

        auto f = [](double z)
        {
            return z * std::exp(-z * z / 2);
        };
        //for (double z = 0; z < 2; z += 0.1)
        //{
        //    std::cout << "f(" << z << ") = " << f(z) << std::endl;;
        //}
        //return 0;
        double z = 1;
        while (f(z) > v)
        {
            z *= 2;
            //std::cout << "f(" << z << ")=" << f(z) << " vs " <<v<< std::endl;
        }

        auto x = z / 2;
        //std::cout << "---------"<< std::endl;

        auto diff = z - x;
        while (std::abs(diff) > epsilon)
        {
            diff = z - x;

            auto half = diff / 2;
            auto y = z - half;

            //std::cout << "f(" << y << ")=" << f(y) <<" vs "<<v << std::endl;


            if (f(y) < v)
                z = y;
            else
                x = y;
        }

        //std::cout << "f(z) = " << f(z) << " vs " << v << std::endl;
        //std::cout << "==================== = " << std::endl;

        auto s = (c / 2 + 1) / z;
        auto coeff = (A / s) / sqrt(2 * pi);
        auto t = ((balls - c / 2) / s);
        auto e = -t * t / 2;
        auto r = coeff * exp(e);
        //auto lc = log(coeff);
        //auto r = exp(lc + e);
        std::cout << z << "  " << coeff << "  " << e << "  " << r << std::endl;
        return r;
    }

    //
    inline Float enumerate(u64 w, u64 h)
    {

    }

    inline void stirlingMain(CLP& cmd)
    {
        u64 n = cmd.getOr("n", 10);
        for (u64 i = 0; i < n; ++i)
        {
            std::cout << "n " << i << ": "
                << factI(i) << " "
                << factF(i) << " "
                << stirlingApprox(i) << std::endl;
        }
    }

    inline void ballBinCapMain(oc::CLP cmd)
    {
        auto balls = cmd.getManyOr<u64>("balls", { 10 });
        auto bins = cmd.getManyOr<u64>("bins", { 10 });
        u64 cap = cmd.getOr("cap", 12);

        std::cout << "bins _:";
        for (auto bin : bins)
            std::cout << bin << " ";
        std::cout << std::endl;
        for (auto ball : balls)
        {
            std::cout << "ball " << ball << ": ";
            for (auto bin : bins)
            {
                auto v = ballBinCap(ball, bin, cap);
                auto vl = log2(v);
                std::cout << vl << " ";
            }
            std::cout << std::endl;
        }


        if (cmd.isSet("x"))
        {

            std::cout << "bins ";
            for (auto bin : bins)
                std::cout << bin << " ";
            std::cout << std::endl;
            for (auto ball : balls)
            {
                std::cout << "ball :" << ball << ": ";
                for (auto bin : bins)
                {
                    //auto v = ballBinCap(ball, bin, cap);
                    //auto vl = std::log2(v);
                    auto v = ballBinCapA(ball, bin, cap);
                    auto vl = log2(v);
                    std::cout << vl << " ";
                }
                std::cout << std::endl;
            }
        }


        //auto f = chooseF(balls + bins - 1, bins - 1);
        //auto f2 = choose(balls + bins - 1, bins - 1);
        //auto fl = std::log2(f);
        //auto fl2 = std::log2(f2);


        //std::cout
        //    << "balls " << balls << " bins " << bins
        //    << ": " << fl << " ~ " << f << std::endl;

        //std::cout
        //    << "balls " << balls << " bins " << bins
        //    << ": " << fl2 << " ~ " << f2 << std::endl;

        //std::cout
        //    << "balls " << balls << " bins " << bins << " cap " << cap
        //    << ": " << vl << " ~ " << v << std::endl;
        //std::cout
        //    << "balls " << balls << " bins " << bins << " cap " << cap
        //    << ": " << vl2 << " ~ " << v2 << std::endl;
    }

    inline Float ballsBins(i64 n, i64 k)
    {
        auto r = chooseF(n + k - 1, k - 1);
        //if (r < 1000)
        //    return choose(n + k - 1, k - 1);
        return r;

    }

    inline Float enumerate(i64 n, i64 w, i64 h, i64 stateSize, bool v)
    {
        if (v > 1)
            std::cout << "n " << n << " w " << w << " h " << h << " s " << stateSize << "\n---------------------------------" << std::endl;

        Float e = 0;
        // b: do we terminate the last run?
        for (i64 b = 0; b < 2; ++b)
        {
            // rMax: the maximum number of runs we need to consider.
            // if the output looks like 10000 10000 10000 ...
            i64 rMax = divCeil(n, stateSize + 1);

            // we require at least w >= 2 r - 1 + b input ones.
            // (w +1-b)/2 >= r
            rMax = std::min<i64>(rMax, (w + 1 - b) / 2);

            // we require at least r ones in the output.
            rMax = std::min<i64>(rMax, h);

            // we require at least n-h>=(r-1+b)*stateSize output zeros
            // (n-h)/stateSize -b + 1 >= r
            rMax = std::min<i64>(rMax, (n - h) / stateSize - b + 1);

            for (i64 r = 1; r <= rMax; ++r)
            {
                // the number of runs that terminate.
                i64 terminatingRuns = (r - 1 + b);


                // the number of output bins where zeros can be place 
                // that have a cap of stateSize - 1. For each run,
                // all but the last 1 can have stateSize-1 zeros to its 
                // right. There are h - r such ones. If the last run 
                // doesn't terminate, then the last one can also have 
                // stateSize - 1 zeros to its right.
                u64 numOutputZeroBinsWthCap = h - r + 1 - b;

                // the maximum number of zeros within a run that we need to consider.
                // we have n-h zeros. of these, stateSize * (r - 1 + b) of them go
                //are used to terminate a run.
                i64 g0Max = n - h - stateSize * terminatingRuns;

                g0Max = std::min<i64>(g0Max, numOutputZeroBinsWthCap * (stateSize - 1));




                // the number of zeros in the runs.
                for (i64 g0 = 0; g0 <= g0Max; ++g0)
                {
                    // total number of items in runs.
                    // we have g0 random zeros, then there are (h-r) ones.
                    // then there are (r-1+b) runs that terminate, each
                    // with stateSize zeros at the end.
                    auto g = g0 + h - r + terminatingRuns * stateSize;

                    if (g >= n)
                        throw RTE_LOC;

                    // w', the number of input ones that aren't allocated
                    // to the start or end of a run.
                    i64 remainingInputOnes = w - 2 * r + 1 - b;

                    // the number of input zeros
                    i64 inputZeros = n - w;

                    // the number of input zeros while the convolution is on.
                    i64 inputZerosOn = g - remainingInputOnes;

                    // the number of input zeros while the convolution is off.
                    i64 inputZerosOff = inputZeros - inputZerosOn;

                    // output ones that are not used to start a run.
                    i64 remainingOutputOnes = h - r;

                    // the output zeros that are not used within a run.
                    i64 remainingOutputZeros = (n - h) - terminatingRuns * stateSize - g0;

                    // input ones are assigned to an run.
                    Float enumInputOnes = ballsBins(remainingInputOnes, r);

                    // input zeros that are On can be assigned to come
                    // after any one.
                    Float enumInputZerosOn = ballsBins(inputZerosOn, w);

                    // input zeros that are off can be assigned to come before
                    // any run or after the last run if it terminates.
                    Float enumInputZerosOff = ballsBins(inputZerosOff, r + b);

                    // output ones can be assigned to any run.
                    Float enumOutputOnes = ballsBins(remainingOutputOnes, r);

                    // output zeros that are one can be assigned anywhere so long
                    // as we dont have stateSize zeros in a row. Balls in bins with capacity.
                    auto enumOuptutZerosOn = ballBinCap(g0, numOutputZeroBinsWthCap, stateSize - 1);

                    // the remaining output zeros are assigned to follow any terminating 
                    // run and before the first run.
                    auto enumOutputZerosOff = ballsBins(remainingOutputZeros, terminatingRuns + 1);

                    auto enumOutputZeros = enumOuptutZerosOn * enumOutputZerosOff;

                    auto enumInputZeros = enumInputZerosOn * enumInputZerosOff;

                    auto eg =
                        enumInputOnes * enumInputZeros *
                        enumOutputOnes * enumOutputZeros;

                    if (v > 1)
                        std::cout
                        << " r " << r << "." << b << " g0 " << g0
                        << "    in (" << enumInputZerosOn << " " << enumInputZerosOff << ", " << enumInputOnes
                        << ") out (" << enumOutputZerosOff << " " << enumOuptutZerosOn << ", " << enumOutputOnes
                        << ")      =      " << eg << " * 2^-" << g << std::endl;


                    e += eg *
                        pow(Float(2), -g);
                }
            }
        }

        return e;
    }

    inline void enumMain(oc::CLP& cmd)
    {

        u64 n = cmd.getOr("n", 100);
        u64 stateSize = cmd.getOr("s", 4);
        u64 v = cmd.getOr("v", 1);
        std::vector<Float> in(n), out(n);

        //for (u64 i = 1; i < n; ++i)
        //{
        //    in[i] = chooseF(n, i);
        //}

        for (u64 w = 1; w < n; ++w)
        {
            std::cout << "w[" << w << "] ";
            for (u64 h = 1; h < n; ++h)
            {
                auto Ewh = enumerate(n, w, h, stateSize, v);
                out[h] += Ewh;

                if(Ewh>=1)
                    std::cout << " " << log2(Ewh);
                else
                    std::cout << " - ";

            }
            std::cout << " \t~~\t" << log2(out[w]) << std::endl;
        }

        //if (v)
        //{

        //    for (u64 w = 1; w < n; ++w)
        //    {
        //        std::cout << "w[" << w << "] "  << log2(out[w]) << std::endl;
        //    }
        //}
    }

    inline void convEnumMain(oc::CLP& cmd)
    {
        //stirlingMain(cmd);
        //ballBinCapMain(cmd);
        enumMain(cmd);

    }
    //struct FactorSet
    //{
    //    std::unordered_map<u64, u64> mVals;

    //    FactorSet& operator*=(const FactorSet& o)
    //    {
    //        for (auto& oo : o.mVals)
    //        {
    //            mVals[oo.first] += oo.second;
    //        }
    //        return *this;
    //    }

    //};

    //// represents n! / k! for k<n.
    //struct FactorialRange
    //{
    //    u64 mN = 0;
    //    u64 mK = 0;


    //    //FactorialRange operator
    //};

    //// represents the fraction (\Pi_i mNum[i]) / (\Pi_i mDom[i])
    //struct FactorialFraction
    //{
    //    std::vector<FactorialRange> mNum, mDom;
    //};

    //// represents n choose k
    //struct NcK
    //{
    //    u64 mN = 0;
    //    u64 mK = 0;
    //};


    //struct BallsInBins
    //{
    //    u64 mBalls = 0;
    //    u64 mBins = 0;
    //    u64 mCap = 0;



    //};
}