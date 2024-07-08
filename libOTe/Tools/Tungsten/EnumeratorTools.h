// balls into bins, balls into bins with capacity, etc.

#pragma once
#include "cryptoTools/Common/TestCollection.h"
#include "cryptoTools/Common/Defines.h"
#include <vector>
#include <unordered_map>
#include "cryptoTools/Common/CLP.h"

#ifdef ENABLE_BOOST
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#ifdef ENABLE_GMP
#include <boost/multiprecision/gmp.hpp>
#include "gmp.h"
#include "gmpxx.h"
#endif

namespace osuCrypto {
    template<typename T, typename R>
    T to(const R&);

    template<typename T>
    T pow2(u64 pow);

    template<typename T>
    struct RationalOf;

    template<typename T>
    T fact(u64 n);


    template <typename T>
    inline T choose(i64 n, i64 k);

    //using MPZ = mpz_class;
//#define MPZ_ENABLE
#ifdef MPZ_ENABLE
    struct MPZ
    {
        mpz_class mVal;

        MPZ() = default;
        MPZ(const MPZ&) = default;
        MPZ(MPZ&&) = default;
        MPZ& operator=(const MPZ&) = default;
        MPZ& operator=(MPZ&&) = default;

        MPZ(i64 u)
        {

#ifdef _MSC_VER
            u64 v = u < 0 ? -u : u;
            if (v >> 32)
            {
                mVal = ((u32*)&v)[1];
                mVal <<= 32;
            }
            mVal += ((u32*)&v)[0];
            if (u < 0)
                mVal = -mVal;
#else
            mVal = u;
#endif
        }


        bool operator>=(i32 v) const
        {
            return mVal >= v;
        }



        MPZ& operator*=(const MPZ& v)
        {
            mVal *= v.mVal;
            return *this;
        }

        MPZ& operator*=(i64 v)
        {
            if (u64(v) >> 32)
            {
                *this *= MPZ(v);
            }
            else
            {
                mVal *= (i32)v;
            }
            return *this;
        }

        MPZ operator*(const MPZ& v)
        {
            auto r = *this;
            r *= v;
            return r;
        }

        bool operator==(const MPZ& v) const
        {
            return mVal == v.mVal;
        }


        MPZ& operator+=(const MPZ& v)
        {
            mVal += v.mVal;
            return *this;
        }

        MPZ exactDiv(const i64& v) const
        {
            if (v < 0)
                throw RTE_LOC;

            MPZ r;
            if (u64(v) >> 32 && sizeof(unsigned long) < 8)
            {
                MPZ zz(v);
                mpz_divexact(r.mVal.get_mpz_t(), mVal.get_mpz_t(), zz.mVal.get_mpz_t());
            }
            else
            {
                mpz_divexact_ui(r.mVal.get_mpz_t(), mVal.get_mpz_t(), (unsigned long)v);
            }

            assert(r * v == *this);

            return r;
        }


        MPZ& operator/=(const MPZ& v)
        {
            mVal /= v.mVal;
            return *this;
        }

        operator mpz_ptr()
        {
            return mVal.get_mpz_t();
        }

    };

    struct MPQ
    {
        mpq_class mVal;


        MPQ() = default;
        MPQ(const MPQ&) = default;
        MPQ(MPQ&&) = default;
        MPQ& operator=(const MPQ&) = default;
        MPQ& operator=(MPQ&&) = default;

        MPQ(u32 n, u32 d = 1)
        {
            mpq_set_ui(mVal.get_mpq_t(), n, d);
        }


        MPQ& operator+=(const MPQ& q)
        {
            mVal += q.mVal;
            return *this;
        }

        operator mpq_ptr()
        {
            return mVal.get_mpq_t();
        }
    };


    template<>
    MPZ to<MPZ, MPQ>(const MPQ& v)
    {
        MPZ r; r.mVal = v.mVal.get_num();
        MPZ d; d.mVal = v.mVal.get_den();
        r /= d;
        return r;
    }
    double log2(MPZ x) {
        signed long int ex;
        const double di = mpz_get_d_2exp(&ex, x.mVal.get_mpz_t());
        return log(di) + log(2) * (double)ex;
    }

    inline std::ostream& operator<<(std::ostream& o, const MPZ& v)
    {
        o << v.mVal;
        return o;
    }

    template<>
    inline MPZ pow2<MPZ>(u64 pow)
    {
        MPZ r;
        r = 1;
        if (pow >> 32)
            throw RTE_LOC;
        mpz_ui_pow_ui(r.mVal.get_mpz_t(), 2, pow);
        //r.mVal =<< (u32)pow;
        return r;
    }

    // returns z/2^power.
    MPQ divPow2(const MPZ& v, u64 power)
    {
        MPQ vv;
        mpq_set_num(vv, v.mVal.get_mpz_t());
        mpq_set_den(vv, pow2<MPZ>(power).mVal.get_mpz_t());
        mpq_canonicalize(vv);
        return vv;
    }

    template<>
    struct RationalOf<MPZ>
    {
        using type = MPQ;
    };


    template<>
    MPZ fact<MPZ>(u64 n)
    {
        MPZ v = 1;
        for (u64 i = 2; i <= n; ++i)
            v *= i;
        return v;
    }



    template <>
    inline MPZ choose_<MPZ>(i64 n, i64 k)
    {
        //mpz_fac_ui
        //choozeZ()
        if (n < 0 || k < 0)
            return 0;
        if (k > n)
            return 0;
        if (k == 0 || k == n)
            return 1;

        if (n - k < k)
            return choose(n, n - k);

        MPZ r = (n - k + 1);
        for (u64 i = 2; i <= k; ++i)
        {
            r *= (n - k + i);
            r = r.exactDiv(i);
        }
        return r;
    }

#endif

    using Float = boost::multiprecision::cpp_bin_float_oct;
#ifdef ENABLE_GMP
    using Int = boost::multiprecision::mpz_int;
    using Rat = boost::multiprecision::mpq_rational;
#else

    using Int = boost::multiprecision::cpp_int;
    using Rat = boost::multiprecision::cpp_rational;

#endif
    template<>
    Float to<Float, Float>(const Float& v)
    {
        return v;
    }

    template<>
    Int to<Int, Rat>(const Rat& v)
    {
        return v.convert_to<Int>();
    }

    // returns z/2^power.
    Float divPow2(const Float& v, u64 power)
    {
        return v / pow(Float(v), power);
    }

    Rat divPow2(const Int& v, u64 power)
    {
        Rat vv(v, Int(1) << power);
        //mpq_set_num(vv, v.mVal.get_mpz_t());
        //mpq_set_den(vv, pow2<MPZ>(power).mVal.get_mpz_t());
        //mpq_canonicalize(vv);
        vv = vv.canonical_value(vv);
        return vv;
    }


    //using Number = MPZ;

    template<>
    struct RationalOf<Float>
    {
        using type = Float;
    };

    template<>
    struct RationalOf<Int>
    {
        using type = Rat;
    };


    template<>
    Float fact<Float>(u64 n)
    {
        Float v = 1;
        for (u64 i = 2; i <= n; ++i)
            v *= i;
        return v;
    }

    template<>
    Int fact<Int>(u64 n)
    {
        Int v = 1;
        for (u64 i = 2; i <= n; ++i)
            v *= i;
        return v;
    }

    u64 log2floor(Int x)
    {
        u64 r = 0;
        while (x >= 2)
        {
            ++r;
            x /= 2;
        }
        return r;
    }

    u64 log2ceil(Int x)
    {
        auto r = log2floor(x);
        if ((Int(1) << r) != x)
            ++r;
        return r;
    }

    double log2(Int x) {

        if (x == 0)
        {
            return log(0);
        }
#ifdef ENABLE_GMP
        signed long int ex;
        const double di = mpz_get_d_2exp(&ex, x.backend().data());
        auto ret = log(di) / log(2) + (double)ex;
        if (log2ceil(x) < ret || log2floor(x) > ret)
        {
            std::cout << "bad log   " << x << std::endl;
            std::cout << "log floor " << log2floor(x) << std::endl;
            std::cout << "log ceil  " << log2ceil(x) << std::endl;
            throw RTE_LOC;
        }
        return ret;
#else
        double v;
        while (x >= 2)
        {
            x /= 2;
            v += 1;
        }
        //std::cout << "rem " << x << std::endl;
        if (x > 0)
        {
            i64 r = x.convert_to<i64>();
            //std::cout << r << std::endl;
            v += ::log2(double(r));
        }
        return v;
#endif

    }


    inline Float stirlingApprox(u64 n)
    {
        if (n == 0)
            return 1;

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
                                           Float("-534703531"), Float("-4483131259"), Float("432261921612371"), Float("6232523202521089"), Float("-25834629665134204969.0"),
                                           Float("-1579029138854919086429.0"), Float("746590869962651602203151.0"),Float("1511513601028097903631961.0"), Float("-8849272268392873147705987190261.0"),  Float("-142801712490607530608130701097701.0")
                                   } };

        std::array<Float, 16> num{ {
                                           12, 288, 51840, 2488320, 209018880,
                                           Float("75246796800"), Float("902961561600"), Float("86684309913600"), Float("514904800886784000"), Float("86504006548979712000.0"),
                                           Float("13494625021640835072000"), Float("9716130015581401251840000"), Float("116593560186976815022080000"), Float("2798245444487443560529920000"), Float("299692087104605205332754432000000"),
                                           Float("57540880724084199423888850944000000") } };
        auto expansion = Float(1);
        for (u64 i = 0; i < 14; ++i)
            expansion += dom[i] / (num[i] * pow(Float(n), Float(i + 1)));
        return v * expansion;
    }


    Float chooseApx(i64 n, i64 k)
    {
        if (k < 0 || k > n)
            return 0;
        if (k == 0 || k == n)
            return 1;
        auto b = (n - k) * log(Float(n) / (n - k)) + k * log(Float(n) / k);
        return exp(b);
    }

    template <typename T>
    inline T choose_(i64 n, i64 k)
    {
        if (k < 0 || k > n)
            return 0;
        if (k == 0 || k == n)
            return 1;

        k = std::min<i64>(k, n - k);
        T c = 1;
        for (u64 i = 0; i < k; ++i)
            c = c * (n - i) / (i + 1);
        return c;
    }


    inline Int ballBinCapX(u64 balls, u64 bins, u64 cap, std::vector<u64>& stack)
    {
        if (balls > bins * cap)
        {
            return 0;

        }
        //if (n == k * cap)
        //{
        //
        //    return 1;
        //}
        if (balls == 0)
        {
            //print(stack);
            return 1;
        }
        if (bins == 1)
        {
            if (balls <= cap)
            {
                stack.push_back(balls);
                //print(stack);
                stack.pop_back();
                return 1;
            }
            else
                return 0;
        }

        Int r = 0;

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

    inline Int ballBinCapX(u64 balls, u64 bins, u64 cap)
    {
        std::vector<u64> stack;
        return ballBinCapX(balls, bins, cap, stack);
    }

    template<typename T>
    inline T labeledBallBinCap(u64 balls, u64 bins, u64 cap) {
        if (balls == 0)
            return 1;

        //if (balls * 2 > bins * cap)
        //    balls = bins * cap - balls;

        if (balls < bins * cap)
        {

            T d = 0;
            for (u64 i = 0; i < bins; ++i)
            {
                T v = (i & 1) ? -1 : 1;
                auto mt = choose_<T>(bins, i);

                //std::cout << i << " mt " << mt << " = C("<< bins<<", " << i << ")" << std::endl;

                i64 bb = cap * (bins - i64(i));
                if (bb < balls || bb < 0)
                    break;

                auto r = choose_<T>(bb, balls);
                //std::cout << i << " r " << r << " = C(" << bb << ", " << bins-1 << ")" << std::endl;

                //if (mt != mt)
                //    throw RTE_LOC;
                //if (r != r)
                //    throw RTE_LOC;
                d += v * mt * r;
                //std::cout << i << " d " << d << std::endl;
            }
            return d;
        }
        else if (balls == bins * cap)
            return 1;
        else
            return 0;
    }

    template<typename T>
    inline T ballBinCap(u64 balls, u64 bins, u64 cap)
    {
        if (balls == 0)
            return 1;

        if (balls * 2 > bins * cap)
            balls = bins * cap - balls;

        if (balls < bins * cap)
        {

            T d = 0;
            for (u64 i = 0; i < bins; ++i)
            {
                T v = (i & 1) ? -1 : 1;
                auto mt = choose_<T>(bins, i);

                //std::cout << i << " mt " << mt << " = C("<< bins<<", " << i << ")" << std::endl;

                i64 bb = bins + balls - i64(i) * (cap + 1) - 1;
                if (bb < bins - 1 || bb < 0)
                    break;

                auto r = choose_<T>(bb, bins - 1);
                //std::cout << i << " r " << r << " = C(" << bb << ", " << bins-1 << ")" << std::endl;

                if (mt != mt)
                    throw RTE_LOC;
                if (r != r)
                    throw RTE_LOC;
                d += v * mt * r;
                //std::cout << i << " d " << d << std::endl;
            }
            return d;
        }
        else if (balls == bins * cap)
            return 1;
        else
            return 0;
    }

    inline void stirlingMain(CLP& cmd)
    {
        u64 n = cmd.getOr("n", 10);
        for (u64 i = 0; i < n; ++i)
        {
            auto I = fact<Int>(i);
            auto F = fact<Float>(i);
            auto S = stirlingApprox(i);

            std::cout << "n " << i << ": "
                      #ifdef MPZ_ENABLE
                      << fact<MPZ>(i) << " "
                      #endif
                      << I << " "
                      //<< F << " "
                      //<< S << " "
                      << (I - F.convert_to<Int>()).convert_to<Float>() / I.convert_to<Float>() << " "
                      << (I - S.convert_to<Int>()).convert_to<Float>() / I.convert_to<Float>()
                      << std::endl;
        }
    }


    inline void chooseMain(oc::CLP cmd)
    {
        auto n = cmd.getManyOr<u64>("n", { 10 });
        auto k = cmd.getManyOr<u64>("k", { 10 });


        for (auto nn : n)
        {
            for (auto kk : k)
            {
                std::cout << "n " << nn << " k " << kk << " : f ";
                auto f = choose_<Float>(nn, kk);
                auto fl = log2(f);
                std::cout << fl << " ~ i ";

                auto z = choose_<Int>(nn, kk);
                auto zl = log2(z);
                std::cout << zl << " @ ";
#ifdef MPZ_ENABLE
#endif
            }
            std::cout << std::endl;
        }
    }

    inline void ballBinCapMain(oc::CLP cmd)
    {
        auto balls = cmd.getManyOr<u64>("n", { 10 });
        auto bins = cmd.getManyOr<u64>("m", { 10 });
        u64 cap = cmd.getOr("c", 12);

        std::cout << "k _:";
        for (auto bin : bins)
            std::cout << bin << " ";
        std::cout << std::endl;
        for (auto ball : balls)
        {
            std::cout << "nn " << ball << ": f ";
            for (auto bin : bins)
            {
                auto f = ballBinCap<Float>(ball, bin, cap);
                auto fl = log2(f);
                std::cout << fl << " i ";
                auto z = ballBinCap<Int>(ball, bin, cap);
                auto zl = log2(z);
                std::cout << zl << ",  ";
#ifdef MPZ_ENABLE
#endif
            }
            std::cout << std::endl;
        }

    }

    template<typename T>
    inline T ballsBins(i64 n, i64 k)
    {
        return choose_<T>(n + k - 1, k - 1);
    }


    inline void stirlingTest(const oc::CLP& cmd)
    {
        u64 n = cmd.getOr("n", 44);
        for (u64 i = 0; i < n; ++i)
        {
            auto I = fact<Int>(i);
            auto F = fact<Float>(i);
            auto S = stirlingApprox(i);

            auto d0 = abs((I - F.convert_to<Int>()).convert_to<Float>() / I.convert_to<Float>());
            auto d1 = abs((I - S.convert_to<Int>()).convert_to<Float>() / I.convert_to<Float>());

            if (d0 > 0.000001)
                throw RTE_LOC;
            if (d1 > 0.000001)
                throw RTE_LOC;
        }
    }

    inline void chooseTest(const oc::CLP& cmd)
    {
        u64 n = cmd.getOr("n", 44);
        u64 m = cmd.getOr("m", 44);
        for (u64 i = 0; i < n; ++i)
        {
            for (u64 j = 0; j < m; ++j)
            {
                auto I = choose_<Int>(i, j);
                //std::cout << I << " ";

                auto F = choose_<Float>(i, j);
                //auto S = chooseApx(i, j);
                auto div = (I ? I.convert_to<Float>() : 1);
                auto d0 = abs((I - F.convert_to<Int>()).convert_to<Float>() / div);
                //auto d1 = (I - S.convert_to<Int>()).convert_to<Float>() / div;

                //std::cout << i << " " << j << ": " << d0 << " " << d1 << std::endl;
                if (d0 > 0.000001)
                    throw RTE_LOC;
                //if (d1 > 0.000001)
                //    throw RTE_LOC;
            }
            //std::cout << "\n";
        }
        //std::cout << "\n";
        //std::cout << "\n";
        //for (u64 i = 0; i < n; ++i)
        //{
        //    for (u64 j = 0; j < m; ++j)
        //    {
        //        auto S = chooseApx(i, j);
        //        std::cout << S << " ";
        //    }
        //    std::cout << "\n";
        //}
    }

    inline void ballbincapTest(const oc::CLP& cmd)
    {
        auto balls = cmd.getManyOr<u64>("n", { 4, 10, 100 });
        auto bins = cmd.getManyOr<u64>("m", { 4, 10, 100 });
        auto caps = cmd.getManyOr<u64>("c", { 2,4, 12 });

        for (auto ball : balls)
        {
            for (auto bin : bins)
            {
                for (auto cap : caps)
                {
                    auto f = ballBinCap<Float>(ball, bin, cap);
                    auto fl = log2(f);
                    //std::cout << fl << " i ";
                    auto z = ballBinCap<Int>(ball, bin, cap);
                    auto zl = log2(z);
                    //std::cout << zl << ",  ";


                    auto div = (z ? z.convert_to<Float>() : 1);
                    auto d0 = abs((z - f.convert_to<Int>()).convert_to<Float>() / div);
                    if (d0 > 0.000001)
                        throw RTE_LOC;

                    if (zl < 16)
                    {
                        auto X = ballBinCapX(ball, bin, cap);
                        //auto d1 = abs((z - X.convert_to<Int>()).convert_to<Float>() / div);
                        if (X != z)
                            throw RTE_LOC;
                    }
                }
            }
        }

    }

    inline void test(oc::CLP& cmd)
    {
        TestCollection tests;
        tests.add("stirlingTest      ", stirlingTest);
        tests.add("chooseTest        ", chooseTest);
        tests.add("ballbincapTest    ", ballbincapTest);

        tests.runIf(cmd);
    }


    inline void EnumToolsMain(oc::CLP& cmd)
    {
        if (cmd.isSet("u")) {
            std::cout << "testing all..." << std::endl;
            test(cmd);
        }

        if (cmd.isSet("stirling")) {
            std::cout << "testing stirling..." << std::endl;
            stirlingMain(cmd);
        }


        if (cmd.isSet("choose")) {
            std::cout << "testing choose..." << std::endl;
            chooseMain(cmd);
        }

        if (cmd.isSet("bbc")) {
            std::cout << "testing balls bins cap..." << std::endl;
            ballBinCapMain(cmd);
        }
    }
}

#endif
