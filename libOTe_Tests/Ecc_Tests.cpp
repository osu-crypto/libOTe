//#include "stdafx.h"

#include <thread>
#include <vector>
#include <memory>

#include "Common.h"
#include "Common/Defines.h"
#include "Crypto/Curve.h" 
#include "Common/Log.h"
#include "Common/ByteStream.h"

using namespace osuCrypto;



void EccpNumber_Test()
{
    u64 mod = 24;

    EllipticCurve curve(p5_INSECURE, ZeroBlock);
    PRNG prng(ZeroBlock);

    EccNumber one(curve, 1);
    EccNumber zero(curve, 0);


    if (one + one != 2)
    {
        Log::out << one + one << Log::endl;
        throw UnitTestFail("1 + 1 != 2");
    }

    if (one != one * one)
    {
        Log::out << one << Log::endl;
        Log::out << one * one << Log::endl;
        throw UnitTestFail("1 != 1* 1");
    }


    u64 tryCount = 100;

    for (u64 i = 0; i < tryCount; ++i)
    {

        auto mult_var = one;
        auto mult_var2 = one;
        auto mult_expected = u64(1);

        auto div_var = one;


        auto add_var = zero;
        auto add_expected = u64(0);
        auto sub_var = zero;

        for (u64 j = 0; j < 20; ++j)
        {
            // sample Z*_p
            auto mult = (prng.get<u64>() % (mod - 1)) + 1;

            //Log::out << "mult in " << mult << Log::endl;

            // sample Z_p
            auto add = prng.get<u64>() % mod;

            mult_expected = mult_expected * mult % mod;
            mult_var = mult_var * mult;
            mult_var2 = mult_var2 * EccNumber(curve,mult);

            div_var = div_var / mult;

            add_expected = (add_expected + add) % mod;
            add_var = add_var + add;
            
            sub_var = sub_var - add;

            if (mult_var != mult_expected || mult_var2 != mult_expected)
            {
                Log::out << i << "  " << j << Log::endl;
                Log::out << "mult var  " << mult_var << Log::endl;
                Log::out << "mult var2 " << mult_var << Log::endl;
                Log::out << "mult exp  " << std::hex << mult_expected << std::dec << Log::endl;
                throw UnitTestFail("mod mult error");
            }
        }




        if (add_var != add_expected)
        {
            Log::out << i << "  " /*<< j*/ << Log::endl;
            Log::out << "add var  " << add_var << Log::endl;
            Log::out << "add var2 " << add_var << Log::endl;
            Log::out << "add exp  " << std::hex << add_expected << std::dec << Log::endl;
            throw UnitTestFail("mod add error");
        }

        if (div_var != one / mult_var)
        {
            Log::out << "div var  " << div_var << Log::endl;
            Log::out << "div exp  " << one / mult_var << Log::endl;
            throw UnitTestFail("mod div error");
        }

        if (sub_var != -add_var)
        {
            Log::out << "sub var  " << sub_var << Log::endl;
            Log::out << "sub exp  " << -add_var << Log::endl;
            throw UnitTestFail("mod div error");
        }


    }

    if (zero - 1 != mod - 1)
    {
        Log::out << "-1 = " << zero - 1 << " != " << mod - 1 << Log::endl;
        throw UnitTestFail("-1 mod p");
    }

    //bool ok = false;
    for (u64 i = 0; i < tryCount; ++i)
    {
        EccNumber var(curve, prng);
        //Log::out << var << Log::endl;

        //if (var == 22)
        //{
        //    ok = true;
        //}

        if (var > (mod-1))
        {
            Log::out << "bad rand'" << Log::endl;
            Log::out << "var " << var << Log::endl;
            Log::out << "mod " << std::hex<< mod << std::dec << Log::endl;
            Log::out << "odr " << curve.getOrder() << Log::endl;
            throw UnitTestFail("bad rand'");
        }
    }

    //if (ok == false)
    //{
    //    Log::out << "bad rand 22" << Log::endl;
    //    throw UnitTestFail("bad rand 22");
    //}


    EccNumber rand(curve, prng), r(curve);

    ByteStream buff(rand.sizeBytes());

    rand.toBytes(buff.data());

    r.fromBytes(buff.data());

    if (r != rand)
    {
        throw UnitTestFail("");
    }

}



void EccpPoint_Test()
{
    EllipticCurve curve(p224, ZeroBlock);
    //EllipticCurve curve(p5_INSECURE, ZeroBlock);
    curve.getMiracl().IOBASE = 10;

    PRNG prng(ZeroBlock);

    EccNumber one(curve, 1);
    EccNumber zero(curve, 0);

    const auto& g = curve.getGenerator();

    auto g2 = curve.getGenerators()[1] + curve.getGenerators()[2];
    EccBrick g2Brick(g2);
    //Log::out << "g            " << g << Log::endl;


    //for (u64 i = 0; i < 24 * 2; ++i)
    //{
    //    Log::out << "g^"<< i<<"         " << g  * (one * i)<< Log::endl;
    //}
    //Log::out << "order        " << order << Log::endl;
    //Log::out << "g^(order-1)  " << g*(order - 1) << Log::endl;
    //Log::out << "g^order      " << g*order << Log::endl;
    //Log::out << "g^(1)        " << g*(one) << Log::endl;
    //Log::out << "g^(order+1)  " << g*(order + 1) << Log::endl;
    //Log::out << "g^(2)        " << g*(one + one) << Log::endl;

    if (g * (curve.getOrder() +1)!= g)
    {
        Log::out << "g^(n+1) != g" << Log::endl;
        Log::out << g * (curve.getOrder() + 1) << Log::endl;
        Log::out << g << Log::endl;
        throw    UnitTestFail("g^(n+1) != g");
    }



    EccNumber a(curve);
    EccNumber b(curve);
    EccNumber r(curve);

    a.randomize(prng);
    b.randomize(prng);
    r.randomize(prng);



    auto a_br = a + b * r;



    auto ga = g* a;

    auto gbr = ((g * b) * r);
    auto gbr2 = g * (b * r);


    //Log::out << "mod  " << curve.getOrder() << Log::endl;
    //Log::out << "a    " << a << Log::endl;
    //Log::out << "b    " << b << Log::endl;
    //Log::out << "r    " << r << Log::endl;
    //Log::out << "abr   " << a_br << Log::endl;
    //Log::out << "ga  " << ga << Log::endl;
    //Log::out << "gbr  " << gbr << Log::endl;
    //Log::out << "gbr2 " << gbr2 << Log::endl;

    auto ga_br = ga + gbr;
    auto ga_br2 = ga + gbr2;
    auto ga_br3 = g * a_br;

    if (ga_br != ga_br2 || ga_br != ga_br3)
    {
        Log::out << "ga_br != ga_br2" << Log::endl;
        Log::out << ga_br << Log::endl;
        Log::out << ga_br2 << Log::endl;
        Log::out << ga_br3 << Log::endl;

        throw UnitTestFail("ga_br != ga_br2");
    }

    EccBrick gBrick(g);

    auto gBOne = gBrick * one;

    if (g != gBOne)
    {
        Log::out << "g     " << g << Log::endl;
        Log::out << "gBOne " << gBOne << Log::endl;

        throw UnitTestFail("ga != gBa");
    }

    auto gBa = gBrick * a;

    if (ga != gBa)
    {
        Log::out << "ga  " << ga << Log::endl;
        Log::out << "gBa " << gBa << Log::endl;

        throw UnitTestFail("ga != gBa");
    }
    auto gBbr = ((gBrick * b) * r);
    auto gBbr2 = (gBrick * (b * r));

    auto gBa_br = gBa + gBbr;
    auto gBa_br2 = gBa + gBbr2;


    if (gBa_br != gBa_br2 || gBa_br != ga_br2)
    {
        Log::out << "gBa_br  " << gBa_br << Log::endl;
        Log::out << "gBa_br2 " << gBa_br2 << Log::endl;
        Log::out << "ga_br2  " << ga_br2 << Log::endl;

        throw UnitTestFail("gBa_br != gBa_br2");
    }


    //auto g2a = g2 * a;
    //auto g2Ba = g2Brick * a;    
    //
    //if (g2Ba != g2a )
    //{
    //    Log::out << "g2Ba  " << g2Ba << Log::endl;
    //    Log::out << "g2a  " << g2a << Log::endl;

    //    throw UnitTestFail("g2a != g2Ba");
    //}
}




void Ecc2mNumber_Test()
{

    EllipticCurve curve(k283, ZeroBlock);

    PRNG prng(ZeroBlock);

    EccNumber one(curve, 1);
    EccNumber zero(curve, 0);


    if (one + one != 2)
    {
        Log::out << one + one << Log::endl;
        throw UnitTestFail("1 + 1 != 2");
    }

    if (one != one * one)
    {
        Log::out << one << Log::endl;
        Log::out << one * one << Log::endl;
        throw UnitTestFail("1 != 1* 1");
    }


    u64 tryCount = 100;

    for (u64 i = 0; i < tryCount; ++i)
    {

        auto mult_var = one;
        auto mult_var2 = one;

        auto div_var = one;


        auto add_var = zero;
        auto sub_var = zero;

        for (u64 j = 0; j < 20; ++j)
        {
            // sample Z*_p
            auto mult = prng.get<u32>() >> 1;
            //Log::out << mult_var << " * " << mult << Log::endl;

            //Log::out << "mult in " << mult << Log::endl;

            // sample Z_p
            auto add = prng.get<u32>() >> 1;

            mult_var = mult_var * mult;
            mult_var2 = mult_var2 * EccNumber(curve, mult);

            div_var = div_var / mult;

            add_var = add_var + add;

            sub_var = sub_var - add;


            if (mult_var != mult_var2)
            {
                Log::out << i << "  " << j << Log::endl;
                Log::out << "mult var  " << mult_var << Log::endl;
                Log::out << "mult var2 " << mult_var << Log::endl;
                throw UnitTestFail("mod mult error");
            }
        }


        if (div_var != one / mult_var)
        {
            Log::out << "div var  " << div_var << Log::endl;
            Log::out << "div exp  " << one / mult_var << Log::endl;
            throw UnitTestFail("mod div error");
        }

        if (sub_var != -add_var)
        {
            Log::out << "sub var  " << sub_var << Log::endl;
            Log::out << "sub exp  " << -add_var << Log::endl;
            throw UnitTestFail("mod div error");
        }


    }

    if (zero - 1 !=  - 1)
    {
        Log::out << "-1 = " << zero - 1 << Log::endl;
        throw UnitTestFail("-1 mod p");
    }

    //if (ok == false)
    //{
    //    Log::out << "bad rand 22" << Log::endl;
    //    throw UnitTestFail("bad rand 22");
    //}


    EccNumber rand(curve, prng), r(curve);

    ByteStream buff(rand.sizeBytes());

    rand.toBytes(buff.data());

    r.fromBytes(buff.data());

    if (r != rand)
    {
        throw UnitTestFail("");
    }

}



void Ecc2mPoint_Test()
{

    EllipticCurve curve(k283, ZeroBlock);
    //EllipticCurve curve(p5_INSECURE, ZeroBlock);
    //curve.getMiracl().IOBASE = 10;

    PRNG prng(ZeroBlock);

    EccNumber one(curve, 1);
    EccNumber zero(curve, 0);

    const auto& g = curve.getGenerator();


    auto g2 = curve.getGenerators()[1] + curve.getGenerators()[2];
    EccBrick g2Brick(g2);


    //Log::out << "g            " << g << Log::endl;


    //for (u64 i = 0; i < 24 * 2; ++i)
    //{
    //    Log::out << "g^"<< i<<"         " << g  * (one * i)<< Log::endl;
    //}
    //Log::out << "order        " << order << Log::endl;
    //Log::out << "g^(order-1)  " << g*(order - 1) << Log::endl;
    //Log::out << "g^order      " << g*order << Log::endl;
    //Log::out << "g^(1)        " << g*(one) << Log::endl;
    //Log::out << "g^(order+1)  " << g*(order + 1) << Log::endl;
    //Log::out << "g^(2)        " << g*(one + one) << Log::endl;

    if (g * (curve.getOrder() + 1) != g)
    {
        Log::out << "g^(n+1) != g" << Log::endl;
        Log::out << g * (curve.getOrder() + 1) << Log::endl;
        Log::out << g << Log::endl;
        throw    UnitTestFail("g^(n+1) != g");
    }



    EccNumber a(curve);
    EccNumber b(curve);
    EccNumber r(curve);

    a.randomize(prng);
    b.randomize(prng);
    r.randomize(prng);



    auto a_br = a + b * r;

    //Log::out << a_br << Log::endl;

    auto ga = g* a;
    //Log::out << "ga  " << ga << Log::endl;

    auto gbr = ((g * b) * r);
    auto gbr2 = g * (b * r);


    //Log::out << "mod  " << curve.getOrder() << Log::endl;
    //Log::out << "a    " << a << Log::endl;
    //Log::out << "b    " << b << Log::endl;
    //Log::out << "r    " << r << Log::endl;
    //Log::out << "abr   " << a_br << Log::endl;
    //Log::out << "ga  " << ga << Log::endl;
    //Log::out << "gbr  " << gbr << Log::endl;
    //Log::out << "gbr2 " << gbr2 << Log::endl;

    auto ga_br = ga + gbr;
    auto ga_br2 = ga + gbr2;
    auto ga_br3 = g * a_br;

    if (ga_br != ga_br2 || ga_br != ga_br3)
    {
        Log::out << "ga_br != ga_br2" << Log::endl;
        Log::out << ga_br << Log::endl;
        Log::out << ga_br2 << Log::endl;
        Log::out << ga_br3 << Log::endl;

        throw UnitTestFail("ga_br != ga_br2");
    }

    EccBrick gBrick(g);

    auto gBOne = gBrick * one;

    if (g != gBOne)
    {
        Log::out << "g     " << g << Log::endl;
        Log::out << "gBOne " << gBOne << Log::endl;

        throw UnitTestFail("ga != gBa");
    }

    auto gBa = gBrick * a;

    if (ga != gBa)
    {
        Log::out << "ga  " << ga << Log::endl;
        Log::out << "gBa " << gBa << Log::endl;

        throw UnitTestFail("ga != gBa");
    }
    auto gBbr = ((gBrick * b) * r);
    auto gBbr2 = (gBrick * (b * r));

    auto gBa_br = gBa + gBbr;
    auto gBa_br2 = gBa + gBbr2;


    if (gBa_br != gBa_br2 || gBa_br != ga_br2)
    {
        Log::out << "gBa_br  " << gBa_br << Log::endl;
        Log::out << "gBa_br2 " << gBa_br2 << Log::endl;
        Log::out << "ga_br2  " << ga_br2 << Log::endl;

        throw UnitTestFail("gBa_br != gBa_br2");
    }

    EccNumber Rc(curve);
    Rc.fromHex("769FC4F81A2622436EAACEB85830FB00EA2F2BE8235D30BC9AA06AA2F26092A81F4050F");
    EccPoint pch(curve);

    pch.fromHex("3A2E668B199FAD952CE14569D8BFC92259E3B04D7F44B4E7AD8C76FBCDCC916697ECF404", "4DB117E685E3139B176F6A96247FFE476115916F488DF399F3D7C458F849B7DC8174DE2");

    auto gRc = pch + g * Rc;
    auto gBRc = pch  + gBrick * Rc;


    //Log::out << "g     " << g << Log::endl;
    //Log::out << "Rc     " << Rc << Log::endl;
    //Log::out << "gBRc  " << gBRc << Log::endl;

    //auto g2a = g2 * a;
    //auto g2Ba = g2Brick * a;    
    
    if (gRc != gRc)
    {
        Log::out << "gBRc  " << gBRc << Log::endl;
        Log::out << "gRc  " << gRc << Log::endl;

        throw UnitTestFail("gBRc != gRc");
    }
}
