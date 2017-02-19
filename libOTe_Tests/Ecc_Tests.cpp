//#include "stdafx.h"

#include <thread>
#include <vector>
#include <memory>

#include "Common.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/Curve.h> 
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/ByteStream.h>

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
        std::cout << one + one << std::endl;
        throw UnitTestFail("1 + 1 != 2");
    }

    if (one != one * one)
    {
        std::cout << one << std::endl;
        std::cout << one * one << std::endl;
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

            //std::cout << "mult in " << mult << std::endl;

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
                std::cout << i << "  " << j << std::endl;
                std::cout << "mult var  " << mult_var << std::endl;
                std::cout << "mult var2 " << mult_var << std::endl;
                std::cout << "mult exp  " << std::hex << mult_expected << std::dec << std::endl;
                throw UnitTestFail("mod mult error");
            }
        }




        if (add_var != add_expected)
        {
            std::cout << i << "  " /*<< j*/ << std::endl;
            std::cout << "add var  " << add_var << std::endl;
            std::cout << "add var2 " << add_var << std::endl;
            std::cout << "add exp  " << std::hex << add_expected << std::dec << std::endl;
            throw UnitTestFail("mod add error");
        }

        if (div_var != one / mult_var)
        {
            std::cout << "div var  " << div_var << std::endl;
            std::cout << "div exp  " << one / mult_var << std::endl;
            throw UnitTestFail("mod div error");
        }

        if (sub_var != -add_var)
        {
            std::cout << "sub var  " << sub_var << std::endl;
            std::cout << "sub exp  " << -add_var << std::endl;
            throw UnitTestFail("mod div error");
        }


    }

    if (zero - 1 != mod - 1)
    {
        std::cout << "-1 = " << zero - 1 << " != " << mod - 1 << std::endl;
        throw UnitTestFail("-1 mod p");
    }

    //bool ok = false;
    for (u64 i = 0; i < tryCount; ++i)
    {
        EccNumber var(curve, prng);
        //std::cout << var << std::endl;

        //if (var == 22)
        //{
        //    ok = true;
        //}

        if (var > (mod-1))
        {
            std::cout << "bad rand'" << std::endl;
            std::cout << "var " << var << std::endl;
            std::cout << "mod " << std::hex<< mod << std::dec << std::endl;
            std::cout << "odr " << curve.getOrder() << std::endl;
            throw UnitTestFail("bad rand'");
        }
    }

    //if (ok == false)
    //{
    //    std::cout << "bad rand 22" << std::endl;
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
    //std::cout << "g            " << g << std::endl;


    //for (u64 i = 0; i < 24 * 2; ++i)
    //{
    //    std::cout << "g^"<< i<<"         " << g  * (one * i)<< std::endl;
    //}
    //std::cout << "order        " << order << std::endl;
    //std::cout << "g^(order-1)  " << g*(order - 1) << std::endl;
    //std::cout << "g^order      " << g*order << std::endl;
    //std::cout << "g^(1)        " << g*(one) << std::endl;
    //std::cout << "g^(order+1)  " << g*(order + 1) << std::endl;
    //std::cout << "g^(2)        " << g*(one + one) << std::endl;

    if (g * (curve.getOrder() +1)!= g)
    {
        std::cout << "g^(n+1) != g" << std::endl;
        std::cout << g * (curve.getOrder() + 1) << std::endl;
        std::cout << g << std::endl;
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


    //std::cout << "mod  " << curve.getOrder() << std::endl;
    //std::cout << "a    " << a << std::endl;
    //std::cout << "b    " << b << std::endl;
    //std::cout << "r    " << r << std::endl;
    //std::cout << "abr   " << a_br << std::endl;
    //std::cout << "ga  " << ga << std::endl;
    //std::cout << "gbr  " << gbr << std::endl;
    //std::cout << "gbr2 " << gbr2 << std::endl;

    auto ga_br = ga + gbr;
    auto ga_br2 = ga + gbr2;
    auto ga_br3 = g * a_br;

    if (ga_br != ga_br2 || ga_br != ga_br3)
    {
        std::cout << "ga_br != ga_br2" << std::endl;
        std::cout << ga_br << std::endl;
        std::cout << ga_br2 << std::endl;
        std::cout << ga_br3 << std::endl;

        throw UnitTestFail("ga_br != ga_br2");
    }

    EccBrick gBrick(g);

    auto gBOne = gBrick * one;

    if (g != gBOne)
    {
        std::cout << "g     " << g << std::endl;
        std::cout << "gBOne " << gBOne << std::endl;

        throw UnitTestFail("ga != gBa");
    }

    auto gBa = gBrick * a;

    if (ga != gBa)
    {
        std::cout << "ga  " << ga << std::endl;
        std::cout << "gBa " << gBa << std::endl;

        throw UnitTestFail("ga != gBa");
    }
    auto gBbr = ((gBrick * b) * r);
    auto gBbr2 = (gBrick * (b * r));

    auto gBa_br = gBa + gBbr;
    auto gBa_br2 = gBa + gBbr2;


    if (gBa_br != gBa_br2 || gBa_br != ga_br2)
    {
        std::cout << "gBa_br  " << gBa_br << std::endl;
        std::cout << "gBa_br2 " << gBa_br2 << std::endl;
        std::cout << "ga_br2  " << ga_br2 << std::endl;

        throw UnitTestFail("gBa_br != gBa_br2");
    }


    //auto g2a = g2 * a;
    //auto g2Ba = g2Brick * a;    
    //
    //if (g2Ba != g2a )
    //{
    //    std::cout << "g2Ba  " << g2Ba << std::endl;
    //    std::cout << "g2a  " << g2a << std::endl;

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
        std::cout << one + one << std::endl;
        throw UnitTestFail("1 + 1 != 2");
    }

    if (one != one * one)
    {
        std::cout << one << std::endl;
        std::cout << one * one << std::endl;
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
            //std::cout << mult_var << " * " << mult << std::endl;

            //std::cout << "mult in " << mult << std::endl;

            // sample Z_p
            auto add = prng.get<u32>() >> 1;

            mult_var = mult_var * mult;
            mult_var2 = mult_var2 * EccNumber(curve, mult);

            div_var = div_var / mult;

            add_var = add_var + add;

            sub_var = sub_var - add;


            if (mult_var != mult_var2)
            {
                std::cout << i << "  " << j << std::endl;
                std::cout << "mult var  " << mult_var << std::endl;
                std::cout << "mult var2 " << mult_var << std::endl;
                throw UnitTestFail("mod mult error");
            }
        }


        if (div_var != one / mult_var)
        {
            std::cout << "div var  " << div_var << std::endl;
            std::cout << "div exp  " << one / mult_var << std::endl;
            throw UnitTestFail("mod div error");
        }

        if (sub_var != -add_var)
        {
            std::cout << "sub var  " << sub_var << std::endl;
            std::cout << "sub exp  " << -add_var << std::endl;
            throw UnitTestFail("mod div error");
        }


    }

    if (zero - 1 !=  - 1)
    {
        std::cout << "-1 = " << zero - 1 << std::endl;
        throw UnitTestFail("-1 mod p");
    }

    //if (ok == false)
    //{
    //    std::cout << "bad rand 22" << std::endl;
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


    //std::cout << "g            " << g << std::endl;


    //for (u64 i = 0; i < 24 * 2; ++i)
    //{
    //    std::cout << "g^"<< i<<"         " << g  * (one * i)<< std::endl;
    //}
    //std::cout << "order        " << order << std::endl;
    //std::cout << "g^(order-1)  " << g*(order - 1) << std::endl;
    //std::cout << "g^order      " << g*order << std::endl;
    //std::cout << "g^(1)        " << g*(one) << std::endl;
    //std::cout << "g^(order+1)  " << g*(order + 1) << std::endl;
    //std::cout << "g^(2)        " << g*(one + one) << std::endl;

    if (g * (curve.getOrder() + 1) != g)
    {
        std::cout << "g^(n+1) != g" << std::endl;
        std::cout << g * (curve.getOrder() + 1) << std::endl;
        std::cout << g << std::endl;
        throw    UnitTestFail("g^(n+1) != g");
    }



    EccNumber a(curve);
    EccNumber b(curve);
    EccNumber r(curve);

    a.randomize(prng);
    b.randomize(prng);
    r.randomize(prng);



    auto a_br = a + b * r;

    //std::cout << a_br << std::endl;

    auto ga = g* a;
    //std::cout << "ga  " << ga << std::endl;

    auto gbr = ((g * b) * r);
    auto gbr2 = g * (b * r);


    //std::cout << "mod  " << curve.getOrder() << std::endl;
    //std::cout << "a    " << a << std::endl;
    //std::cout << "b    " << b << std::endl;
    //std::cout << "r    " << r << std::endl;
    //std::cout << "abr   " << a_br << std::endl;
    //std::cout << "ga  " << ga << std::endl;
    //std::cout << "gbr  " << gbr << std::endl;
    //std::cout << "gbr2 " << gbr2 << std::endl;

    auto ga_br = ga + gbr;
    auto ga_br2 = ga + gbr2;
    auto ga_br3 = g * a_br;

    if (ga_br != ga_br2 || ga_br != ga_br3)
    {
        std::cout << "ga_br != ga_br2" << std::endl;
        std::cout << ga_br << std::endl;
        std::cout << ga_br2 << std::endl;
        std::cout << ga_br3 << std::endl;

        throw UnitTestFail("ga_br != ga_br2");
    }

    EccBrick gBrick(g);

    auto gBOne = gBrick * one;

    if (g != gBOne)
    {
        std::cout << "g     " << g << std::endl;
        std::cout << "gBOne " << gBOne << std::endl;

        throw UnitTestFail("ga != gBa");
    }

    auto gBa = gBrick * a;

    if (ga != gBa)
    {
        std::cout << "ga  " << ga << std::endl;
        std::cout << "gBa " << gBa << std::endl;

        throw UnitTestFail("ga != gBa");
    }
    auto gBbr = ((gBrick * b) * r);
    auto gBbr2 = (gBrick * (b * r));

    auto gBa_br = gBa + gBbr;
    auto gBa_br2 = gBa + gBbr2;


    if (gBa_br != gBa_br2 || gBa_br != ga_br2)
    {
        std::cout << "gBa_br  " << gBa_br << std::endl;
        std::cout << "gBa_br2 " << gBa_br2 << std::endl;
        std::cout << "ga_br2  " << ga_br2 << std::endl;

        throw UnitTestFail("gBa_br != gBa_br2");
    }

    EccNumber Rc(curve);

    std::string rcStr = "769FC4F81A2622436EAACEB85830FB00EA2F2BE8235D30BC9AA06AA2F26092A81F4050F";
    std::string pchA = "3A2E668B199FAD952CE14569D8BFC92259E3B04D7F44B4E7AD8C76FBCDCC916697ECF404";
    std::string pchB = "4DB117E685E3139B176F6A96247FFE476115916F488DF399F3D7C458F849B7DC8174DE2";
    char *rc_cstr = new char[rcStr.length() + 1];
    char *pchA_cstr = new char[pchA.length() + 1];
    char *pchB_cstr = new char[pchB.length() + 1];
    memcpy(rc_cstr   , rcStr.c_str(), rcStr.size() + 1);
    memcpy(pchA_cstr, pchA.c_str(), pchA.size() + 1);
    memcpy(pchB_cstr, pchB.c_str(), pchB.size() + 1);


    Rc.fromHex(rc_cstr);
    //   "769FC4F81A2622436EAACEB85830FB00EA2F2BE8235D30BC9AA06AA2F26092A81F4050F");
    
    EccPoint pch(curve);

    pch.fromHex(pchA_cstr, pchB_cstr);
    //    "3A2E668B199FAD952CE14569D8BFC92259E3B04D7F44B4E7AD8C76FBCDCC916697ECF404", 
    //    "4DB117E685E3139B176F6A96247FFE476115916F488DF399F3D7C458F849B7DC8174DE2");


    delete[] rc_cstr;
    delete[] pchA_cstr;
    delete[] pchB_cstr;

    auto gRc = pch + g * Rc;
    auto gBRc = pch  + gBrick * Rc;


    //std::cout << "g     " << g << std::endl;
    //std::cout << "Rc     " << Rc << std::endl;
    //std::cout << "gBRc  " << gBRc << std::endl;

    //auto g2a = g2 * a;
    //auto g2Ba = g2Brick * a;    
    
    if (gRc != gRc)
    {
        std::cout << "gBRc  " << gBRc << std::endl;
        std::cout << "gRc  " << gRc << std::endl;

        throw UnitTestFail("gBRc != gRc");
    }
}
