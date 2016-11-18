#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 


#include "miracl/include/miracl.h"
#include "Common/Defines.h"
#include "Crypto/PRNG.h"
#include <memory>
namespace osuCrypto
{

#ifndef MR_GENERIC_MT
#error "expecting Miracl to have generic multi-threading"
#endif

    // elliptic curve parameters for prime fields F_p
    struct EccpParams
    {
        u32 bitCount;
        // prime
        const char* p;
        // order
        const char* n;
        // coefficient a   for  y^2=x^3+ax+b  (mod p)
        const char* a;
        // coefficient b   for  y^2=x^3+ax+b  (mod p)
        const char* b;
        // Generator X coordiate
        const char* X;
        // Generator Y coordiate
        const char* Y;
    };


    const EccpParams p5_INSECURE
    {
        5, //bitCount
        "17", // prime p 
        "18", // order n
        "1", // coefficient a
        "0", // coefficient b
        "B", // generator X
        "A" // generator Y  
    };
    // NIST Prime Curves Parameters 
    // http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
    // FIPS 186-2
    // extra generators were computed using SageMath

    const EccpParams p160Param
    {
        160,
        "D9C574C2AE564498F71D2DE9E371F8CD3943AC29",// prime
        "D9C574C2AE564498F71E2D49D2F2A824B7CD76FD",// order
        "-3",// coefficient a
        "5FFB743F36241263F07BD09325BD458EDFD4F468",// coefficient b
        "1",// X
        "CF65573794C0D0C494310ED3008679F01AFAF63A" // Y
    };

    const EccpParams p192
    {
        192, //bitCount
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", // prime p
        "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", // order n (prime)
        "-3", // coefficient a
        "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", // coefficient b
                                                            // X coordinate for 3 generators 
                                                            "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,F4544EE4AF10068B2F4B84F89C61D62321DFDCE3C64FB8AC,AA7413B7548B2E65DD4803051781E551CEBFD225FECAE3A8",
                                                            // Y coordinate for 3 generators 
                                                            "07192b95ffc8da78631011ed6b24cdd573f977a11e794811,98947BC0114D6962864CA0B4327128BAF21D1A5A0B3116E7,A9B71EE5740AC250F28C975C63857AF065F13B683FA83367",
    };

    const EccpParams p224
    {
        224, //bitCount
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", // prime p
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", // order n (prime)
        "-3", // coefficient a
        "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", // coefficient b
        "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,50C28C17768D789CCB4E627CED3DEC9E2458420D16053A18F6F757BA,E8D310D34AEEA15E8B3ECC8F2D8814D5CA1CEA3A4DD4BC925F1E3584", // generator X
        "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34,E9CE211AC8B9572B5C1CECF02F590ABD2B17EE790E547834A3F101A2,BFCC93F3E072D5AA145C78E9205EFE320BB674E58599D87814D91BCE" // generator Y
    };


    const EccpParams Curve25519
    {
        256, //bitCount
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", // prime p
        "80000000000000000000000000000000A6F7CEF517BCE6B2C09318D2E7AE9F68", // order n (prime)
        "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144", // coefficient a
        "7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864", // coefficient b
                                                                            // generator X
                                                                            "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a,3f267c73b659f84aff395f3fe0192d49c2fec1b08d9c71bc244f2a77ab5b9213,266ab69088cd09d2f6f774004d15cc5d46e5b8481ad56e30dbe08f18cdf6c4c",
                                                                            // generator Y
                                                                            "20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9,5df0b7dac0994826e3ea1d0bbb5e0bab45537a3929fceb47329c35fd02edfe72,9740583582a16a3d924f6a70da8849d54f9939de3cc7fb6bbb71ef982918eb1"
    };




    // elliptic curve parameters for binary fields F_{2^m}
    struct Ecc2mParams
    {

        u32 bitCount;
        u32 BA;
        u32 BB;
        const char* X;
        const char* Y;
        u32 m;
        u32 a;
        u32 b;
        u32 c;
        const char* order;
    };


    // NIST Koblitz Curves Parameters 
    // https://en.wikisource.org/wiki/NIST_Koblitz_Curves_Parameters
    // FIPS 186-2 

    const Ecc2mParams k163 =
    {
        163,
        1,  // BA
        1,  // BB 
        "2fe13c0537bbc11acaa07d793de4e6d5e5c94eee8", // X
        "289070fb05d38ff58321f2e800536d538ccdaa3d9", // Y
        163, // m
        7,   // a
        6,   // b
        3,   // c
        "800000000000000000004021145C1981B33F14BDE" // order
    };

    const Ecc2mParams k233 =
    {
        233,
        0,  // BA
        1,  // BB 
        "17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126", // X
        "1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3", // Y
        233, // m
        74,  // a
        0,   // b
        0,   // c
        "200000000000000000000000000001A756EE456F351BBEC6B57C5CEAF7C" // order
    };

    const Ecc2mParams k283 =
    {
        283,
        0,  // BA
        1,  // BB 
        "503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836,503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836,503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836", // X
        "1ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259,1ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259,1ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259", // Y
        283, // m
        12,  // a
        7,   // b
        5,   // c
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA6B8BB41D5DC9977FDFE511478187858F184" // order
    };

    class EllipticCurve;
    class EccPoint;
    class EccBrick;


    class EccNumber
    {
    public:

        EccNumber(const EccNumber& num);
        EccNumber(EccNumber&& num);
        EccNumber(EllipticCurve& curve);
        EccNumber(EllipticCurve& curve, const EccNumber& copy);
        EccNumber(EllipticCurve& curve, PRNG& prng);
        EccNumber(EllipticCurve& curve, const i32& val);

        ~EccNumber();

        EccNumber& operator=(const EccNumber& c);
        EccNumber& operator=(big c);
        EccNumber& operator=(int i);


        EccNumber& operator++();
        EccNumber& operator--();
        EccNumber& operator+=(int i);
        EccNumber& operator-=(int i);
        EccNumber& operator+=(const EccNumber& b);
        EccNumber& operator-=(const EccNumber& b);
        EccNumber& operator*=(const EccNumber& b);
        EccNumber& operator*=(int i);
        EccNumber& operator/=(const EccNumber& b);
        EccNumber& operator/=(int i);
        EccNumber& negate();

        bool operator==(const EccNumber& cmp) const;
        bool operator==(const int& cmp)const;
        friend bool operator==(const int& cmp1, const EccNumber& cmp2);
        bool operator!=(const EccNumber& cmp)const;
        bool operator!=(const int& cmp)const;
        friend bool operator!=(const int& cmp1, const EccNumber& cmp2);

        bool operator>=(const EccNumber& cmp)const;
        bool operator>=(const int& cmp)const;

        bool operator<=(const EccNumber& cmp)const;
        bool operator<=(const int& cmp)const;

        bool operator>(const EccNumber& cmp)const;
        bool operator>(const int& cmp)const;

        bool operator<(const EccNumber& cmp)const;
        bool operator<(const int& cmp)const;


        BOOL iszero() const;


        friend EccNumber operator-(const EccNumber&);
        friend EccNumber operator+(const EccNumber&, int);
        friend EccNumber operator+(int, const EccNumber&);
        friend EccNumber operator+(const EccNumber&, const EccNumber&);

        friend EccNumber operator-(const EccNumber&, int);
        friend EccNumber operator-(int, const EccNumber&);
        friend EccNumber operator-(const EccNumber&, const EccNumber&);

        friend EccNumber operator*(const EccNumber&, int);
        friend EccNumber operator*(int, const EccNumber&);
        friend EccNumber operator*(const EccNumber&, const EccNumber&);

        friend EccNumber operator/(const EccNumber&, int);
        friend EccNumber operator/(int, const EccNumber&);
        friend EccNumber operator/(const EccNumber&, const EccNumber&);

        u64 sizeBytes() const;
        void toBytes(u8* dest) const;
        void fromBytes(u8* src);
        void fromHex(char* src);
        void fromDec(char* src);

        void randomize(PRNG& prng);
        void randomize(const block& seed);


    private:

        void init();
        void reduce();

        //void toNres()const;
        //void fromNres()const;
        //enum class NresState
        //{
        //    nres,
        //    nonNres,
        //    uninitialized
        //};
        //mutable NresState mIsNres;

    public:
        big mVal;
        EllipticCurve* mCurve;

        friend class EllipticCurve;
        friend EccBrick;
        friend EccPoint;
        friend std::ostream& operator<<(std::ostream& out, const EccNumber& val);
    };
    std::ostream& operator<<(std::ostream& out, const EccNumber& val);


    class EccPoint
    {
    public:


        EccPoint(EllipticCurve& curve);
        EccPoint(EllipticCurve& curve, const EccPoint& copy);
        EccPoint(const EccPoint& copy);
        EccPoint(EccPoint&& move);

        ~EccPoint();

        EccPoint& operator=(const EccPoint& copy);
        EccPoint& operator+=(const EccPoint& addIn);
        EccPoint& operator-=(const EccPoint& subtractIn);
        EccPoint& operator*=(const EccNumber& multIn);


        EccPoint operator+(const EccPoint& addIn) const;
        EccPoint operator-(const EccPoint& subtractIn) const;
        EccPoint operator*(const EccNumber& multIn) const;

        bool operator==(const EccPoint& cmp) const;
        bool operator!=(const EccPoint& cmp) const;

        u64 sizeBytes() const;
        void toBytes(u8* dest) const;
        void fromBytes(u8* src);
        void fromHex(char* x, char* y);
        void fromDec(char* x, char* y);
        void fromNum(EccNumber& x, EccNumber& y);

        void randomize(PRNG& prng);
        void randomize(const block& seed);

        void setCurve(EllipticCurve& curve);

        epoint* mVal;
    private:

        void init();
        char* mMem;
        EllipticCurve* mCurve;
        //EllipticCurve& getCurve();

        friend EccBrick;
        friend EccNumber;
        friend std::ostream& operator<<(std::ostream& out, const EccPoint& val);
    };

    std::ostream& operator<<(std::ostream& out, const EccPoint& val);

    class EccBrick
    {
    public:
        EccBrick(const EccPoint& copy);
        EccBrick(EccBrick&& copy);

        EccPoint operator*(const EccNumber& multIn) const;

        void multiply(const EccNumber& multIn, EccPoint& result) const;

    private:

        ebrick2 mBrick2;
        ebrick mBrick;
        EllipticCurve* mCurve;

    };

    class EllipticCurve
    {
    public:
        typedef EccPoint Point;



        EllipticCurve(const Ecc2mParams& params, const block& seed);
        EllipticCurve(const EccpParams& params, const block& seed);
        EllipticCurve() = delete;
        ~EllipticCurve();


        void setParameters(const Ecc2mParams& params);
        void setParameters(const Ecc2mParams& params, const block& seed);
        void setParameters(const EccpParams& params);
        void setParameters(const EccpParams& params, const block& seed);
        void setPrng(const block& seed);

        miracl& getMiracl() const;
        const Point& getGenerator() const;
        const std::vector<Point>& getGenerators() const;
        const EccNumber& getOrder() const;
        const EccNumber& getFieldPrime() const;

    private:
        // A **non-thread safe** member variable which acts as a memory pool and 
        // determines the byte/bit size of the variables within this curve.
        miracl* mMiracl;

        bool mIsPrimeField;
        PRNG mPrng;
        //csprng mMrPrng;
        Ecc2mParams mEcc2mParams;
        EccpParams mEccpParams;
        big BA, BB;
        std::unique_ptr<EccNumber> mOrder, mFieldPrime;
        std::vector<Point> mG;



        friend Point;
        friend EccNumber;
        friend EccBrick;
        friend std::ostream& operator<<(std::ostream & out, const EccPoint & val);
        friend std::ostream& operator<<(std::ostream& out, const EccNumber& val);



        friend EccNumber operator-(const EccNumber&);
        friend EccNumber operator+(const EccNumber&, int);
        friend EccNumber operator+(int, const EccNumber&);
        friend EccNumber operator+(const EccNumber&, const EccNumber&);

        friend EccNumber operator-(const EccNumber&, int);
        friend EccNumber operator-(int, const EccNumber&);
        friend EccNumber operator-(const EccNumber&, const EccNumber&);

        friend EccNumber operator*(const EccNumber&, int);
        friend EccNumber operator*(int, const EccNumber&);
        friend EccNumber operator*(const EccNumber&, const EccNumber&);

        friend EccNumber operator/(const EccNumber&, int);
        friend EccNumber operator/(int, const EccNumber&);
        friend EccNumber operator/(const EccNumber&, const EccNumber&);

    };

}
