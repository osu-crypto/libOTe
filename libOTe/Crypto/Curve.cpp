#include "Curve.h"

#include "Common/Log.h"

#include "miracl/include/miracl.h"
#include "Common/ByteStream.h"

namespace osuCrypto
{
    EllipticCurve::EllipticCurve(const Ecc2mParams & params, const block& seed)
        :
        mMiracl(nullptr),
        mOrder(nullptr),
        BB(nullptr),
        BA(nullptr)
    {
        setParameters(params);
        setPrng(seed);
    }

    EllipticCurve::EllipticCurve(const EccpParams & params, const block & seed)
        :
        mMiracl(nullptr),
        mOrder(nullptr),
        BB(nullptr),
        BA(nullptr)
    {
        setParameters(params);
        setPrng(seed);
    }

    EllipticCurve::~EllipticCurve()
    {
        mG = std::vector<Point>();

        if (mMiracl)
        {
            mirexit(mMiracl);

            mirkill(BA);
            mirkill(BB);
        }
    }

    void EllipticCurve::setParameters(const Ecc2mParams & params, const block& seed)
    {
        setPrng(seed);
        setParameters(params);
    }

    void EllipticCurve::setParameters(const EccpParams & params)
    {

        mIsPrimeField = true;
        mEcc2mParams = Ecc2mParams();
        mEccpParams = params;

        if (mMiracl) mirexit(mMiracl);

        mMiracl = mirsys(params.bitCount * 2, 2);

        //mMiracl = mirsys(300,0);
        mMiracl->IOBASE = 16;

        mirkill(BA);
        mirkill(BB);

        BA = mirvar(mMiracl, 0);
        BB = mirvar(mMiracl, 0);

        cinstr(mMiracl, BA,(char*)params.a);
        cinstr(mMiracl, BB,(char*)params.b);

        mOrder.reset(new EccNumber(*this));
        mOrder->fromHex((char*)params.n);

        mFieldPrime.reset(new EccNumber(*this));
        mFieldPrime->fromHex((char*)params.p);
        //incr(mMiracl, P, 1, mModulus->mVal);
        //*mModulus = *mOrder;
        

        ecurve_init(
            mMiracl,
            BA,
            BB,
            mFieldPrime->mVal,
            //MR_AFFINE
            MR_PROJECTIVE
        );

        //mG.reset(new EccPoint(*this));
        //mG->fromHex(mEccpParams.X, mEccpParams.Y);
        std::stringstream ssX(mEccpParams.X);
        std::stringstream ssY(mEccpParams.Y);

        while (true)
        {
            std::string X, Y;
            std::getline(ssX, X, ',');
            std::getline(ssY, Y, ',');

            if (X.size())
            {
                mG.emplace_back(*this);
                mG.back().fromHex((char*)X.c_str(), (char*)Y.c_str());
            }
            else
            {
                break;
            }
        }

    }

    void EllipticCurve::setPrng(const block & seed)
    {
        mPrng.SetSeed(seed);
        irand(mMiracl, (int)mPrng.get<u32>());
    }

    void EllipticCurve::setParameters(const Ecc2mParams & params)
    {


        mIsPrimeField = false;
        mEcc2mParams = params;
        mEccpParams = EccpParams();

        if (mMiracl) mirexit(mMiracl);

        mMiracl = mirsys(params.bitCount * 2, 2);

        mMiracl->IOBASE = 16;

        if(BA) mirkill(BA);
        if(BB) mirkill(BB);
    
        BA = mirvar(mMiracl, 0);
        BB = mirvar(mMiracl, 0);

        convert(mMiracl, params.BA, BA);
        convert(mMiracl, params.BB, BB);

        mOrder.reset(new EccNumber(*this));
        mOrder->fromHex(params.order);


        ecurve2_init(
            mMiracl,
            params.m,
            params.a,
            params.b,
            params.c,
            BA,
            BB,
            false,
            MR_PROJECTIVE);

        //mG.reset(new EccPoint(*this));
        //mG->fromHex(params.X, params.Y);
        std::stringstream ssX(params.X);
        std::stringstream ssY(params.Y);

        while (true)
        {
            std::string X, Y;
            std::getline(ssX, X, ',');
            std::getline(ssY, Y, ',');

            if (X.size())
            {
                mG.emplace_back(*this);
                mG.back().fromHex((char*)X.c_str(), (char*)Y.c_str());
            }
            else
            {
                break;
            }
        }

    }

    miracl & EllipticCurve::getMiracl() const
    {
        return *mMiracl;
    }

    const EllipticCurve::Point & EllipticCurve::getGenerator() const
    {
        return mG[0];
    }

    const std::vector<EccPoint>& EllipticCurve::getGenerators() const
    {
        return mG;
    }

    const EccNumber & EllipticCurve::getOrder() const
    {
        return *mOrder;
    }

    const EccNumber & EllipticCurve::getFieldPrime() const
    {
        return *mFieldPrime;
    }

    EccPoint::EccPoint(
        EllipticCurve & curve)
        :
        mMem(nullptr),
        mVal(nullptr),
        mCurve(&curve)

    {
        init();
    }

    EccPoint::EccPoint(
        EllipticCurve & curve,
        const EccPoint & copy)
        :
        mMem(nullptr),
        mVal(nullptr),
        mCurve(&curve)
    {
        init();

        *this = copy;
    }

    EccPoint::EccPoint(
        const EccPoint & copy)
        :
        mMem(nullptr),
        mVal(nullptr),
        mCurve(copy.mCurve)
    {

        init();

        *this = copy;
    }

    EccPoint::EccPoint(EccPoint && move)
        :
        mMem(move.mMem),
        mVal(move.mVal),
        mCurve(move.mCurve)
    {
        move.mVal = nullptr;
        move.mMem = nullptr;
    }

    EccPoint::~EccPoint()
    {
        if (mMem)
            ecp_memkill(mCurve->mMiracl, mMem, 0);
    }

    EccPoint & EccPoint::operator=(
        const EccPoint & copy)
    {

        if (mCurve->mIsPrimeField)
        {
            epoint_copy((epoint*)copy.mVal, mVal);
        }
        else
        {
            epoint2_copy((epoint*)copy.mVal, mVal);
        }

        return *this;
    }

    EccPoint & EccPoint::operator+=(
        const EccPoint & addIn)
    {
#ifndef NDEBUG
        if (mCurve != addIn.mCurve) throw std::runtime_error("curves instances must match.");
#endif

        if (mCurve->mIsPrimeField)
        {
            ecurve_add(mCurve->mMiracl, (epoint*)addIn.mVal, mVal);
        }
        else
        {
            ecurve2_add(mCurve->mMiracl, (epoint*)addIn.mVal, mVal);
        }
        return *this;
    }

    EccPoint & EccPoint::operator-=(
        const EccPoint & subtractIn)
    {
#ifndef NDEBUG
        if (mCurve != subtractIn.mCurve) throw std::runtime_error("curves instances must match.");
#endif
        if (mCurve->mIsPrimeField)
        {
            ecurve_sub(mCurve->mMiracl, (epoint*)subtractIn.mVal, mVal);
        }
        else
        {
            ecurve2_sub(mCurve->mMiracl, (epoint*)subtractIn.mVal, mVal);
        }
        return *this;
    }

    EccPoint & EccPoint::operator*=(
        const EccNumber & multIn)
    {
#ifndef NDEBUG
        if (mCurve != multIn.mCurve) throw std::runtime_error("curves instances must match.");
#endif
        //multIn.fromNres();


        if (mCurve->mIsPrimeField)
        {
            ecurve_mult(mCurve->mMiracl, multIn.mVal, mVal, mVal);
        }
        else
        {
            ecurve2_mult(mCurve->mMiracl, multIn.mVal, mVal, mVal);
        }

        return *this;
    }

    EccPoint EccPoint::operator+(
        const EccPoint & addIn) const
    {
#ifndef NDEBUG
        if (mCurve != addIn.mCurve) throw std::runtime_error("curves instances must match.");
#endif

        EccPoint temp(*this);

        temp += addIn;

        return temp;
    }

    EccPoint EccPoint::operator-(
        const EccPoint & subtractIn) const
    {
        EccPoint temp(*this);

        temp -= subtractIn;

        return temp;
    }

    EccPoint EccPoint::operator*(
        const EccNumber & multIn) const
    {

        EccPoint temp(*this);

        temp *= multIn;

        return temp;
    }

    bool EccPoint::operator==(
        const EccPoint & cmp) const
    {
#ifndef NDEBUG
        if (mCurve != cmp.mCurve) throw std::runtime_error("curves instances must match.");
#endif
        if (mCurve->mIsPrimeField)
        {
            return epoint_comp(mCurve->mMiracl, mVal, cmp.mVal);
        }
        else
        {
            return epoint2_comp(mCurve->mMiracl, mVal, cmp.mVal);
        }
    }
    bool EccPoint::operator!=(
        const EccPoint & cmp) const
    {
        return !(*this == cmp);
    }

    u64 EccPoint::sizeBytes() const
    {
        return ((mCurve->mIsPrimeField?
            mCurve->mEccpParams.bitCount : 
            mCurve->mEcc2mParams.bitCount) 
            + 7) / 8 + 1;
    }

    void EccPoint::toBytes(u8 * dest) const
    {
        big varX = mirvar(mCurve->mMiracl, 0);

        // convert the point into compressed format where dest[0] holds
        // the y bit and varX holds the x data.
        if (mCurve->mIsPrimeField)
        {
            dest[0] = epoint_get(mCurve->mMiracl, mVal, varX, varX) & 1;
        }
        else
        {
            dest[0] = epoint2_get(mCurve->mMiracl, mVal, varX, varX) & 1;
        }
        // copy the bits of varX into the buffer
        big_to_bytes(mCurve->mMiracl, (int)sizeBytes() - 1, varX, (char*)dest + 1, true);

        mirkill(varX);
    }

    void EccPoint::fromBytes(u8 * src)
    {
        big varX = mirvar(mCurve->mMiracl, 0);

        bytes_to_big(mCurve->mMiracl, (int)sizeBytes() - 1, (char*)src + 1, varX);
        if (mCurve->mIsPrimeField)
        {
            epoint_set(mCurve->mMiracl, varX, varX, src[0], mVal);
        }
        else
        {
            epoint2_set(mCurve->mMiracl, varX, varX, src[0], mVal);
        }

        mirkill(varX);
    }

    void EccPoint::fromHex(char * x, char * y)
    {
        EccNumber XX(*mCurve), YY(*mCurve);
        XX.fromHex(x);
        YY.fromHex(y);

        fromNum(XX, YY);
    }

    void EccPoint::fromDec(char * x, char * y)
    {

        EccNumber XX(*mCurve), YY(*mCurve);
        XX.fromDec(x);
        YY.fromDec(y);
        fromNum(XX, YY);

    }

    void EccPoint::fromNum(EccNumber & XX, EccNumber & YY)
    {

        if (mCurve->mIsPrimeField)
        {
            auto result = epoint_set(mCurve->mMiracl, XX.mVal, YY.mVal, 0, mVal);

            //Log::out << "plain " << XX << " " << YY << Log::endl;
            //Log::out << "point " << *this << Log::endl;
            if (result == false)
            {
                Log::out << "bad point" << Log::endl;
                throw std::runtime_error(LOCATION);
            }
        }
        else
        {
            auto result = epoint2_set(mCurve->mMiracl, XX.mVal, YY.mVal, 0, mVal);

            if (result == false)
            {
                Log::out << "bad point" << Log::endl;
                throw std::runtime_error(LOCATION);
            }
        }
    }


    void EccPoint::randomize(PRNG& prng)
    {
        u64 byteSize = (mCurve->mEcc2mParams.bitCount + 7) / 8;
        u8* buff = new u8[byteSize];
        //u8* buff2 = new u8[sizeBytes()];

        // a mask for the top bits so the buff contains at most 
        // bitCount non zeros
        u8 mask = u8(-1);
        if (mCurve->mEcc2mParams.bitCount & 7)
            mask >>= (8 - (mCurve->mEcc2mParams.bitCount & 7));


        big var = mirvar(mCurve->mMiracl, 0);

        //do
        {
            //TODO("replace bigdig with our PRNG");

            //bigdig(mCurve->mMiracl, mCurve->mParams.bitCount, 2, var);
            prng.get(buff, byteSize);
            buff[byteSize - 1] &= mask;

            bytes_to_big(mCurve->mMiracl, byteSize, (char*)buff, var);
            if (mCurve->mIsPrimeField)
            {
                epoint_set(mCurve->mMiracl, var, var, 0, mVal);
            }
            else
            {
                epoint2_set(mCurve->mMiracl, var, var, 0, mVal);
            }
            //toBytes(buff2);
            //fromBytes(buff2);
        } 
        
        if (point_at_infinity(mVal))
        {
            // if that failed, just get a random point
            // by computing g^r    where r <- Z_p
            EccNumber num(*mCurve, prng);

            *this = mCurve->getGenerator() * num;
        }


        delete[] buff;
        //delete[] buff2;
        mirkill(var);


        //const auto& g = mCurve->getGenerator();
        //EccNumber num(mCurve,prng);

        //*this = g * num;
    }

    void EccPoint::randomize(const block & seed)
    {
        PRNG prng(seed);
        randomize(prng);
    }

    void EccPoint::setCurve(EllipticCurve & curve)
    {
        mCurve = &curve;
    }

    void EccPoint::init()
    {
        mMem = (char *)ecp_memalloc(mCurve->mMiracl, 1);
        mVal = (epoint *)epoint_init_mem(mCurve->mMiracl, mMem, 0);
    }

    EccNumber::EccNumber(const EccNumber & num)
        :mVal(nullptr)
        , mCurve(num.mCurve)
    {
        init();

        *this = num;
    }

    EccNumber::EccNumber(EccNumber && num)
        : mVal(num.mVal)
        , mCurve(num.mCurve)
    {
        num.mVal = nullptr;
    }

    EccNumber::EccNumber(
        EllipticCurve & curve)
        :
        mVal(nullptr),
        mCurve(&curve)
    {
        init();
    }

    EccNumber::EccNumber(
        EllipticCurve & curve,
        const EccNumber& copy)
        :
        mVal(nullptr),
        mCurve(&curve)
    {
        init();
        *this = copy;
    }

    EccNumber::EccNumber(EllipticCurve & curve, PRNG & prng)
        :
        mVal(nullptr),
        mCurve(&curve)
    {
        init();
        randomize(prng);
    }

    EccNumber::EccNumber(
        EllipticCurve & curve,
        const i32 & val)
        :
        mVal(nullptr),
        mCurve(&curve)
    {
        init();
        *this = val;
    }

    EccNumber::~EccNumber()
    {
        if (mVal)
            mirkill(mVal);
    }

    EccNumber& EccNumber::operator=(const EccNumber& c)
    {
        copy(c.mVal, mVal);
        return *this;
    }

    EccNumber& EccNumber::operator=(big c)
    {
        copy(c, mVal);
        return *this;
    }

    EccNumber& EccNumber::operator=(int i)
    {
        if (i == 0)
            zero(mVal);
        else
        {
            convert(mCurve->mMiracl, i, mVal);
            reduce();
            //nres(mCurve->mMiracl, mVal, mVal); 
        }
        return *this;
    }
    EccNumber& EccNumber::operator++()
    {
        incr(mCurve->mMiracl, mVal, 1, mVal);
        reduce();

        //toNres();
        //nres_modadd(mCurve->mMiracl, mVal, mCurve->mMiracl->one, mVal); 
        return *this;
    }
    EccNumber& EccNumber::operator--()
    {
        decr(mCurve->mMiracl, mVal, 1, mVal);
        reduce();

        //toNres();
        //nres_modsub(mCurve->mMiracl, mVal, mCurve->mMiracl->one, mVal); 
        return *this;
    }

    EccNumber& EccNumber::operator+=(int i)
    {
        EccNumber inc(*mCurve, i);

        add(mCurve->mMiracl, mVal, inc.mVal, mVal);
        reduce();

        //toNres();
        //inc.toNres();
        //nres_modadd(mCurve->mMiracl, mVal, inc.mVal, mVal); 

        return *this;
    }
    EccNumber& EccNumber::operator-=(int i)
    {
        EccNumber dec(*mCurve, i);
        subtract(mCurve->mMiracl, mVal, dec.mVal, mVal);
        reduce();

        //toNres();
        //dec.toNres();
        //nres_modsub(mCurve->mMiracl, mVal, dec.mVal, mVal);

        return *this;
    }
    EccNumber& EccNumber::operator+=(const EccNumber& b)
    {
        add(mCurve->mMiracl, mVal, b.mVal, mVal);
        reduce();

        //toNres();
        //b.toNres();
        //nres_modadd(mCurve->mMiracl, mVal, b.mVal, mVal); 

        return *this;
    }
    EccNumber& EccNumber::operator-=(const EccNumber& b)
    {
        subtract(mCurve->mMiracl, mVal, b.mVal, mVal);
        reduce();
        //toNres();
        //b.toNres();
        //nres_modsub(mCurve->mMiracl, mVal, b.mVal, mVal); 
        return *this;
    }
    EccNumber& EccNumber::operator*=(const EccNumber& b)
    {
        multiply(mCurve->mMiracl, mVal, b.mVal, mVal);
        reduce();

        //toNres();
        //b.toNres();
        //nres_modmult(mCurve->mMiracl, mVal, b.mVal, mVal);
        return *this;
    }
    EccNumber& EccNumber::operator*=(int i)
    {
        premult(mCurve->mMiracl, mVal,i, mVal);
        reduce();

        //toNres();
        //nres_premult(mCurve->mMiracl, mVal, i, mVal);
        return *this;
    }
    EccNumber& EccNumber::operator/=(const EccNumber& b)
    {
        divide(mCurve->mMiracl, mVal, mCurve->getOrder().mVal, mVal);

        //toNres();
        //b.toNres();
        //nres_moddiv(mCurve->mMiracl, mVal, b.mVal, mVal);
        return *this;
    }
    EccNumber& EccNumber::operator/=(int i)
    {
        EccNumber div(*mCurve, i);

        *this /= div;

        //toNres();
        //div.toNres();
        //nres_moddiv(mCurve->mMiracl, mVal, div.mVal, mVal);

        return *this;
    }

    EccNumber& EccNumber::negate()
    {
        insign(-1, mVal);
        reduce();
        
        //toNres();
        //nres_negate(mCurve->mMiracl, mVal, mVal);
        return *this;
    }

    bool EccNumber::operator==(const EccNumber & cmp) const
    {
        //fromNres();
        //cmp.fromNres();
        return (mr_compare(mVal, cmp.mVal) == 0);
    }

    bool EccNumber::operator==(const int & cmp)const
    {
        return cmp == *this;
    }

    bool EccNumber::operator!=(const EccNumber & cmp)const
    {
        return !(*this == cmp);
    }

    bool EccNumber::operator!=(const int & cmp)const
    {
        return !(*this == cmp);
    }

    bool EccNumber::operator>=(const EccNumber & cmp)const
    {
        //fromNres();
        //cmp.fromNres();
        return (mr_compare(mVal, cmp.mVal) >= 0);
    }

    bool EccNumber::operator>=(const int & cmp)const
    {
        EccNumber c(*mCurve, cmp);
        return (*this >= c);
    }

    bool EccNumber::operator<=(const EccNumber & cmp)const
    {
        //fromNres();
        //cmp.fromNres();
        return (mr_compare(mVal, cmp.mVal) <= 0);
    }

    bool EccNumber::operator<=(const int & cmp)const
    {
        EccNumber c(*mCurve, cmp);
        return (*this <= c);
    }

    bool EccNumber::operator>(const EccNumber & cmp)const
    {
        return !(cmp >= *this);
    }

    bool EccNumber::operator>(const int & cmp)const
    {
        EccNumber c(*mCurve, cmp);
        return !(c >= *this);
    }

    bool EccNumber::operator<(const EccNumber & cmp)const
    {
        return !(cmp <= *this);
    }

    bool EccNumber::operator<(const int & cmp)const
    {
        EccNumber c(*mCurve, cmp);
        return !(c <= *this);
    }

    BOOL EccNumber::iszero() const
    {
        if (size(mVal) == 0) return TRUE;
        return FALSE;
    }

    bool operator==(const int & cmp1, const EccNumber & cmp2)
    {
        EccNumber cmp(*cmp2.mCurve, cmp1);

        return (cmp == cmp2);
    }

    EccNumber operator-(const EccNumber& b)
    {
        EccNumber x = b;
        x.negate();
        return x;
    }

    EccNumber operator+(const EccNumber& b, int i)
    {
        EccNumber abi = b;
        abi += i;
        return abi;
    }
    EccNumber operator+(int i, const EccNumber& b)
    {
        EccNumber aib = b; 
        aib += i;
        return aib;
    }
    EccNumber operator+(const EccNumber& b1, const EccNumber& b2)
    {
        EccNumber abb = b1;
        abb += b2;
        return abb;
    }

    EccNumber operator-(const EccNumber& b, int i)
    {
        EccNumber mbi = b; 
        mbi -= i;
        return mbi;
    }
    EccNumber operator-(int i, const EccNumber& b)
    {
        EccNumber mib(*b.mCurve, i);
        mib -= b;
        return mib;
    }
    EccNumber operator-(const EccNumber& b1, const EccNumber& b2)
    {
        EccNumber mbb = b1;
        mbb -= b2; 
        return mbb;
    }

    EccNumber operator*(const EccNumber& b, int i)
    {
        EccNumber xbb = b;
        xbb *= i;
        return xbb;
    }
    EccNumber operator*(int i, const EccNumber& b)
    {
        EccNumber xbb = b; 
        xbb *= i;
        return xbb;
    }
    EccNumber operator*(const EccNumber& b1, const EccNumber& b2)
    {
        EccNumber xbb = b1; 
        xbb *= b2;
        return xbb;
    }

    EccNumber operator/(const EccNumber& b1, int i)
    {
        EccNumber z = b1; 
        z /= i;
        return z;
    }

    EccNumber operator/(int i, const EccNumber& b2)
    {
        EccNumber z(*b2.mCurve, i); 
        z /= b2;
        return z;
    }
    EccNumber operator/(const EccNumber& b1, const EccNumber& b2)
    {
        EccNumber z = b1; 
        z /= b2;
        return z;
    }

    u64 EccNumber::sizeBytes() const
    {
        return ((mCurve->mIsPrimeField ? 
            mCurve->mEccpParams.bitCount :
            mCurve->mEcc2mParams.bitCount)
            + 7) / 8;
    }

    void EccNumber::toBytes(u8 * dest) const
    {
        //fromNres();
        big_to_bytes(mCurve->mMiracl, (int)sizeBytes(), mVal, (char*)dest, true);

        //dest[0] = exsign(mVal);
        //if (b)
        //{
        //    Log::out << *this << Log::endl;
        //    Log::out << u32(dest[0]) << Log::endl;
        //}
    }

    void EccNumber::fromBytes(u8 * src)
    {
        bytes_to_big(mCurve->mMiracl, (int)sizeBytes(), (char*)src, mVal);
        //mIsNres = NresState::nonNres;
        //if (b)
            //Log::out << *this << Log::endl;

        //insign(char(src[0]), mVal);

        //if (b)
        //{
        //    Log::out << *this << Log::endl;
        //    Log::out << u32(src[0]) << Log::endl;
        //}
    }

    void EccNumber::fromHex(char * src)
    {
        auto oldBase = mCurve->mMiracl->IOBASE;
        mCurve->mMiracl->IOBASE = 16;

        cinstr(mCurve->mMiracl, mVal, src);
        //mIsNres = NresState::nonNres;

        mCurve->mMiracl->IOBASE = oldBase;
    }

    void EccNumber::fromDec(char * src)
    {
        auto oldBase = mCurve->mMiracl->IOBASE;
        mCurve->mMiracl->IOBASE = 10;

        cinstr(mCurve->mMiracl, mVal, src);
        //mIsNres = NresState::nonNres;

        mCurve->mMiracl->IOBASE = oldBase;
    }

    void EccNumber::randomize(PRNG & prng)
    {

        int m;
        mr_small r;

        auto w = mCurve->getOrder().mVal;
        auto mr_mip = mCurve->mMiracl;

        m = 0;
        zero(mVal);

        do
        { /* create big rand piece by piece */
            m++;
            mVal->len = m;
            r = prng.get<u64>();

            if (mCurve->mMiracl->base == 0)
            {
                mVal->w[m - 1] = r;
            }
            else
            {
                mVal->w[m - 1] = MR_REMAIN(r, mCurve->mMiracl->base);
            }

        } while (mr_compare(mVal, w) < 0);

        mr_lzero(mVal);
        divide(_MIPP_ mVal, w, w);

        while (mr_compare(mVal, mCurve->getOrder().mVal) > 0)
        {
            Log::out << "bad rand" << Log::endl;
            throw std::runtime_error("");
        }

    }

    void EccNumber::randomize(const block & seed)
    {
        PRNG prng(seed);
        randomize(prng);
    }

    void EccNumber::init()
    {
        mVal = mirvar(mCurve->mMiracl, 0);

    }

    void EccNumber::reduce()
    {

        if (exsign(mVal) == -1)
        {
            //Log::out << "neg                  " << *this << Log::endl;


            add(mCurve->mMiracl, mVal, mCurve->getOrder().mVal, mVal);
            //*this += mCurve->getOrder();

            if (exsign(mVal) == -1)
            {
                Log::out << "neg reduce error " << *this << Log::endl;
                Log::out << "                  " << mCurve->getOrder() << Log::endl;
                throw std::runtime_error(LOCATION);
            }
        }
            
        if(*this >= mCurve->getOrder())
        {
            // only computes the remainder. since the params are
            //
            //    divide(mVal, mod, mod)
            //
            // mVal holds  the remainder
            bool  n = 0;
            if (exsign(mVal) == -1)
            {
                Log::out << *this << " -> ";
                n = 1;
            }

            divide(mCurve->mMiracl, 
                mVal, 
                mCurve->getOrder().mVal,
                mCurve->getOrder().mVal);

            if (n)
            {
                Log::out << *this << Log::endl;
            }
        }

        //if (exsign(mVal) == -1)
        //{
        //    *this += mCurve->getModulus();
        //}
        //else if (*this >= mCurve->getModulus())
        //{
        //    *this -= mCurve->getModulus();
        //}


        //if (exsign(mVal) == -1 || *this >= mCurve->getModulus())
        //{
        //    Log::out << "EccNumber mod error" << Log::endl;
        //    throw std::runtime_error("");
        //}
    }

    EccBrick::EccBrick(const EccPoint & copy)
        :mCurve(copy.mCurve)
    {
        bool result = 0;
        //big x, y;
        if (mCurve->mIsPrimeField)
        {

            big x = mirvar(copy.mCurve->mMiracl, 0);
            big y = mirvar(copy.mCurve->mMiracl, 0);

            redc(copy.mCurve->mMiracl, copy.mVal->X, x);
            redc(copy.mCurve->mMiracl, copy.mVal->Y, y);



            result = ebrick_init(mCurve->mMiracl, &mBrick, 
                x,y, 
                mCurve->BA, mCurve->BB,
                mCurve->getFieldPrime().mVal,
                8, mCurve->mEccpParams.bitCount);

            mirkill(x);
            mirkill(y);
        }
        else
        {

            //fe2ec2(point)->getxy(x, y);
            result = ebrick2_init(mCurve->mMiracl, &mBrick2, copy.mVal->X, copy.mVal->Y, mCurve->BA, mCurve->BB,
                mCurve->mEcc2mParams.m, mCurve->mEcc2mParams.a, mCurve->mEcc2mParams.b, mCurve->mEcc2mParams.c, 8, mCurve->mEcc2mParams.bitCount);
        }

        if (result == 0)
        {
            throw std::runtime_error(LOCATION);
        }
    }

    EccBrick::EccBrick(EccBrick && copy)
        :
        mBrick2(copy.mBrick2),
        mCurve(copy.mCurve)
    {

    }

    EccPoint EccBrick::operator*(const EccNumber & multIn) const
    {

        EccPoint ret(*mCurve);

        multiply(multIn, ret);

        return ret;
    }

    void EccBrick::multiply(const EccNumber & multIn, EccPoint & result) const
    {
#ifndef NDEBUG
        if (mCurve != multIn.mCurve) throw std::runtime_error("curves instances must match.");
        if (mCurve != result.mCurve) throw std::runtime_error("curves instances must match.");
#endif

        //multIn.fromNres();
        big x, y;

        x = mirvar(mCurve->mMiracl, 0);
        y = mirvar(mCurve->mMiracl, 0);


        if (mCurve->mIsPrimeField)
        {
            mul_brick(mCurve->mMiracl, (ebrick*)&mBrick, multIn.mVal, x, y);
            epoint_set(mCurve->mMiracl, x, y, 0, result.mVal);
            //throw std::runtime_error(LOCATION);
        }
        else
        {
            //throw std::runtime_error(LOCATION);
            mul2_brick(mCurve->mMiracl, (ebrick2*)&mBrick2, multIn.mVal, x, y);
            epoint2_set(mCurve->mMiracl, x, y, 0, result.mVal);
        }

        mirkill(x);
        mirkill(y);
    }

    std::ostream & operator<<(std::ostream & out, const EccNumber & val)
    {
        //val.fromNres();

        cotstr(val.mCurve->mMiracl, val.mVal, val.mCurve->mMiracl->IOBUFF);
        out << val.mCurve->mMiracl->IOBUFF;

        return out;
    }

    std::ostream & operator<<(std::ostream & out, const EccPoint & val)
    {

        if (val.mVal->marker == MR_EPOINT_INFINITY)
        {
            out << "(Infinity)";
        }
        else
        {

            if (val.mCurve->mIsPrimeField)
            {
                epoint_norm(val.mCurve->mMiracl, val.mVal);
                big x = mirvar(val.mCurve->mMiracl, 0);
                big y = mirvar(val.mCurve->mMiracl, 0);

                redc(val.mCurve->mMiracl, val.mVal->X, x);
                redc(val.mCurve->mMiracl, val.mVal->Y, y);

                cotstr(val.mCurve->mMiracl, x, val.mCurve->mMiracl->IOBUFF);
                out << val.mCurve->mMiracl->IOBUFF << " ";
                cotstr(val.mCurve->mMiracl, y, val.mCurve->mMiracl->IOBUFF);
                out << val.mCurve->mMiracl->IOBUFF;

                mirkill(x);
                mirkill(y);

            }
            else
            {
                epoint2_norm(val.mCurve->mMiracl, val.mVal);

                cotstr(val.mCurve->mMiracl, val.mVal->X, val.mCurve->mMiracl->IOBUFF);
                out << val.mCurve->mMiracl->IOBUFF << " ";
                cotstr(val.mCurve->mMiracl, val.mVal->Y, val.mCurve->mMiracl->IOBUFF);
                out << val.mCurve->mMiracl->IOBUFF;

            }

        }

        return out;
    }

}