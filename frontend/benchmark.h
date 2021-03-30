#include "cryptoTools/Common/CLP.h"

namespace osuCrypto
{

    //inline void encodeBench(CLP& cmd)
    //{
    //    u64 mm = cmd.getOr("r", 100000);
    //    u64 w = cmd.getOr("w", 5);
    //    auto gap = cmd.getOr("g", 16);
    //    LdpcDiagRegRepeaterEncoder::Code code;
    //    if (w == 11)
    //        code = LdpcDiagRegRepeaterEncoder::Weight11;
    //    else if (w == 5)
    //        code = LdpcDiagRegRepeaterEncoder::Weight5;
    //    else
    //        throw RTE_LOC;

    //    u64 colWeight = w;
    //    u64 diags = w;
    //    u64 gapWeight = w;
    //    u64 period = mm;
    //    std::vector<u64> db{ 5,31 };
    //    PRNG pp(oc::ZeroBlock);
    //    u64 trials = cmd.getOr("t", 10);


    //    PRNG prng(ZeroBlock);


    //    LdpcEncoder TZ;
    //    TZ.init(sampleTriangularBand(mm, mm * 2, w, 1, 2, 0, 0, 0, {}, true, true, false, prng, prng), 0);


    //    //auto H = sampleRegTriangularBand(mm, mm, colWeight, gap, gapWeight, diags, 0,0, {}, true, false, false, prng);
    //    ////std::cout << H << std::endl;
    //    //return;
    //    S1DiagRepEncoder mZpsDiagEncoder;
    //    mZpsDiagEncoder.mL.init(mm, colWeight);
    //    mZpsDiagEncoder.mR.init(mm, gap, gapWeight, period, db, true, pp);


    //    std::vector<block> x(mZpsDiagEncoder.cols());
    //    Timer timer;




    //    S1DiagRegRepEncoder enc2;
    //    enc2.mL.init(mm, colWeight);
    //    enc2.mR.init(mm, code, true);

    //    //mZpsDiagEncoder.setTimer(timer);
    //    //enc2.setTimer(timer);
    //    timer.setTimePoint("_____________________");

    //    for (u64 i = 0; i < trials; ++i)
    //    {
    //        TZ.cirTransEncode<block>(x);
    //        timer.setTimePoint("tz");
    //    }
    //    timer.setTimePoint("_____________________");

    //    for (u64 i = 0; i < trials; ++i)
    //    {

    //        mZpsDiagEncoder.cirTransEncode<block>(x);
    //        timer.setTimePoint("a");
    //    }


    //    timer.setTimePoint("_____________________");
    //    for (u64 i = 0; i < trials; ++i)
    //    {

    //        enc2.cirTransEncode<block>(x);
    //        timer.setTimePoint("b");

    //    }

    //    std::cout << timer << std::endl;
    //}

}