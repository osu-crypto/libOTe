
#include "Mtx.h"
#include "LdpcDecoder.h"

namespace osuCrypto
{


    enum class BPAlgo
    {
        LogBP = 0,
        AltLogBP = 1,
        MinSum = 2
    };

    enum class ListDecoder
    {
        Chase = 0 ,
        OSD = 1
    };

    //extern std::vector<u8> minCW;
    
    void LdpcDecode_impulse(const oc::CLP& cmd);

    //u64 impulseDist(LdpcDecoder& D, u64 i, u64 n, u64 k, u64 Ne, u64 maxIter);
    //u64 impulseDist(SparseMtx& mH, u64 Ne, u64 w, u64 maxIter, u64 numThreads, bool randImpulse, u64 trials, BPAlgo algo, bool verbose);
}