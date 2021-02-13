

#include "cryptoTools/Common/CLP.h"
#include <vector>
#include "Mtx.h"
namespace osuCrypto
{

    std::pair<double, std::vector<u64>> minDist(const DenseMtx& mtx, bool verbose);
    DenseMtx computeGen(DenseMtx& H);
    DenseMtx computeGen(DenseMtx H, std::vector<std::pair<u64, u64>>& colSwaps);

    namespace tests
    {
        void computeGen_test(const oc::CLP& cmd);
        void computeGen_test2(const oc::CLP& cmd);
    }


    int minDist(std::string path, u64 numTHreads, bool verbose);
    int minDist2(const DenseMtx& mtx, u64 numTHreads, bool verbose);
    //inline int minDist(std::string path, u64 numTHreads)
    //{
    //    return minDist(path, numTHreads, false);
    //}
    //inline int minDist2(const DenseMtx& mtx, u64 numTHreads)
    //{
    //    return minDist2(mtx, numTHreads, false);
    //}

    void ithCombination(u64 index, u64 n, std::vector<u64>& set);
    std::vector<u64> ithCombination(u64 index, u64 n, u64 k);
    u64 choose(u64 n, u64 k);

    extern int alg994;
    extern int num_saved_generators;
    extern int num_cores;
    extern int num_permutations;
    extern int print_matrices;

}

void rank(oc::CLP& cmd);