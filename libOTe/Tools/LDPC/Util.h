

#include "libOTe/config.h"
#include "cryptoTools/Common/CLP.h"
#include <vector>
#include "Mtx.h"
namespace osuCrypto
{
    DenseMtx computeGen(DenseMtx& H);
    DenseMtx computeGen(DenseMtx H, std::vector<std::pair<u64, u64>>& colSwaps);

    int minDist(std::string path, u64 numTHreads, bool verbose);
    int minDist2(const DenseMtx& mtx, u64 numTHreads, bool verbose);


    void ithCombination(u64 index, u64 n, std::vector<u64>& set);
    std::vector<u64> ithCombination(u64 index, u64 n, u64 k);
    u64 choose(u64 n, u64 k);

#ifdef ENABLE_ALGO994
    extern int alg994;
    extern int num_saved_generators;
    extern int num_cores;
    extern int num_permutations;
    extern int print_matrices;
#endif

}

