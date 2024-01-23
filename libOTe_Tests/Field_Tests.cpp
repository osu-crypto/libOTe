

#include "libOTe/Tools/Field/FP.h"
#include "libOTe/Tools/Field/GF128.h"
#include "libOTe/Tools/NTT/Poly.h"
#include "Field_Tests.h"
using namespace osuCrypto;
#include <vector>

namespace tests_libOTe
{

    void Field_F7681_Test()
    {
        std::vector<u8> lower;

        u64 n = 6;
        for (u64 i = 1; i < 6780; ++i)
        {
            if (F7681(i).pow(n) == 1 && 
                F7681(i).pow(2) != 1 && 
                F7681(i).pow(3) != 1)
            {
                std::cout << i << std::endl;


            }
        }
        std::cout << "---------------" << std::endl;

        PRNG prng(AllOneBlock);
        for (u64 i = 0; i < 10; ++i)
        {
            auto unity = primRootOfUnity<F7681>(n, prng);
            std::cout << unity.mVal << std::endl;
        }
        //F7681 fourthRootUnity1 = 3383;
        //F7681 fourthRootUnity2 = 4298;

        //auto unit1 = fourthRootUnity1.pow(4);
        //if (unit1 != 1)
        //    throw RTE_LOC;
        //if (fourthRootUnity1.pow(4) != 1)
        //    throw RTE_LOC;

    }

    void Field_F12289_Test()
    {
        u64 n = 512;

        F12289 s = 1321;
        F12289 w = 3;


        auto ss = s * s;
        std::cout << "s " << ss.mVal << std::endl;

        for (u64 i = 1; i < 6780; ++i)
        {
            if (F12289(i).pow(n * 2) == 1 &&
                F12289(i).pow(n) != 1)
            {
                std::cout << i << std::endl;


            }
        }

        PRNG prng(AllOneBlock);

        for (u64 i = 0; i < 10; ++i)
        {
            auto unity = primRootOfUnity<F12289>(n, prng);
            std::cout << unity.mVal << std::endl;
        }
    }


    void Field_GF128_Test()
    {
        GF128 g;
    }

}