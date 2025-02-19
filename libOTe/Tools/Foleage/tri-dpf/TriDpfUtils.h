#pragma once


#include <stdint.h>
#include <stdio.h>
#include "libOTe/Tools/Foleage/FoleageUtils.h"
#include "cryptoTools/Common/BitIterator.h"

namespace osuCrypto
{

    static inline block flip_lsb(block input)
    {
        return input ^ block(0, 1);
    }

    static inline block get_lsb(block input)
    {
        return block::allSame(-(input.get<u8>(0) & 1));
    }

    static inline int get_trit(uint64_t x, int size, int t)
    {
        std::vector<int> ternary(size);
        for (int i = 0; i < size; i++)
        {
            ternary[i] = x % 3;
            x /= 3;
        }

        return ternary[t];
    }

    static inline int get_bit(block x, int size, int b)
    {
        return *oc::BitIterator((u8*)&x, (size - b));
        //return ((x) >> (size - b)) & 1;
    }

    //static void printBytes(void* p, int num)
    //{
    //    unsigned char* c = (unsigned char*)p;
    //    for (int i = 0; i < num; i++)
    //    {
    //        printf("%02x", c[i]);
    //    }
    //    printf("\n");
    //}

    //// Compute base^exp without the floating-point precision
    //// errors of the built-in pow function.
    //static inline int ipow(int base, int exp)
    //{
    //    int result = 1;
    //    while (1)
    //    {
    //        if (exp & 1)
    //            result *= base;
    //        exp >>= 1;
    //        if (!exp)
    //            break;
    //        base *= base;
    //    }

    //    return result;
    //}

}