#include "RingLpnTriple.h"


namespace osuCrypto
{


#ifdef ENABLE_SSE

    OC_FORCEINLINE block shuffle_epi8(const block& a, const block& b)
    {
        return _mm_shuffle_epi8(a, b);
    }

    template<int s>
    OC_FORCEINLINE block slli_epi16(const block& v)
    {
        return _mm_slli_epi16(v, s);
    }

    OC_FORCEINLINE  int movemask_epi8(const block v)
    {
        return _mm_movemask_epi8(v);
    }
#else
    OC_FORCEINLINE block shuffle_epi8(const block& a, const block& b)
    {
        // _mm_shuffle_epi8(a, b): 
        //     FOR j := 0 to 15
        //         i: = j * 8
        //         IF b[i + 7] == 1
        //             dst[i + 7:i] : = 0
        //         ELSE
        //             index[3:0] : = b[i + 3:i]
        //             dst[i + 7:i] : = a[index * 8 + 7:index * 8]
        //         FI
        //     ENDFOR

        block dst;
        for (u64 i = 0; i < 16; ++i)
        {
            auto bi = b.get<i8>(i);

            // 0 if bi < 0. otherwise 11111111
            u8 mask = ~(-i8(bi >> 7));
            u8 idx = bi & 15;

            dst.set<i8>(i, a.get<i8>(idx) & mask);
        }
        return dst;
    }

    template<int s>
    OC_FORCEINLINE block slli_epi16(const block& v)
    {
        block r;
        auto rr = (i16*)&r;
        auto vv = (const i16*)&v;
        for (u64 i = 0; i < 8; ++i)
            rr[i] = vv[i] << s;
        return r;
    }

    OC_FORCEINLINE int movemask_epi8(const block v)
    {
        // extract all the of MSBs if each byte.
        u64 mask = 1;
        int r = 0;
        for (i64 i = 0; i < 16; ++i)
        {
            r |= (v.get<u8>(0) >> i) & mask;
            mask <<= 1;
        }
        return r;
    }

#endif

    // the LSB of A is the choice bit of the OT.
    void convertToOle(
        span<oc::block> A,
		BitVector& choice,
        span<oc::block> add,
        span<oc::block> mult)
    {
        auto aIter16 = (u16*)add.data();
        //auto bIter8 = (u8*)mult.data();

        if (add.size() * 128 != A.size())
            throw RTE_LOC;
        if (mult.size() * 128 != A.size())
            throw RTE_LOC;
        if (choice.size() != A.size())
            throw RTE_LOC;

        memcpy(mult.data(), choice.data(), choice.sizeBytes());

        auto shuffle = std::array<block, 16>{};
        memset(shuffle.data(), 1 << 7, sizeof(*shuffle.data()) * shuffle.size());
        for (u64 i = 0; i < 16; ++i)
            shuffle[i].set<u8>(i, 0);

        auto OneBlock = block(1);
        auto AllOneBlock = block(~0ull, ~0ull);
        block mask = OneBlock ^ AllOneBlock;

        auto m = &A[0];

        for (u64 i = 0; i < A.size(); i += 16)
        {
            // _mm_shuffle_epi8(a, b): 
            //     FOR j := 0 to 15
            //         i: = j * 8
            //         IF b[i + 7] == 1
            //             dst[i + 7:i] : = 0
            //         ELSE
            //             index[3:0] : = b[i + 3:i]
            //             dst[i + 7:i] : = a[index * 8 + 7:index * 8]
            //         FI
            //     ENDFOR

            // _mm_sll_epi16 : shifts 16 bit works left
            // _mm_movemask_epi8: packs together the MSG
            
            block a00 = shuffle_epi8(m[0], shuffle[0]);
            block a01 = shuffle_epi8(m[1], shuffle[1]);
            block a02 = shuffle_epi8(m[2], shuffle[2]);
            block a03 = shuffle_epi8(m[3], shuffle[3]);
            block a04 = shuffle_epi8(m[4], shuffle[4]);
            block a05 = shuffle_epi8(m[5], shuffle[5]);
            block a06 = shuffle_epi8(m[6], shuffle[6]);
            block a07 = shuffle_epi8(m[7], shuffle[7]);
            block a08 = shuffle_epi8(m[8], shuffle[8]);
            block a09 = shuffle_epi8(m[9], shuffle[9]);
            block a10 = shuffle_epi8(m[10], shuffle[10]);
            block a11 = shuffle_epi8(m[11], shuffle[11]);
            block a12 = shuffle_epi8(m[12], shuffle[12]);
            block a13 = shuffle_epi8(m[13], shuffle[13]);
            block a14 = shuffle_epi8(m[14], shuffle[14]);
            block a15 = shuffle_epi8(m[15], shuffle[15]);

            a00 = a00 ^ a08;
            a01 = a01 ^ a09;
            a02 = a02 ^ a10;
            a03 = a03 ^ a11;
            a04 = a04 ^ a12;
            a05 = a05 ^ a13;
            a06 = a06 ^ a14;
            a07 = a07 ^ a15;

            a00 = a00 ^ a04;
            a01 = a01 ^ a05;
            a02 = a02 ^ a06;
            a03 = a03 ^ a07;

            a00 = a00 ^ a02;
            a01 = a01 ^ a03;

            a00 = a00 ^ a01;

            a00 = slli_epi16<7>(a00);

            u16 ap = movemask_epi8(a00);

            *aIter16++ = ap;
            m += 16;

        }
    }


    void convertToOle(
        span<std::array<oc::block,2>> B,
        span<oc::block> add,
        span<oc::block> mult)
    {

        auto bIter16 = (u16*)add.data();
        auto aIter16 = (u16*)mult.data();

        if (add.size() * 128 != B.size())
            throw RTE_LOC;
        if (mult.size() * 128 != B.size())
            throw RTE_LOC;
        using block = oc::block;

        auto shuffle = std::array<block, 16>{};
        memset(shuffle.data(), 1 << 7, sizeof(*shuffle.data()) * shuffle.size());
        for (u64 i = 0; i < 16; ++i)
            shuffle[i].set<u8>(i, 0);

        std::array<block, 16> sendMsg;
        auto m = B.data();

        auto OneBlock = block(1);
        auto AllOneBlock = block(~0ull, ~0ull);

        for (u64 i = 0; i < B.size(); i += 16)
        {
            auto s = sendMsg.data();

            for (u64 j = 0; j < 2; ++j)
            {
                s[0] = m[0][0];
                s[1] = m[1][0];
                s[2] = m[2][0];
                s[3] = m[3][0];
                s[4] = m[4][0];
                s[5] = m[5][0];
                s[6] = m[6][0];
                s[7] = m[7][0];
                s += 8;
                m += 8;
            }


            block a00 = shuffle_epi8(sendMsg[0], shuffle[0]);
            block a01 = shuffle_epi8(sendMsg[1], shuffle[1]);
            block a02 = shuffle_epi8(sendMsg[2], shuffle[2]);
            block a03 = shuffle_epi8(sendMsg[3], shuffle[3]);
            block a04 = shuffle_epi8(sendMsg[4], shuffle[4]);
            block a05 = shuffle_epi8(sendMsg[5], shuffle[5]);
            block a06 = shuffle_epi8(sendMsg[6], shuffle[6]);
            block a07 = shuffle_epi8(sendMsg[7], shuffle[7]);
            block a08 = shuffle_epi8(sendMsg[8], shuffle[8]);
            block a09 = shuffle_epi8(sendMsg[9], shuffle[9]);
            block a10 = shuffle_epi8(sendMsg[10], shuffle[10]);
            block a11 = shuffle_epi8(sendMsg[11], shuffle[11]);
            block a12 = shuffle_epi8(sendMsg[12], shuffle[12]);
            block a13 = shuffle_epi8(sendMsg[13], shuffle[13]);
            block a14 = shuffle_epi8(sendMsg[14], shuffle[14]);
            block a15 = shuffle_epi8(sendMsg[15], shuffle[15]);

            s = sendMsg.data();
            m -= 16;
            for (u64 j = 0; j < 2; ++j)
            {
                s[0] = m[0][1];
                s[1] = m[1][1];
                s[2] = m[2][1];
                s[3] = m[3][1];
                s[4] = m[4][1];
                s[5] = m[5][1];
                s[6] = m[6][1];
                s[7] = m[7][1];

                s += 8;
                m += 8;
            }

            block b00 = shuffle_epi8(sendMsg[0], shuffle[0]);
            block b01 = shuffle_epi8(sendMsg[1], shuffle[1]);
            block b02 = shuffle_epi8(sendMsg[2], shuffle[2]);
            block b03 = shuffle_epi8(sendMsg[3], shuffle[3]);
            block b04 = shuffle_epi8(sendMsg[4], shuffle[4]);
            block b05 = shuffle_epi8(sendMsg[5], shuffle[5]);
            block b06 = shuffle_epi8(sendMsg[6], shuffle[6]);
            block b07 = shuffle_epi8(sendMsg[7], shuffle[7]);
            block b08 = shuffle_epi8(sendMsg[8], shuffle[8]);
            block b09 = shuffle_epi8(sendMsg[9], shuffle[9]);
            block b10 = shuffle_epi8(sendMsg[10], shuffle[10]);
            block b11 = shuffle_epi8(sendMsg[11], shuffle[11]);
            block b12 = shuffle_epi8(sendMsg[12], shuffle[12]);
            block b13 = shuffle_epi8(sendMsg[13], shuffle[13]);
            block b14 = shuffle_epi8(sendMsg[14], shuffle[14]);
            block b15 = shuffle_epi8(sendMsg[15], shuffle[15]);

            a00 = a00 ^ a08;
            a01 = a01 ^ a09;
            a02 = a02 ^ a10;
            a03 = a03 ^ a11;
            a04 = a04 ^ a12;
            a05 = a05 ^ a13;
            a06 = a06 ^ a14;
            a07 = a07 ^ a15;

            b00 = b00 ^ b08;
            b01 = b01 ^ b09;
            b02 = b02 ^ b10;
            b03 = b03 ^ b11;
            b04 = b04 ^ b12;
            b05 = b05 ^ b13;
            b06 = b06 ^ b14;
            b07 = b07 ^ b15;

            a00 = a00 ^ a04;
            a01 = a01 ^ a05;
            a02 = a02 ^ a06;
            a03 = a03 ^ a07;

            b00 = b00 ^ b04;
            b01 = b01 ^ b05;
            b02 = b02 ^ b06;
            b03 = b03 ^ b07;

            a00 = a00 ^ a02;
            a01 = a01 ^ a03;

            b00 = b00 ^ b02;
            b01 = b01 ^ b03;

            a00 = a00 ^ a01;
            b00 = b00 ^ b01;

            a00 = slli_epi16<7>(a00);
            b00 = slli_epi16<7>(b00);

            u16 ap = movemask_epi8(a00);
            u16 bp = movemask_epi8(b00);

            assert(aIter16 < (u16*)(mult.data() + mult.size()));
            assert(bIter16 < (u16*)(add.data() + add.size()));

            *aIter16++ = ap ^ bp;
            *bIter16++ = ap;
        }
    }

}