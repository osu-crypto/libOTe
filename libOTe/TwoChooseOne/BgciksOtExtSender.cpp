#include "libOTe/TwoChooseOne/BgciksOtExtSender.h"
#include "libOTe/DPF/BgiGenerator.h"
#include "libOTe/Tools/Tools.h"
#include "libOTe/TwoChooseOne/BgciksOtExtReceiver.h"
#include "bitpolymul2/bitpolymul.h"
namespace osuCrypto
{

    extern u64 numPartitions;
    extern u64 nScaler;
    u64 nextPrime(u64 n);

    void BgciksOtExtSender::genBase(u64 n, Channel & chl)
    {

        setTimePoint("sender.gen.start");

        mP = nextPrime(n);
        mN = roundUpTo(mP, 128);
        mN2 = nScaler * mN;


        mSizePer = (mN2 + numPartitions - 1) / numPartitions;
        auto groupSize = 8;
        auto depth = log2ceil((mSizePer + groupSize - 1) / groupSize) + 1;

        std::vector<std::vector<block>>
            k1(numPartitions), g1(numPartitions),
            k2(numPartitions), g2(numPartitions);

        PRNG prng(ZeroBlock);
        std::vector<u64> S(numPartitions);
        mDelta = prng.get();


        for (u64 i = 0; i < numPartitions; ++i)
        {
            S[i] = prng.get<u64>() % mSizePer;

            k1[i].resize(depth);
            k2[i].resize(depth);
            g1[i].resize(groupSize);
            g2[i].resize(groupSize);

            BgiGenerator::keyGen(S[i], mDelta, toBlock(i), k1[i], g1[i], k2[i], g2[i]);
        }

        mGen.init(k1, g1);

        setTimePoint("sender.gen.done");

    }



    //sigma = 0   Receiver
    //
    //    u_i is the choice bit
    //    v_i = w_i + u_i * x
    //
    //    ------------------------ -
    //    u' =   0000001000000000001000000000100000...00000,   u_i = 1 iff i \in S 
    //
    //    v' = r + (x . u') = DPF(k0)
    //       = r + (000000x00000000000x000000000x00000...00000)
    //
    //    u = u' * H             bit-vector * H. Mapping n'->n bits
    //    v = v' * H		   block-vector * H. Mapping n'->n block
    //
    //sigma = 1   Sender
    //
    //    x   is the delta
    //    w_i is the zero message
    //
    //    m_i0 = w_i
    //    m_i1 = w_i + x
    //
    //    ------------------------
    //    x
    //    r = DPF(k1)
    //
    //    w = r * H





    void BgciksOtExtSender::send(
        span<std::array<block, 2>>
        messages,
        PRNG & prng,
        Channel & chl)
    {
        setTimePoint("sender.expand.start");

        std::vector<block> r(mN2);

        for (u64 i = 0; i < r.size();)
        {
            auto blocks = mGen.yeild();
            auto min = std::min<u64>(r.size() - i, blocks.size());
            memcpy(r.data() + i, blocks.data(), min * sizeof(block));

            i += min;
        }

        setTimePoint("sender.expand.dpf");

        if (mN2 % 128) throw RTE_LOC;
        Matrix<block> rT(128, mN2 / 128, AllocType::Uninitialized);
        sse_transpose(r, rT);
        setTimePoint("sender.expand.transpose");

        //for (u64 i = 0; i < r.size(); i += 128)
        //{
        //    std::array<block, 128>& view = *(std::array<block, 128>*)(r.data() + i);

        //    sse_transpose128(view);
        //}


        auto type = MultType::QuasiCyclic;

        switch (type)
        {
        case osuCrypto::MultType::Naive:
            randMulNaive(rT, messages);
            break;
        case osuCrypto::MultType::QuasiCyclic:
            randMulQuasiCyclic(rT, messages);
            break;
        default:
            break;
        }
        //randMulNaive(rT, messages);


    }
    void BgciksOtExtSender::randMulNaive(Matrix<block>& rT, span<std::array<block, 2>>& messages)
    {

        std::vector<block> mtxColumn(rT.cols());

        PRNG pubPrng(ZeroBlock);

        for (u64 i = 0; i < messages.size(); ++i)
        {
            block& m0 = messages[i][0];
            block& m1 = messages[i][1];

            BitIterator iter((u8*)&m0, 0);

            mulRand(pubPrng, mtxColumn, rT, iter);

            m1 = m0 ^ mDelta;
        }

        setTimePoint("sender.expand.mul");
    }

    void bitShiftXor(span<block> dest, span<block> in, u8 bitShift)
    {


        if (bitShift > 127)
            throw RTE_LOC;
        if (u64(in.data()) % 16)
            throw RTE_LOC;

        if (bitShift >= 64)
        {
            bitShift -= 64;
            const int bitShift2 = 64 - bitShift;
            u8* inPtr = ((u8*)in.data()) + sizeof(u64);
            for (u64 i = 0; i < dest.size(); ++i, inPtr += sizeof(block))
            {
                block
                    b0 = _mm_loadu_si128((block*)inPtr),
                    b1 = _mm_load_si128((block*)(inPtr + sizeof(u64)));

                dest[i] = dest[i] ^ _mm_srli_epi64(b0, bitShift);
                dest[i] = dest[i] ^ _mm_slli_epi64(b1, bitShift2);
            }
        }
        else
        {
            const int bitShift2 = 64 - bitShift;
            u8* inPtr = (u8*)in.data();
            for (u64 i = 0; i < dest.size(); ++i, inPtr += sizeof(block))
            {
                block
                    b0 = _mm_load_si128((block*)inPtr),
                    b1 = _mm_loadu_si128((block*)(inPtr + sizeof(u64)));

                //std::cout << "b0  " << b0 << std::endl;
                //std::cout << "b0  " << b1 << std::endl;

                //std::cout << "b0' " << (b0 >> bitShift) << std::endl;
                //std::cout << "b0' " << (b1 << bitShift2) << std::endl;

                dest[i] = dest[i] ^ _mm_srli_epi64(b0, bitShift);
                dest[i] = dest[i] ^ _mm_slli_epi64(b1, bitShift2);
            }
        }
    }

    void modp(span<block> dest, span<block> in, u64 p)
    {
        auto pBlocks = (p + 127) / 128;
        auto pBytes = (p + 7) / 8;

        if (dest.size() < pBlocks)
            throw RTE_LOC;

        if (in.size() < pBlocks)
            throw RTE_LOC;

        auto count = (in.size() * 128 + p - 1) / p;

        memcpy(dest.data(), in.data(), pBytes);


        for (u64 i = 1; i < count; ++i)
        {
            auto idx = i * p;
            auto shift = idx & 127;

            auto in_i = span<block>(in.data() + (idx / 128), pBlocks);

            bitShiftXor(dest, in_i, shift);
        }

        auto offset = (p & 7);
        if (offset)
        {
            u8 mask = (1 << (8 - offset)) - 1;
            auto idx = p / 8;
            ((u8*)dest.data())[idx] &= mask;
        }

        auto rem = dest.size() * 16 - pBytes;
        if(rem)
            memset(((u8*)dest.data()) + pBytes, 0, rem);
    }

    void BgciksOtExtSender::randMulQuasiCyclic(Matrix<block>& rT, span<std::array<block, 2>>& messages)
    {
        auto nBlocks = mN / 128;
        auto n2Blocks = mN2 / 128;
        auto n64 = i64(nBlocks * 2);


        const u64 rows(128);
        if (rT.rows() != rows)
            throw RTE_LOC;

        if (rT.cols() != n2Blocks)
            throw RTE_LOC;


        std::vector<block> a(nBlocks);
        u64* a64ptr = (u64*)a.data();

        bpm::FFTPoly aPoly;
        bpm::FFTPoly bPoly;

        PRNG pubPrng(ZeroBlock);

        std::vector<bpm::FFTPoly> c(rows);

        for (u64 s = 0; s < nScaler; ++s)
        {
            pubPrng.get(a.data(), a.size());
            aPoly.encode({ a64ptr, n64 });

            for (u64 i = 0; i < rows; ++i)
            {
                //    auto ci = c[i];

                //    u64* c64ptr = (u64*)((s == 0) ? ci.data() : temp.data());
                u64* b64ptr = (u64*)(rT[i].data() + s * nBlocks);

                //bitpolymul_2_128(c64ptr, a64ptr, b64ptr, nBlocks * 2);
                bPoly.encode({ b64ptr, n64 });

                if (s)
                {
                    bPoly.multEq(aPoly);
                    c[i].addEq(bPoly);
                }
                else
                {
                    c[i].mult(aPoly, bPoly);
                }
            }
        }
        a = {};


        setTimePoint("sender.expand.mul");

        Matrix<block>cModP1(128, nBlocks, AllocType::Uninitialized);

        std::vector<u64> temp(c[0].mPoly.size() + 2), temp2(c[0].mPoly.size());

        auto pBlocks = (mP + 127) / 128;

        auto t64Ptr = temp.data();
        auto t128Ptr = (block*)temp.data();

        for (u64 i = 0; i < rows; ++i)
        {
            // decode c[i] and store it at t64Ptr
            c[i].decode({ t64Ptr, 2 * n64 }, temp2, true);

            // reduce s[i] mod (x^p - 1) and store it at cModP1[i]
            modp(cModP1[i], { t128Ptr, n64 }, mP);

            //memcpy(cModP1[i].data(), t64Ptr, nBlocks * sizeof(block));

            //u64 shift = 0;
            //bitShiftXor(
            //    { (block*)t64Ptr,  pBlocks },
            //    {(block*)t64Ptr + mP / 128,  pBlocks }, shift);
            //reduce()
            //TODO("do a real reduction mod (x^p-1)");
        }

        setTimePoint("sender.expand.decodeReduce");

        Matrix<block> view(mN, 1, AllocType::Uninitialized);
        sse_transpose(MatrixView<block>(cModP1), MatrixView<block>(view));

        for (u64 i = 0; i < messages.size(); ++i)
        {
            messages[i][0] = view(i, 0);
            messages[i][1] = view(i, 0) ^ mDelta;
        }

        setTimePoint("sender.expand.transposeXor");
    }
}

