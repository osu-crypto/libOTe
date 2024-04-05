#include "Pprf_Tests.h"

#include "libOTe/Tools/Pprf/RegularPprf.h"
#include "cryptoTools/Common/TestCollection.h"

#ifdef ENABLE_PPRF
#include "cryptoTools/Common/Log.h"
#include "Common.h"
#include <numeric>
using namespace osuCrypto;
using namespace tests_libOTe;


template<typename F, typename G, typename Ctx>
void Tools_Pprf_expandOne_test_impl(u64 domain, bool program)
{

    u64 depth = log2ceil(domain);
    auto pntCount = 8ull;
    PRNG prng(CCBlock);

    RegularPprfSender<F, G, Ctx> sender;
    RegularPprfReceiver<F, G, Ctx> recver;

    sender.configure(domain, pntCount);
    recver.configure(domain, pntCount);

    F value = prng.get();
    sender.setValue({ &value, 1 });

    auto numOTs = sender.baseOtCount();
    std::vector<std::array<block, 2>> sendOTs(numOTs);
    std::vector<block> recvOTs(numOTs);
    BitVector recvBits = recver.sampleChoiceBits(prng);


    prng.get(sendOTs.data(), sendOTs.size());
    for (u64 i = 0; i < numOTs; ++i)
    {
        recvOTs[i] = sendOTs[i][recvBits[i]];
    }
    sender.setBase(sendOTs);
    recver.setBase(recvOTs);


    block seed = CCBlock;

    auto sLevels = std::vector<span<AlignedArray<block, 8>>>{};
    auto rLevels = std::vector<span<AlignedArray<block, 8>>>{};
    auto sBuff = std::vector<u8>{};
    auto sSums = span<std::array<block, 2>>{};
    auto sLast = span<u8>{};

    //pprf::TreeAllocator mTreeAlloc;
    sLevels.resize(depth);
    rLevels.resize(depth);


    //mTreeAlloc.reserve(2, (1ull << depth) + 2);
    AlignedUnVector<block> sTree, rTree;

    pprf::allocateExpandTree(domain, sTree, sLevels, false);
    pprf::allocateExpandTree(domain, rTree, rLevels, false);
    using VecF = typename Ctx::template Vec<F>;
    VecF sLeafLevel(8ull * domain);
    VecF rLeafLevel(8ull * domain);
    u64 leafOffset = 0;

    Ctx ctx;
    pprf::allocateExpandBuffer<F, Ctx>(depth - 1, pntCount, program, sBuff, sSums, sLast, ctx);

    std::vector<u64> points(recver.mPntCount);
    recver.getPoints(points, PprfOutputFormat::ByLeafIndex);

    sender.expandOne(seed, 0, program, sLevels, sLeafLevel, leafOffset, sSums, sLast, ctx);
    recver.expandOne(0, program, rLevels, rLeafLevel, leafOffset, sSums, sLast, points, ctx);

    bool failed = false;
    for (u64 i = 0; i < pntCount; ++i)
    {
        // the index of the leaf node that is active.
        auto leafIdx = points[i];
        //std::cout << "active leaf idx = " << leafIdx << std::endl;
        for (u64 d = 1; d < depth; ++d)
        {
            //u64 width = std::min<u64>(domain, 1ull << d);
            auto width = divCeil(domain, 1ull << (depth - d));

            // The index of the active child node.
            auto activeChildIdx = leafIdx >> (depth - d);

            // The index of the active child node sibling.

            for (u64 j = 0; j < width; ++j)
            {
                //std::cout
                //    << " " << sLevels[d][j][i].get<u16>()[0]
                //    << " " << rLevels[d][j][i].get<u16>()[0]
                //    ;

                if (j == activeChildIdx)
                {
                    //std::cout << "*";
                    continue;
                }


                if (sLevels[d][j][i] != rLevels[d][j][i])
                {
                    //std::cout << " < ";
                    throw RTE_LOC;
                    failed = true;
                }

                //std::cout << ", ";
            }
            //std::cout << std::endl;
        }

        MatrixView<F> sLeaves(sLeafLevel.data(), sLeafLevel.size() / 8, 8);
        MatrixView<F> rLeaves(rLeafLevel.data(), rLeafLevel.size() / 8, 8);

        for (u64 j = 0; j < sLeaves.rows(); ++j)
        {
            if (j == leafIdx)
            {
                F exp;
                ctx.plus(exp, sLeaves(j, i), value);
                if (program && exp != rLeaves(j, i))
                {
                    std::cout << i << " exp " << ctx.str(exp) << " " << ctx.str(rLeaves(j, i)) << std::endl;
                    throw RTE_LOC;
                }
            }
            else
            {
                if (sLeaves(j, i) != rLeaves(j, i))
                {
                    std::cout << "j " << j << " i " << i << " sender " << ctx.str(sLeaves(j, i)) << " recver " << ctx.str(rLeaves(j, i)) << std::endl;
                    throw RTE_LOC;
                }
            }
        }
    }

    if (failed)
        throw RTE_LOC;
}

void Tools_Pprf_expandOne_test(const oc::CLP& cmd)
{
#if defined(ENABLE_SILENTOT) || defined(ENABLE_SILENT_VOLE)


    for (u64 domain : { 2, 128, 4522}) for (bool program : {true, false})
    {

        Tools_Pprf_expandOne_test_impl<u64, u64, CoeffCtxInteger>(domain, program);
        Tools_Pprf_expandOne_test_impl<block, block, CoeffCtxGF128>(domain, program);
        Tools_Pprf_expandOne_test_impl<std::array<u32,11>, u32, CoeffCtxArray<u32, 11>>(domain, program);

    }

#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}


template<typename F, typename G, typename Ctx>
void Tools_Pprf_test_impl(
    u64 domain, 
    u64 numPoints, 
    bool program, 
    PprfOutputFormat  format,
    bool eagerSend,
    bool verbose)
{

    auto threads = 1;
    PRNG prng(CCBlock);
    using Vec = typename Ctx::template Vec<F>;

    auto sockets = cp::LocalAsyncSocket::makePair();

    RegularPprfSender<F, G, Ctx> sender;
    RegularPprfReceiver<F, G, Ctx> recver;
    Vec delta;
    Ctx ctx;
    auto seed = prng.get<block>();
    ctx.resize(delta, numPoints * program);
    for (u64 i = 0; i < delta.size(); ++i)
        ctx.fromBlock(delta[i], seed);

    sender.configure(domain, numPoints);
    recver.configure(domain, numPoints);

    auto numOTs = sender.baseOtCount();
    std::vector<std::array<block, 2>> sendOTs(numOTs);
    std::vector<block> recvOTs(numOTs);
    BitVector recvBits = recver.sampleChoiceBits(prng);

    prng.get(sendOTs.data(), sendOTs.size());
    for (u64 i = 0; i < numOTs; ++i)
        recvOTs[i] = sendOTs[i][recvBits[i]];

    sender.setBase(sendOTs);
    recver.setBase(recvOTs);

    Vec a(numPoints * domain), a2;
    Vec b(numPoints * domain), b2;
    if (format == PprfOutputFormat::Callback)
    {
        a2 = std::move(a);
        b2 = std::move(b);
        a = {};
        b = {};
        sender.mOutputFn = [&](u64 treeIdx, Vec& data){
            auto offset = treeIdx * domain;
            std::copy(data.begin(), data.end(), b2.begin() + offset);
        };
        recver.mOutputFn = [&](u64 treeIdx, Vec& data) {
            auto offset = treeIdx * domain;
            std::copy(data.begin(), data.end(), a2.begin() + offset);
        };
    }

    std::vector<u64> points(numPoints);
    recver.getPoints(points, format);
    sender.mEagerSend = eagerSend;
    recver.mEagerSend = eagerSend;

    // a = b + points * delta
    auto p0 = sender.expand(sockets[0], delta, prng.get(), b, format, program, threads);
    auto p1 = recver.expand(sockets[1], a, format, program, threads);


    try
    {
        eval(p0, p1);
    }
    catch (std::exception& e)
    {
        sockets[0].close();
        sockets[1].close();
        macoro::sync_wait(macoro::when_all_ready(
            sockets[0].flush(),
            sockets[1].flush()
        ));
        throw;
    }

    if (format == PprfOutputFormat::Callback)
    {
        a = std::move(a2);
        b = std::move(b2);
    }

    switch (format)
    {
    case osuCrypto::PprfOutputFormat::ByLeafIndex:
    case osuCrypto::PprfOutputFormat::ByTreeIndex:
    {

        bool failed = false;
        for (u64 j = 0; j < numPoints; ++j)
        {
            for (u64 i = 0; i < domain; ++i)
            {
                u64 idx = format == osuCrypto::PprfOutputFormat::ByTreeIndex ?
                    j * domain + i :
                    i * numPoints + j;
    
                F exp;

                if (points[j] == i)
                {
                    if (program)
                        ctx.plus(exp, b[idx], delta[j]);
                    else
                        ctx.zero(&exp, &exp + 1);
                }
                else
                    exp = b[idx];

                if (program && exp != a[idx])
                {
                    failed = true;

                    if (verbose)
                        std::cout << Color::Red;
                }
                if (verbose)
                {
                    std::cout << "r[" << j << "][" << i << "] " << exp << " " << ctx.str(a[idx]);
                    if (points[j] == i)
                        std::cout << " < ";

                    std::cout << std::endl << Color::Default;
                }
            }
            if (verbose)
                std::cout << "\n";
        }

        if (failed)
            throw RTE_LOC;

        break;
    }
    case osuCrypto::PprfOutputFormat::Interleaved:
    case osuCrypto::PprfOutputFormat::Callback:
    {

        bool failed = false;
        std::vector<std::size_t> index(points.size());
        std::iota(index.begin(), index.end(), 0);
        std::sort(index.begin(), index.end(),
            [&](std::size_t i, std::size_t j) { return points[i] < points[j]; });

        auto iIter = index.begin();
        auto leafIdx = points[*iIter];
        F deltaVal;
        ctx.zero(&deltaVal, &deltaVal + 1);
        if(program)
            deltaVal = delta[*iIter];
        
        ++iIter;
        for (u64 j = 0; j < a.size(); ++j)
        {
            F exp, act;

            // a = b + points * delta

            // act = a - b 
            //     = point * delta
            ctx.minus(act, a[j], b[j]);
            ctx.zero(&exp, &exp + 1);
            bool active = false;
            if (j == leafIdx)
            {
                active = true;
                if (program)
                    ctx.copy(exp, deltaVal);
                else
                    ctx.minus(exp, exp, b[j]);
            }

            if (exp != act)
            {
                failed = true;
                if (verbose)
                    std::cout << Color::Red;
            }

            if (verbose)
            {
                std::cout << j << " exp " << ctx.str(exp) << " " << ctx.str(act)
                    << " a " << ctx.str(a[j]) << " b " << ctx.str(b[j]);

                if (active)
                    std::cout << " < " << deltaVal;

                std::cout << std::endl << Color::Default;
            }

            if (j == leafIdx)
            {
                if (iIter != index.end())
                {
                    leafIdx = points[*iIter];
                    if(program)
                        deltaVal = delta[*iIter];
                    ++iIter;
                }
            }
        }

        if (failed)
            throw RTE_LOC;
        break;
    }
    default:
        break;
    }


}

void Tools_Pprf_inter_test(const CLP& cmd)
{
    auto f = PprfOutputFormat::Interleaved;
    auto v = cmd.isSet("v");
    for (auto d : { 32,3242 }) for (auto n : { 8, 128 }) for (auto p : { true, false }) for (auto e : { true, false })
    {
        Tools_Pprf_test_impl<u64, u64, CoeffCtxInteger>(d, n, p, f, e, v);
        Tools_Pprf_test_impl<block, block, CoeffCtxInteger>(d, n, p, f, e, v);
    }
}



void Tools_Pprf_ByLeafIndex_test(const CLP& cmd)
{
#if defined(ENABLE_SILENTOT) || defined(ENABLE_SILENT_VOLE)

    auto f = PprfOutputFormat::ByLeafIndex;
    auto v = cmd.isSet("v");
    for (auto d : { 32,3242 }) for (auto n : { 8, 128 }) for (auto p : { true/*, false */}) for (auto e : { true/*, false */})
    {
        Tools_Pprf_test_impl<u64, u64, CoeffCtxInteger>(d, n, p, f, e, v);
        Tools_Pprf_test_impl<block, block, CoeffCtxInteger>(d, n, p, f, e, v);
    }
#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}



void Tools_Pprf_ByTreeIndex_test(const oc::CLP& cmd)
{
#if defined(ENABLE_SILENTOT) || defined(ENABLE_SILENT_VOLE)


    auto f = PprfOutputFormat::ByTreeIndex;
    auto v = cmd.isSet("v");
    for (auto d : { 32,3242 }) for (auto n : { 8, 19}) for (auto p : { true/*, false*/ })
    {
        Tools_Pprf_test_impl<u64, u64, CoeffCtxInteger>(d, n, p, f, false, v);
        Tools_Pprf_test_impl<block, block, CoeffCtxInteger>(d, n, p, f, false, v);
    }

#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}



void Tools_Pprf_callback_test(const oc::CLP& cmd)
{
#if defined(ENABLE_SILENTOT) || defined(ENABLE_SILENT_VOLE)

    auto f = PprfOutputFormat::Callback;
    auto v = cmd.isSet("v");
    for (auto d : { 32,3242 }) for (auto n : { 8, 128 }) for (auto p : { true/*, false */})
    {
        Tools_Pprf_test_impl<u64, u64, CoeffCtxInteger>(d, n, p, f, false, v);
        Tools_Pprf_test_impl<block, block, CoeffCtxInteger>(d, n, p, f, false, v);
    }
#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}
#else


namespace {
    void throwDisabled()
    {
        throw oc::UnitTestSkipped(
            "ENABLE_PPRF not defined. "
        );
    }
}

void Tools_Pprf_expandOne_test(const oc::CLP& cmd) { throwDisabled(); }
void Tools_Pprf_inter_test(const oc::CLP& cmd) { throwDisabled(); }
void Tools_Pprf_ByLeafIndex_test(const oc::CLP& cmd) { throwDisabled(); }
void Tools_Pprf_ByTreeIndex_test(const oc::CLP& cmd) { throwDisabled(); }
void Tools_Pprf_callback_test(const oc::CLP& cmd) { throwDisabled(); }

#endif
