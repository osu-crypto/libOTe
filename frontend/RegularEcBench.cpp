#include "RegularEcBench.h"

#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "libOTe/TwoChooseOne/ConfigureCode.h"
#include "libOTe/Tools/CoeffCtx.h"
#include "libOTe/Tools/ExConvCode/RegularEcCode.h"
#include "libOTe/Tools/ExConvCode/RegularEcFieldCode.h"
#include "libOTe/Tools/ExConvCode/RegularEcStreamingFieldCode.h"
#include "libOTe/Tools/Field/Fp.h"
#include "libOTe/Tools/Field/FVec.h"
#include "libOTe/Tools/Field/Goldilocks.h"
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

namespace osuCrypto
{
    namespace
    {
        using Clock = std::chrono::steady_clock;

        using Fp127 = Fp<127, u8, u16>;

        template<u64 LeftDegree, u64 Memory, typename Code>
        std::vector<Fp127> materializeFieldGenerator(
            const Code& code, CoeffCtxFp ctx)
        {
            const u64 rows = code.mMessageSize;
            const u64 columns = code.mCodeSize;
            std::vector<Fp127> matrix(rows * columns, Fp127::zero());
            for (u64 row = 0; row != rows; ++row)
            {
                Fp127* word = matrix.data() + row * columns;
                for (u64 region = 0; region != LeftDegree; ++region)
                {
                    const u64 right = code.rightAt(region, row);
                    word[right] += code.edgeLabel(region, row, ctx);
                }
                for (u64 time = 0; time != columns; ++time)
                {
                    for (u64 lag = 1; lag <= Memory && lag <= time; ++lag)
                    {
                        word[time] +=
                            code.feedbackCoefficient(time, lag, ctx) *
                            word[time - lag];
                    }
                }
            }
            return matrix;
        }

        u64 fieldMatrixRank(
            std::vector<Fp127> matrix, u64 rows, u64 columns)
        {
            u64 rank = 0;
            for (u64 column = 0; column != columns && rank != rows; ++column)
            {
                u64 pivot = rank;
                while (pivot != rows &&
                    matrix[pivot * columns + column] == Fp127::zero())
                    ++pivot;
                if (pivot == rows)
                    continue;
                for (u64 index = column; index != columns; ++index)
                    std::swap(
                        matrix[rank * columns + index],
                        matrix[pivot * columns + index]);

                const Fp127 inverse =
                    matrix[rank * columns + column].inverse();
                for (u64 index = column; index != columns; ++index)
                    matrix[rank * columns + index] *= inverse;
                for (u64 row = rank + 1; row != rows; ++row)
                {
                    const Fp127 factor = matrix[row * columns + column];
                    if (factor == Fp127::zero())
                        continue;
                    for (u64 index = column; index != columns; ++index)
                        matrix[row * columns + index] -=
                            factor * matrix[rank * columns + index];
                }
                ++rank;
            }
            return rank;
        }

        std::pair<u64, u64> fieldRowAndPairWeight(
            const std::vector<Fp127>& matrix, u64 rows, u64 columns)
        {
            u64 minimumRow = columns + 1;
            for (u64 row = 0; row != rows; ++row)
            {
                u64 weight = 0;
                const Fp127* word = matrix.data() + row * columns;
                for (u64 column = 0; column != columns; ++column)
                    weight += word[column] != Fp127::zero();
                minimumRow = std::min(minimumRow, weight);
            }

            std::array<u8, 127> inverses{};
            for (u64 value = 1; value != inverses.size(); ++value)
                inverses[value] = Fp127(value).inverse().mVal;

            u64 minimumPair = columns + 1;
            for (u64 first = 0; first != rows; ++first)
            {
                const Fp127* lhs = matrix.data() + first * columns;
                for (u64 second = first + 1; second != rows; ++second)
                {
                    const Fp127* rhs = matrix.data() + second * columns;
                    std::array<u32, 127> cancellations{};
                    u64 unionWeight = 0;
                    for (u64 column = 0; column != columns; ++column)
                    {
                        const u64 lhsValue = lhs[column].mVal;
                        const u64 rhsValue = rhs[column].mVal;
                        unionWeight += (lhsValue | rhsValue) != 0;
                        if (lhsValue && rhsValue)
                        {
                            const u64 ratio =
                                ((127 - lhsValue) * inverses[rhsValue]) % 127;
                            ++cancellations[ratio];
                        }
                    }
                    const u64 bestCancellation = *std::max_element(
                        cancellations.begin() + 1, cancellations.end());
                    minimumPair = std::min(
                        minimumPair, unionWeight - bestCancellation);
                }
            }
            return { minimumRow, minimumPair };
        }

        template<typename Code>
        std::tuple<u64, u64, u64> auditFieldCode(
            Code& code, u64 k, u64 n, block seed, CoeffCtxFp ctx)
        {
            code.config(k, n, seed, ctx);
            auto matrix = materializeFieldGenerator<26, 4>(code, ctx);
            const u64 rank = fieldMatrixRank(matrix, k, n);
            const auto [rowWeight, pairWeight] =
                fieldRowAndPairWeight(matrix, k, n);
            return { rank, rowWeight, pairWeight };
        }

        void fieldGeneratorAudit(u64 regionSize, u64 seeds)
        {
            constexpr u64 leftDegree = 26;
            constexpr u64 rightDegree = 13;
            constexpr u64 memory = 4;
            const u64 k = rightDegree * regionSize;
            const u64 n = leftDegree * regionSize;
            CoeffCtxFp ctx;
            std::cout << "exact-libOTe F127 " << leftDegree << '/'
                << rightDegree << "/m" << memory
                << " region=" << regionSize << " seeds=" << seeds << '\n';
            for (u64 seedIndex = 0; seedIndex != seeds; ++seedIndex)
            {
                const block seed(seedIndex, ~seedIndex);
                RegularEcFieldCode<leftDegree, memory, Fp127> reference;
                RegularEcStreamingFieldCode<leftDegree, memory, Fp127> streaming;
                const auto [referenceRank, referenceRow, referencePair] =
                    auditFieldCode(reference, k, n, seed, ctx);
                const auto [streamingRank, streamingRow, streamingPair] =
                    auditFieldCode(streaming, k, n, seed, ctx);
                std::cout << "seed=" << seedIndex
                    << " reference(rank=" << referenceRank
                    << ",row=" << referenceRow
                    << ",pair=" << referencePair << ')'
                    << " streaming(rank=" << streamingRank
                    << ",row=" << streamingRow
                    << ",pair=" << streamingPair << ")\n";
            }
        }

        template<u64 LeftDegree, u64 RightDegree, u64 Memory>
        void binaryBench(u64 n, u64 repetitions)
        {
            const u64 k = RightDegree * (n / LeftDegree);
            RegularEcCode<LeftDegree, Memory> code;

            const auto configBegin = Clock::now();
            code.config(k, n, block(0x1234, 0x5678));
            const auto configEnd = Clock::now();

            std::vector<block> source(n), input(n), output(k);
            std::vector<u8> bitSource(n), bitInput(n), bitOutput(k);
            PRNG prng(block(0x9abc, 0xdef0));
            prng.get(source.data(), source.size());
            prng.get(bitSource.data(), bitSource.size());

            double bestSeconds = std::numeric_limits<double>::infinity();
            double bestConvolution = std::numeric_limits<double>::infinity();
            double bestExpander = std::numeric_limits<double>::infinity();
            for (u64 repetition = 0; repetition != repetitions; ++repetition)
            {
                std::copy(source.begin(), source.end(), input.begin());
                const auto begin = Clock::now();
                code.template dualConvolve<block>(input, CoeffCtxGF2{});
                const auto middle = Clock::now();
                code.template dualExpand<block>(input, output, CoeffCtxGF2{});
                const auto end = Clock::now();
                bestSeconds = std::min(bestSeconds,
                    std::chrono::duration<double>(end - begin).count());
                bestConvolution = std::min(bestConvolution,
                    std::chrono::duration<double>(middle - begin).count());
                bestExpander = std::min(bestExpander,
                    std::chrono::duration<double>(end - middle).count());
            }

            double bestPairSeconds = std::numeric_limits<double>::infinity();
            for (u64 repetition = 0; repetition != repetitions; ++repetition)
            {
                std::copy(source.begin(), source.end(), input.begin());
                std::copy(bitSource.begin(), bitSource.end(), bitInput.begin());
                const auto begin = Clock::now();
                code.template dualEncode2<block, u8>(
                    input, output, bitInput, bitOutput, CoeffCtxGF2{});
                const auto end = Clock::now();
                bestPairSeconds = std::min(bestPairSeconds,
                    std::chrono::duration<double>(end - begin).count());
            }

            const double configSeconds =
                std::chrono::duration<double>(configEnd - configBegin).count();
            const double inputGiB = static_cast<double>(n * sizeof(block)) /
                static_cast<double>(u64{ 1 } << 30);
            const double tableMiB = static_cast<double>(
                k * (LeftDegree - 1) * sizeof(u32) +
                n * ((Memory - 1 + 7) / 8)) /
                static_cast<double>(u64{ 1 } << 20);

            std::cout << "F2 " << LeftDegree << '/' << RightDegree
                << "/m" << Memory << "  k=" << k << " n=" << n
                << "  config=" << std::fixed << std::setprecision(3)
                << configSeconds << " s  tables=" << std::setprecision(1)
                << tableMiB << " MiB  encode=" << std::setprecision(3)
                << bestSeconds << " s (conv " << bestConvolution
                << ", expand " << bestExpander << ")  input="
                << std::setprecision(2) << inputGiB / bestSeconds
                << " GiB/s  pair=" << std::setprecision(3)
                << bestPairSeconds << " s\n";
        }

        template<u64 LeftDegree, u64 RightDegree, u64 Memory,
            bool Reference>
        void fp31Bench(u64 n, u64 repetitions)
        {
            using F = Fp31;
            const u64 k = RightDegree * (n / LeftDegree);
            CoeffCtxFp ctx;
            using Code = std::conditional_t<
                Reference,
                RegularEcFieldCode<LeftDegree, Memory, F>,
                RegularEcStreamingFieldCode<LeftDegree, Memory, F>>;
            Code code;

            const auto configBegin = Clock::now();
            code.config(k, n, block(0x1234, 0x5678), ctx);
            const auto configEnd = Clock::now();

            std::vector<F> source(n), input(n), output(k);
            PRNG prng(block(0x9abc, 0xdef0));
            for (auto& value : source)
                ctx.fromBlock(value, prng.get<block>());

            double bestSeconds = std::numeric_limits<double>::infinity();
            double bestConvolution = std::numeric_limits<double>::infinity();
            double bestExpander = std::numeric_limits<double>::infinity();
            for (u64 repetition = 0; repetition != repetitions; ++repetition)
            {
                std::copy(source.begin(), source.end(), input.begin());
                const auto begin = Clock::now();
                code.template dualConvolve<F>(input, ctx);
                const auto middle = Clock::now();
                code.template dualExpand<F>(input, output, ctx);
                const auto end = Clock::now();
                bestSeconds = std::min(bestSeconds,
                    std::chrono::duration<double>(end - begin).count());
                bestConvolution = std::min(bestConvolution,
                    std::chrono::duration<double>(middle - begin).count());
                bestExpander = std::min(bestExpander,
                    std::chrono::duration<double>(end - middle).count());
            }

            const double configSeconds =
                std::chrono::duration<double>(configEnd - configBegin).count();
            const double scheduleKiB = static_cast<double>(code.scheduleBytes()) /
                static_cast<double>(u64{ 1 } << 10);

            std::cout << "Fp31 "
                << (Reference ? "reference " : "streaming-heuristic ")
                << LeftDegree << '/' << RightDegree
                << "/m" << Memory << "  k=" << k << " n=" << n
                << "  config=" << std::fixed << std::setprecision(3)
                << configSeconds << " s  schedule=" << std::setprecision(1)
                << scheduleKiB << " KiB  encode=" << std::setprecision(3)
                << bestSeconds << " s (conv " << bestConvolution
                << ", expand " << bestExpander << ")\n";
        }

        template<bool Reference>
        void fp31ProfileBench(
            const std::string& profile, u64 repetitions)
        {
            if (profile == "22/11/m12")
                fp31Bench<22, 11, 12, Reference>(2097150, repetitions);
            else if (profile == "24/12/m6")
                fp31Bench<24, 12, 6, Reference>(2097144, repetitions);
            else if (profile == "26/13/m4")
                fp31Bench<26, 13, 4, Reference>(2097134, repetitions);
            else if (profile == "28/14/m3")
                fp31Bench<28, 14, 3, Reference>(2097144, repetitions);
            else
                throw std::invalid_argument("unknown regular EC Fp31 profile");
        }

        template<typename Code, typename Value>
        double goldilocksEncodeBench(
            const Code& code,
            const std::vector<Value>& source,
            std::vector<Value>& input,
            CoeffCtxGoldilocks ctx,
            u64 repetitions)
        {
            double best = std::numeric_limits<double>::infinity();
            for (u64 repetition = 0; repetition != repetitions; ++repetition)
            {
                std::copy(source.begin(), source.end(), input.begin());
                const auto begin = Clock::now();
                code.template dualEncode<Value>(input.begin(), ctx);
                const auto end = Clock::now();
                best = std::min(best,
                    std::chrono::duration<double>(end - begin).count());
            }
            return best;
        }

        template<bool Reference>
        void goldilocksBench(u64 repetitions)
        {
            using G = Goldilocks;
            using F = FVec<G, 2>;
            constexpr u64 leftDegree = 26;
            constexpr u64 rightDegree = 13;
            constexpr u64 memory = 4;
            constexpr u64 n = 2097134;
            constexpr u64 k = 1048567;

            CoeffCtxGoldilocks ctx;
            using Code = std::conditional_t<
                Reference,
                RegularEcFieldCode<leftDegree, memory, G>,
                RegularEcStreamingFieldCode<leftDegree, memory, G>>;
            Code code;
            const auto configBegin = Clock::now();
            code.config(k, n, block(0x1234, 0x5678), ctx);
            const auto configEnd = Clock::now();

            std::vector<G> scalarSource(n), scalarInput(n);
            std::vector<F> wideSource(n), wideInput(n);
            PRNG prng(block(0x9abc, 0xdef0));
            for (u64 i = 0; i != n; ++i)
            {
                ctx.fromBlock(scalarSource[i], prng.get<block>());
                ctx.fromBlock(wideSource[i][0], prng.get<block>());
                ctx.fromBlock(wideSource[i][1], prng.get<block>());
            }

            const double scalarSeconds = goldilocksEncodeBench(
                code, scalarSource, scalarInput, ctx, repetitions);
            const double wideSeconds = goldilocksEncodeBench(
                code, wideSource, wideInput, ctx, repetitions);

            double scalarConvolution = std::numeric_limits<double>::infinity();
            double scalarExpander = std::numeric_limits<double>::infinity();
            for (u64 repetition = 0; repetition != repetitions; ++repetition)
            {
                std::copy(scalarSource.begin(), scalarSource.end(), scalarInput.begin());
                std::vector<G> output(k);
                const auto begin = Clock::now();
                code.template dualConvolve<G>(scalarInput, ctx);
                const auto middle = Clock::now();
                code.template dualExpand<G>(scalarInput, output, ctx);
                const auto end = Clock::now();
                scalarConvolution = std::min(scalarConvolution,
                    std::chrono::duration<double>(middle - begin).count());
                scalarExpander = std::min(scalarExpander,
                    std::chrono::duration<double>(end - middle).count());
            }

            double pairSeconds = std::numeric_limits<double>::infinity();
            for (u64 repetition = 0; repetition != repetitions; ++repetition)
            {
                std::copy(wideSource.begin(), wideSource.end(), wideInput.begin());
                std::copy(scalarSource.begin(), scalarSource.end(), scalarInput.begin());
                const auto begin = Clock::now();
                code.template dualEncode2<F, G>(
                    wideInput.begin(), scalarInput.begin(), ctx);
                const auto end = Clock::now();
                pairSeconds = std::min(pairSeconds,
                    std::chrono::duration<double>(end - begin).count());
            }

            const double configSeconds =
                std::chrono::duration<double>(configEnd - configBegin).count();
            const double scheduleKiB = static_cast<double>(code.scheduleBytes()) /
                static_cast<double>(u64{ 1 } << 10);

            std::cout << "Goldilocks "
                << (Reference ? "reference " : "streaming-heuristic ")
                << leftDegree << '/' << rightDegree
                << "/m" << memory << "  k=" << k << " n=" << n
                << "  config=" << std::fixed << std::setprecision(3)
                << configSeconds << " s  schedule=" << std::setprecision(1)
                << scheduleKiB << " KiB  G=" << std::setprecision(3)
                << scalarSeconds << " s (conv " << scalarConvolution
                << ", expand " << scalarExpander << ")  F=G^2=" << wideSeconds
                << " s  receiver-pair=" << pairSeconds << " s\n";
        }

#ifdef ENABLE_SILENT_VOLE
        template<typename Scalar, typename Ctx>
        void setScalarVoleFakeBase(
            SilentVoleReceiver<Scalar, Scalar, Ctx>& receiver,
            SilentVoleSender<Scalar, Scalar, Ctx>& sender,
            Scalar delta,
            PRNG& prng,
            Ctx ctx)
        {
            const auto count = sender.baseCount();
            std::vector<std::array<block, 2>> sendOts(count.mBaseOtCount);
            const BitVector choices = receiver.sampleBaseChoiceBits(prng);
            std::vector<block> receiveOts(choices.size());
            if (choices.size() != sendOts.size())
                throw std::runtime_error(
                    "Silent VOLE parties requested different base OT counts");

            for (auto& messages : sendOts)
            {
                messages[0] = prng.get();
                messages[1] = prng.get();
            }
            for (u64 index = 0; index != receiveOts.size(); ++index)
                receiveOts[index] = sendOts[index][choices[index]];

            typename Ctx::template Vec<Scalar> a(count.mBaseVoleCount);
            typename Ctx::template Vec<Scalar> b(count.mBaseVoleCount);
            typename Ctx::template Vec<Scalar> c(count.mBaseVoleCount);
            for (u64 index = 0; index != c.size(); ++index)
            {
                ctx.fromBlock(c[index], prng.get<block>());
                ctx.fromBlock(b[index], prng.get<block>());
                ctx.mul(a[index], delta, c[index]);
                ctx.plus(a[index], a[index], b[index]);
            }

            sender.setBaseCors(sendOts, b);
            receiver.setBaseCors(choices, receiveOts, a, c);
        }

        template<typename Scalar, typename Ctx>
        double scalarVoleTrial(
            MultType profile,
            u64 requestSize,
            SdNoiseDistribution noise,
            u64 repetition)
        {
            Ctx ctx;
            SilentVoleSender<Scalar, Scalar, Ctx> sender;
            SilentVoleReceiver<Scalar, Scalar, Ctx> receiver;
            sender.configure(
                requestSize, SilentSecType::SemiHonest,
                profile,
                SilentBaseType::BaseExtend, noise, 128, ctx);
            receiver.configure(
                requestSize, SilentSecType::SemiHonest,
                profile,
                SilentBaseType::BaseExtend, noise, 128, ctx);

            PRNG setupPrng(block(
                0x51f15eeda11ce000ull + repetition,
                0x7e57ba5e00000000ull));
            Scalar delta;
            ctx.fromBlock(delta, setupPrng.get<block>());
            setScalarVoleFakeBase(
                receiver, sender, delta, setupPrng, ctx);

            typename Ctx::template Vec<Scalar> a(requestSize);
            typename Ctx::template Vec<Scalar> b(requestSize);
            typename Ctx::template Vec<Scalar> c(requestSize);
            PRNG receiverPrng(block(0x7265636569766572ull, repetition));
            PRNG senderPrng(block(0x73656e6465720000ull, repetition));
            auto sockets = coproto::LocalAsyncSocket::makePair();

            const auto begin = Clock::now();
            auto receive = receiver.silentReceive(
                c, a, receiverPrng, sockets[0]);
            auto send = sender.silentSend(
                delta, b, senderPrng, sockets[1]);
            auto results = macoro::sync_wait(macoro::when_all_ready(
                std::move(receive), std::move(send)));
            std::get<0>(results).result();
            std::get<1>(results).result();
            const auto end = Clock::now();

            for (u64 index = 0; index != requestSize; ++index)
            {
                Scalar expected;
                ctx.mul(expected, delta, c[index]);
                ctx.plus(expected, expected, b[index]);
                if (a[index] != expected)
                    throw std::runtime_error(
                        "Silent scalar VOLE correlation check failed");
            }

            return std::chrono::duration<double>(end - begin).count();
        }

        template<typename Scalar, typename Ctx>
        void printScalarVoleBench(
            const char* fieldName,
            MultType profile,
            u64 requestSize,
            SdNoiseDistribution noise,
            std::vector<double> timings)
        {
            std::sort(timings.begin(), timings.end());

            const auto groupBitCount =
                coefficientGroupBitCount<Scalar>(Ctx{});
            const auto config = syndromeDecodingConfigure(
                128, requestSize, profile, noise, groupBitCount);
            const double median = timings[timings.size() / 2];
            const double best = timings.front();
            const double outputMiB = static_cast<double>(
                requestSize * 3 * sizeof(Scalar)) /
                static_cast<double>(u64{ 1 } << 20);
            std::cout << fieldName << " Silent VOLE " << profile
                << "  requested=" << requestSize
                << "  encoded=" << config.mNoiseVectorSize
                << "  noise=" << config.mNumPartitions << 'x'
                << config.mSizePer
                << "  best=" << std::fixed << std::setprecision(3)
                << best << " s  median=" << median
                << " s  output=" << std::setprecision(1)
                << outputMiB / median << " MiB/s\n";
        }

        template<typename Scalar, typename Ctx>
        void scalarVoleBench(
            const char* fieldName,
            MultType profile,
            u64 requestSize,
            u64 repetitions,
            SdNoiseDistribution noise)
        {
            if (repetitions == 0)
                throw std::invalid_argument(
                    "Silent VOLE benchmark needs at least one repetition");
            std::vector<double> timings;
            timings.reserve(repetitions);
            for (u64 repetition = 0; repetition != repetitions; ++repetition)
                timings.push_back(scalarVoleTrial<Scalar, Ctx>(
                    profile, requestSize, noise, repetition));
            printScalarVoleBench<Scalar, Ctx>(
                fieldName, profile, requestSize, noise, std::move(timings));
        }
#endif
    }

    void RegularEcBench(CLP& cmd)
    {
        const u64 repetitions = cmd.getOr("t", 3ull);
        if (cmd.isSet("columnLabels") || cmd.isSet("unitLabels"))
            throw std::invalid_argument(
                "regular EC label ablation modes were removed; use -reference or the default heuristic");
        const bool reference = cmd.isSet("reference");
        if (cmd.isSet("audit"))
        {
            fieldGeneratorAudit(
                cmd.getOr("regionSize", 29ull),
                cmd.getOr("seeds", 8ull));
            return;
        }
        if (cmd.isSet("goldilocks"))
        {
#ifdef ENABLE_SILENT_VOLE
            if (cmd.isSet("vole"))
            {
                const u64 requestSize =
                    cmd.getOr("n", 1ull << cmd.getOr("nn", 20));
                const auto noise = static_cast<SdNoiseDistribution>(
                    cmd.getOr("noise", static_cast<int>(
                        SdNoiseDistribution::Regular)));
                scalarVoleBench<Goldilocks, CoeffCtxGoldilocks>(
                    "Goldilocks", MultType::RegularEc26x13x4,
                    requestSize, repetitions, noise);
                return;
            }
#else
            if (cmd.isSet("vole"))
                throw std::runtime_error(
                    "Goldilocks Silent VOLE benchmark requires ENABLE_SILENT_VOLE");
#endif
            if (reference)
                goldilocksBench<true>(repetitions);
            else
                goldilocksBench<false>(repetitions);
            return;
        }

        if (cmd.isSet("gf128"))
        {
#ifdef ENABLE_SILENT_VOLE
            const MultType profile = cmd.isSet("default") ?
                DefaultMultType : MultType::RegularEc26x13x4;
            const u64 requestSize =
                cmd.getOr("n", 1ull << cmd.getOr("nn", 20));
            const auto noise = static_cast<SdNoiseDistribution>(
                cmd.getOr("noise", static_cast<int>(
                    SdNoiseDistribution::Regular)));
            scalarVoleBench<block, CoeffCtxGF128>(
                "GF128", profile,
                requestSize, repetitions, noise);
            return;
#else
            throw std::runtime_error(
                "GF128 Silent VOLE benchmark requires ENABLE_SILENT_VOLE");
#endif
        }

        if (cmd.isSet("fp31"))
        {
            const auto profile =
                cmd.getOr<std::string>("profile", "26/13/m4");
            if (reference)
                fp31ProfileBench<true>(profile, repetitions);
            else
                fp31ProfileBench<false>(profile, repetitions);
            return;
        }

        binaryBench<10, 5, 15>(2097150, repetitions);
        if (cmd.isSet("all"))
        {
            binaryBench<18, 9, 4>(2097270, repetitions);
            binaryBench<14, 7, 6>(2097270, repetitions);
            binaryBench<6, 3, 79>(2097150, repetitions);
        }
    }
}
