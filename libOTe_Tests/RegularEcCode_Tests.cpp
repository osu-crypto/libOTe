#include "RegularEcCode_Tests.h"

#include "cryptoTools/Common/TestCollection.h"
#include "libOTe/Tools/CoeffCtx.h"
#include "libOTe/Tools/ExConvCode/RegularEcCode.h"
#include "libOTe/Tools/ExConvCode/RegularEcFieldCode.h"
#include "libOTe/Tools/ExConvCode/RegularEcStreamingFieldCode.h"
#include "libOTe/Tools/Field/Fp.h"
#include "libOTe/Tools/Field/FVec.h"
#include "libOTe/Tools/Field/Goldilocks.h"

#include <array>
#include <limits>
#include <vector>

namespace osuCrypto
{
    namespace
    {
        template<u64 LeftDegree, u64 Memory>
        std::vector<u8> encodeRow(
            const RegularEcCode<LeftDegree, Memory>& code,
            u64 row)
        {
            std::vector<u8> word(code.mCodeSize);
            for (u64 region = 0; region != LeftDegree; ++region)
                word[code.rightAt(region, row)] ^= 1;

            for (u64 time = 0; time != code.mCodeSize; ++time)
            {
                for (u64 lag = 1; lag < Memory && lag <= time; ++lag)
                {
                    if (code.randomCoefficient(time, lag))
                        word[time] ^= word[time - lag];
                }
                if (time >= Memory)
                    word[time] ^= word[time - Memory];
            }
            return word;
        }

        template<typename Fn>
        void expectInvalid(Fn&& fn)
        {
            bool rejected = false;
            try
            {
                fn();
            }
            catch (const std::invalid_argument&)
            {
                rejected = true;
            }
            if (!rejected)
                throw UnitTestFail("invalid regular EC configuration was accepted" LOCATION);
        }

        template<u64 LeftDegree, u64 Memory, typename F, typename Ctx>
        std::vector<F> encodeFieldRow(
            const RegularEcStreamingFieldCode<
                LeftDegree, Memory, F>& code,
            u64 row,
            Ctx ctx)
        {
            std::vector<F> word(code.mCodeSize);
            ctx.zero(word.begin(), word.end());
            for (u64 region = 0; region != LeftDegree; ++region)
            {
                const auto right = code.rightAt(region, row);
                ctx.plus(word[right], word[right], code.edgeLabel(region, row, ctx));
            }

            for (u64 time = 0; time != code.mCodeSize; ++time)
            {
                for (u64 lag = 1; lag <= Memory && lag <= time; ++lag)
                {
                    F product;
                    ctx.mul(product,
                        code.feedbackCoefficient(time, lag, ctx),
                        word[time - lag]);
                    ctx.plus(word[time], word[time], product);
                }
            }
            return word;
        }

        template<u64 LeftDegree, u64 Memory, typename F, typename Ctx>
        std::vector<F> encodeFieldRow(
            const RegularEcFieldCode<LeftDegree, Memory, F>& code,
            u64 row,
            Ctx ctx)
        {
            std::vector<F> word(code.mCodeSize);
            ctx.zero(word.begin(), word.end());
            for (u64 region = 0; region != LeftDegree; ++region)
            {
                const auto right = code.rightAt(region, row);
                ctx.plus(word[right], word[right], code.edgeLabel(region, row, ctx));
            }

            for (u64 time = 0; time != code.mCodeSize; ++time)
            {
                for (u64 lag = 1; lag <= Memory && lag <= time; ++lag)
                {
                    F product;
                    ctx.mul(product,
                        code.feedbackCoefficient(time, lag, ctx),
                        word[time - lag]);
                    ctx.plus(word[time], word[time], product);
                }
            }
            return word;
        }

        template<u64 LeftDegree, u64 Memory>
        u64 expansionRank(
            const RegularEcStreamingFieldCode<
                LeftDegree, Memory, Fp31>& code,
            CoeffCtxFp ctx)
        {
            const u64 rows = code.mMessageSize;
            const u64 columns = code.mCodeSize;
            std::vector<Fp31> matrix(rows * columns, Fp31::zero());
            for (u64 row = 0; row != rows; ++row)
            {
                for (u64 region = 0; region != LeftDegree; ++region)
                {
                    const u64 column = code.rightAt(region, row);
                    matrix[row * columns + column] +=
                        code.edgeLabel(region, row, ctx);
                }
            }

            u64 rank = 0;
            for (u64 column = 0; column != columns && rank != rows; ++column)
            {
                u64 pivot = rank;
                while (pivot != rows &&
                    matrix[pivot * columns + column] == Fp31::zero())
                    ++pivot;
                if (pivot == rows)
                    continue;
                for (u64 index = column; index != columns; ++index)
                    std::swap(
                        matrix[rank * columns + index],
                        matrix[pivot * columns + index]);

                const Fp31 inverse =
                    matrix[rank * columns + column].inverse();
                for (u64 index = column; index != columns; ++index)
                    matrix[rank * columns + index] *= inverse;
                for (u64 row = rank + 1; row != rows; ++row)
                {
                    const Fp31 factor = matrix[row * columns + column];
                    if (factor == Fp31::zero())
                        continue;
                    for (u64 index = column; index != columns; ++index)
                        matrix[row * columns + index] -=
                            factor * matrix[rank * columns + index];
                }
                ++rank;
            }
            return rank;
        }

        template<u64 LeftDegree, u64 Memory, typename Scalar, typename Ctx>
        u64 binaryExpansionRank(
            const RegularEcStreamingFieldCode<
                LeftDegree, Memory, Scalar>& code,
            Ctx)
        {
            const u64 rows = code.mMessageSize;
            const u64 columns = code.mCodeSize;
            std::vector<u8> matrix(rows * columns);
            for (u64 row = 0; row != rows; ++row)
            {
                for (u64 region = 0; region != LeftDegree; ++region)
                    matrix[row * columns + code.rightAt(region, row)] ^= 1;
            }

            u64 rank = 0;
            for (u64 column = 0; column != columns && rank != rows; ++column)
            {
                u64 pivot = rank;
                while (pivot != rows && !matrix[pivot * columns + column])
                    ++pivot;
                if (pivot == rows)
                    continue;
                for (u64 index = column; index != columns; ++index)
                    std::swap(
                        matrix[rank * columns + index],
                        matrix[pivot * columns + index]);
                for (u64 row = rank + 1; row != rows; ++row)
                {
                    if (!matrix[row * columns + column])
                        continue;
                    for (u64 index = column; index != columns; ++index)
                        matrix[row * columns + index] ^=
                            matrix[rank * columns + index];
                }
                ++rank;
            }
            return rank;
        }
    }

    void RegularEcCode_encode_test(const CLP&)
    {
        constexpr u64 LeftDegree = 6;
        constexpr u64 Memory = 4;
        constexpr u64 k = 9;
        constexpr u64 n = 18;

        RegularEcCode<LeftDegree, Memory> code;
        code.config(k, n, block(0x1234, 0x5678));

        std::vector<u8> input(n);
        for (u64 i = 0; i != n; ++i)
            input[i] = static_cast<u8>((i * i + 3 * i + 1) & 1);
        const auto original = input;
        std::vector<u8> actual(k);
        code.dualEncode<u8>(input, actual, CoeffCtxGF2{});

        for (u64 row = 0; row != k; ++row)
        {
            const auto generatorRow = encodeRow(code, row);
            u8 expected = 0;
            for (u64 column = 0; column != n; ++column)
                expected ^= generatorRow[column] & original[column];
            if (actual[row] != expected)
                throw UnitTestFail(
                    "regular EC transpose disagrees with its materialized generator" LOCATION);
        }

        {
            RegularEcCode<10, 15> target;
            target.config(10, 20, block(0x2468, 0x1357));
            std::vector<u8> targetInput(20), targetOutput(10);
            for (u64 i = 0; i != targetInput.size(); ++i)
                targetInput[i] = static_cast<u8>((7 * i + i * i + 1) & 1);
            const auto targetOriginal = targetInput;
            target.dualEncode<u8>(targetInput, targetOutput, CoeffCtxGF2{});
            for (u64 row = 0; row != target.mMessageSize; ++row)
            {
                const auto generatorRow = encodeRow(target, row);
                u8 expected = 0;
                for (u64 column = 0; column != target.mCodeSize; ++column)
                    expected ^= generatorRow[column] & targetOriginal[column];
                if (targetOutput[row] != expected)
                    throw UnitTestFail(
                        "10/5/m15 transpose disagrees with its generator" LOCATION);
            }

            std::vector<block> targetBlockInput(target.mCodeSize);
            for (u64 i = 0; i != targetBlockInput.size(); ++i)
                targetBlockInput[i] = block(i * 0x9e3779b97f4a7c15ull,
                                            i ^ 0xd1b54a32d192ed03ull);
            const auto targetBlockOriginal = targetBlockInput;
            std::vector<block> targetBlockOutput(target.mMessageSize);
            target.dualEncode<block>(
                targetBlockInput, targetBlockOutput, CoeffCtxGF2{});
            for (u64 row = 0; row != target.mMessageSize; ++row)
            {
                const auto generatorRow = encodeRow(target, row);
                block expected = ZeroBlock;
                for (u64 column = 0; column != target.mCodeSize; ++column)
                {
                    if (generatorRow[column])
                        expected ^= targetBlockOriginal[column];
                }
                if (targetBlockOutput[row] != expected)
                    throw UnitTestFail(
                        "10/5/m15 block transpose disagrees with its generator" LOCATION);
            }
        }

        PRNG prng(block(0x9abc, 0xdef0));
        std::vector<block> blockInput(n);
        prng.get(blockInput.data(), blockInput.size());
        const auto originalBlocks = blockInput;
        std::vector<block> blockOutput(k);
        code.dualEncode<block>(blockInput, blockOutput, CoeffCtxGF2{});
        for (u64 row = 0; row != k; ++row)
        {
            const auto generatorRow = encodeRow(code, row);
            block expected = ZeroBlock;
            for (u64 column = 0; column != n; ++column)
            {
                if (generatorRow[column])
                    expected ^= originalBlocks[column];
            }
            if (blockOutput[row] != expected)
                throw UnitTestFail(
                    "regular EC block transpose disagrees with its generator" LOCATION);
        }

        auto inPlace = originalBlocks;
        code.dualEncode<block>(inPlace.begin(), CoeffCtxGF2{});
        for (u64 row = 0; row != k; ++row)
        {
            if (inPlace[row] != blockOutput[row])
                throw UnitTestFail("regular EC in-place encode disagrees" LOCATION);
        }

        std::vector<u64> rightDegrees(n);
        std::vector<u64> leftDegrees(k);
        for (u64 left = 0; left != k; ++left)
        {
            std::vector<u8> seenRegion(LeftDegree);
            for (u64 region = 0; region != LeftDegree; ++region)
            {
                const u64 right = code.rightAt(region, left);
                if (right / code.mRegionSize != region)
                    throw UnitTestFail("regular EC edge escaped its region" LOCATION);
                if (seenRegion[region])
                    throw UnitTestFail("regular EC row repeats a region" LOCATION);
                seenRegion[region] = 1;
                ++leftDegrees[left];
                ++rightDegrees[right];
            }
        }
        for (const auto degree : leftDegrees)
        {
            if (degree != LeftDegree)
                throw UnitTestFail("regular EC left degree is not exact" LOCATION);
        }
        for (const auto degree : rightDegrees)
        {
            if (degree != code.rightDegree())
                throw UnitTestFail("regular EC right degree is not exact" LOCATION);
        }

        std::vector<u8> input0 = original;
        std::vector<u8> input1(n);
        for (u64 i = 0; i != n; ++i)
            input1[i] = static_cast<u8>((5 * i + 1) & 1);
        const auto original1 = input1;
        std::vector<u8> output0(k), output1(k);
        code.dualEncode2<u8, u8>(input0, output0, input1, output1, CoeffCtxGF2{});

        auto separate1 = original1;
        std::vector<u8> separateOutput1(k);
        code.dualEncode<u8>(separate1, separateOutput1, CoeffCtxGF2{});
        if (output1 != separateOutput1)
            throw UnitTestFail("regular EC dualEncode2 disagrees with dualEncode" LOCATION);

        auto pairedBlocks = originalBlocks;
        auto pairedBits = original1;
        code.dualEncode2<block, u8>(
            pairedBlocks.begin(), pairedBits.begin(), CoeffCtxGF2{});
        for (u64 row = 0; row != k; ++row)
        {
            if (pairedBlocks[row] != blockOutput[row] ||
                pairedBits[row] != separateOutput1[row])
                throw UnitTestFail("regular EC in-place dualEncode2 disagrees" LOCATION);
        }


        {
            using F = Fp31;
            CoeffCtxFp ctx;
            RegularEcStreamingFieldCode<6, 4, F> fpCode;
            fpCode.config(k, n, block(0x8642, 0x9753), ctx);

            std::vector<F> fpInput(n), fpOutput(k);
            for (u64 i = 0; i != n; ++i)
                fpInput[i] = F(17 * i * i + 5 * i + 3);
            const auto fpOriginal = fpInput;
            fpCode.dualEncode<F>(fpInput, fpOutput, ctx);

            for (u64 row = 0; row != k; ++row)
            {
                const auto generatorRow = encodeFieldRow(fpCode, row, ctx);
                F expected = F::zero();
                for (u64 column = 0; column != n; ++column)
                    expected += generatorRow[column] * fpOriginal[column];
                if (fpOutput[row] != expected)
                    throw UnitTestFail(
                        "finite-field regular EC transpose disagrees with its generator" LOCATION);
            }

            for (u64 region = 0; region != fpCode.leftDegree(); ++region)
            {
                for (u64 row = 0; row != k; ++row)
                {
                    if (fpCode.edgeLabel(region, row, ctx) == F::zero())
                        throw UnitTestFail(
                            "finite-field regular EC sampled a zero edge label" LOCATION);
                }
            }

            auto fpInPlace = fpOriginal;
            fpCode.dualEncode<F>(fpInPlace.begin(), ctx);
            for (u64 row = 0; row != k; ++row)
            {
                if (fpInPlace[row] != fpOutput[row])
                    throw UnitTestFail(
                        "finite-field regular EC in-place encode disagrees" LOCATION);
            }

            RegularEcFieldCode<6, 4, F> referenceCode;
            referenceCode.config(k, n, block(0x4682, 0x1759), ctx);
            auto referenceInput = fpOriginal;
            std::vector<F> referenceOutput(k);
            referenceCode.dualEncode<F>(referenceInput, referenceOutput, ctx);
            for (u64 row = 0; row != k; ++row)
            {
                const auto generatorRow = encodeFieldRow(
                    referenceCode, row, ctx);
                F expected = F::zero();
                for (u64 column = 0; column != n; ++column)
                    expected += generatorRow[column] * fpOriginal[column];
                if (referenceOutput[row] != expected)
                    throw UnitTestFail(
                        "reference field EC transpose disagrees with its generator" LOCATION);
            }

            std::vector<u64> referenceDegrees(n);
            for (u64 row = 0; row != k; ++row)
            {
                for (u64 region = 0; region != LeftDegree; ++region)
                {
                    const u64 right = referenceCode.rightAt(region, row);
                    ++referenceDegrees[right];
                    if (referenceCode.edgeLabel(region, row, ctx) == F::zero())
                        throw UnitTestFail(
                            "reference field EC sampled a zero edge label" LOCATION);
                }
            }
            for (const auto degree : referenceDegrees)
            {
                if (degree != referenceCode.rightDegree())
                    throw UnitTestFail(
                        "reference field EC right degree is not exact" LOCATION);
            }

            auto referenceSeparate0 = fpOriginal;
            auto referenceSeparate1 = fpOriginal;
            for (u64 i = 0; i != n; ++i)
                referenceSeparate1[i] += F(9 * i + 1);
            auto referencePair0 = referenceSeparate0;
            auto referencePair1 = referenceSeparate1;
            referenceCode.dualEncode<F>(referenceSeparate0.begin(), ctx);
            referenceCode.dualEncode<F>(referenceSeparate1.begin(), ctx);
            referenceCode.dualEncode2<F, F>(
                referencePair0.begin(), referencePair1.begin(), ctx);
            for (u64 row = 0; row != k; ++row)
            {
                if (referencePair0[row] != referenceSeparate0[row] ||
                    referencePair1[row] != referenceSeparate1[row])
                    throw UnitTestFail(
                        "reference field EC paired encode disagrees with separate encodes" LOCATION);
            }
        }

        {
            CoeffCtxGF128 ctx;
            RegularEcStreamingFieldCode<6, 4, block> gfCode;
            gfCode.config(k, n, block(0x7531, 0x8642), ctx);

            std::vector<block> gfInput(n), gfOutput(k);
            PRNG gfPrng(block(0x1122, 0x3344));
            gfPrng.get(gfInput.data(), gfInput.size());
            const auto gfOriginal = gfInput;
            gfCode.dualEncode<block>(gfInput, gfOutput, ctx);

            for (u64 row = 0; row != k; ++row)
            {
                const auto generatorRow = encodeFieldRow(gfCode, row, ctx);
                block expected = ZeroBlock;
                for (u64 column = 0; column != n; ++column)
                    expected ^= generatorRow[column].gf128Mul(gfOriginal[column]);
                if (gfOutput[row] != expected)
                    throw UnitTestFail(
                        "GF128 regular EC transpose disagrees with its generator" LOCATION);
            }
        }

        {
            using G = Goldilocks;
            using F = FVec<G, 2>;
            CoeffCtxGoldilocks ctx;
            RegularEcStreamingFieldCode<6, 4, G> goldCode;
            goldCode.config(k, n, block(0x9753, 0x1357), ctx);

            std::vector<F> wideInput(n);
            std::vector<G> scalarInput(n);
            PRNG goldPrng(block(0x5566, 0x7788));
            for (u64 i = 0; i != n; ++i)
            {
                ctx.fromBlock(wideInput[i][0], goldPrng.get<block>());
                ctx.fromBlock(wideInput[i][1], goldPrng.get<block>());
                ctx.fromBlock(scalarInput[i], goldPrng.get<block>());
            }

            auto separateWide = wideInput;
            auto separateScalar = scalarInput;
            goldCode.dualEncode<F>(separateWide.begin(), ctx);
            goldCode.dualEncode<G>(separateScalar.begin(), ctx);

            goldCode.dualEncode2<F, G>(
                wideInput.begin(), scalarInput.begin(), ctx);
            for (u64 row = 0; row != k; ++row)
            {
                if (wideInput[row] != separateWide[row] ||
                    scalarInput[row] != separateScalar[row])
                    throw UnitTestFail(
                        "Goldilocks module dualEncode2 disagrees with separate encodes" LOCATION);
            }
        }
    }

    void RegularEcCode_config_test(const CLP&)
    {
        expectInvalid([] { RegularEcCode<6, 4> code; code.config(0, 18); });
        expectInvalid([] { RegularEcCode<6, 4> code; code.config(18, 18); });
        expectInvalid([] { RegularEcCode<6, 4> code; code.config(9, 17); });
        expectInvalid([] { RegularEcCode<6, 4> code; code.config(10, 18); });
        expectInvalid([] { RegularEcCode<8, 4> code; code.config(4, 8); });
        expectInvalid([] { RegularEcCode<6, 18> code; code.config(9, 18); });
        expectInvalid([] {
            RegularEcCode<6, 4> code;
            code.config(static_cast<u64>(std::numeric_limits<u32>::max()) + 1, 18);
        });
        expectInvalid([] {
            CoeffCtxGF128 ctx;
            RegularEcStreamingFieldCode<6, 4, block> code;
            code.config(3, 6, block(1, 2), ctx);
        });

        RegularEcCode<18, 4> fast;
        fast.config(18, 36);
        if (fast.rightDegree() != 9)
            throw UnitTestFail("18/9 regular EC profile has the wrong right degree" LOCATION);

        RegularEcCode<14, 6> balanced;
        balanced.config(14, 28);
        if (balanced.rightDegree() != 7)
            throw UnitTestFail("14/7 regular EC profile has the wrong right degree" LOCATION);

        RegularEcCode<2, 1> accumulator;
        accumulator.config(7, 14);
        if (accumulator.rightDegree() != 1)
            throw UnitTestFail("memory-one profile did not reduce to an accumulator" LOCATION);

        {
            constexpr u64 leftDegree = 10;
            constexpr u64 rightDegree = 5;
            constexpr u64 regionSize = 257;
            constexpr u64 k = rightDegree * regionSize;
            constexpr u64 n = leftDegree * regionSize;
            CoeffCtxFp ctx;

            for (u64 seedIndex = 0; seedIndex != 128; ++seedIndex)
            {
                RegularEcStreamingFieldCode<leftDegree, 4, Fp31> code;
                code.config(k, n, block(seedIndex, ~seedIndex), ctx);
                std::vector<u32> degrees(n);
                for (u64 left = 0; left != k; ++left)
                {
                    for (u64 region = 0; region != leftDegree; ++region)
                    {
                        const u64 right = code.rightAt(region, left);
                        if (right / regionSize != region)
                            throw UnitTestFail(
                                "streaming regular EC edge escaped its region" LOCATION);
                        ++degrees[right];
                        const auto label = code.edgeLabel(region, left, ctx);
                        if (label == Fp31::zero())
                            throw UnitTestFail(
                                "streaming regular EC sampled a zero column label" LOCATION);
                        if (label != Fp31::one() && label != -Fp31::one())
                            throw UnitTestFail(
                                "streaming regular EC column label was not a sign" LOCATION);
                    }
                }
                for (const auto degree : degrees)
                {
                    if (degree != rightDegree)
                        throw UnitTestFail(
                            "streaming regular EC right degree is not exact" LOCATION);
                }
            }

            RegularEcStreamingFieldCode<leftDegree, 4, Fp31> code0;
            RegularEcStreamingFieldCode<leftDegree, 4, Fp31> code1;
            code0.config(k, n, block(11, 22), ctx);
            code1.config(k, n, block(11, 22), ctx);
            for (u64 left = 0; left != k; ++left)
            {
                for (u64 region = 0; region != leftDegree; ++region)
                {
                    if (code0.rightAt(region, left) != code1.rightAt(region, left) ||
                        code0.edgeLabel(region, left, ctx) !=
                            code1.edgeLabel(region, left, ctx))
                        throw UnitTestFail(
                            "streaming regular EC seed is not deterministic" LOCATION);
                }
            }

            // Slot-preserving cyclic shifts have a (rightDegree - 1)
            // dimensional kernel.  Full-index permutations must not retain
            // that invariant.
            constexpr u64 rankRegionSize = 7;
            constexpr u64 rankK = 13 * rankRegionSize;
            constexpr u64 rankN = 26 * rankRegionSize;
            CoeffCtxGF128 gf128Ctx;
            for (u64 seedIndex = 0; seedIndex != 128; ++seedIndex)
            {
                RegularEcStreamingFieldCode<26, 4, Fp31> rankCode;
                rankCode.config(
                    rankK, rankN, block(seedIndex, ~seedIndex), ctx);
                if (expansionRank(rankCode, ctx) != rankK)
                    throw UnitTestFail(
                        "streaming regular EC expander is rank deficient" LOCATION);

                RegularEcStreamingFieldCode<26, 4, block> binaryRankCode;
                binaryRankCode.config(
                    rankK, rankN, block(seedIndex, ~seedIndex), gf128Ctx);
                if (binaryExpansionRank(binaryRankCode, gf128Ctx) != rankK)
                    throw UnitTestFail(
                        "characteristic-two streaming regular EC expander is rank deficient" LOCATION);
            }

            constexpr u64 collisionRegionSize = 1009;
            RegularEcStreamingFieldCode<10, 4, Fp31> collisionFreeCode;
            collisionFreeCode.config(
                5 * collisionRegionSize,
                10 * collisionRegionSize,
                block(0x5060, 0x7080),
                ctx);
            for (u64 first = 0; first != 5; ++first)
            {
                for (u64 second = first + 1; second != 5; ++second)
                {
                    std::vector<u8> seen(collisionRegionSize);
                    for (u64 region = 0; region != 10; ++region)
                    {
                        const u64 firstRight =
                            collisionFreeCode.rightAt(region, first) -
                            region * collisionRegionSize;
                        const u64 secondRight =
                            collisionFreeCode.rightAt(region, second) -
                            region * collisionRegionSize;
                        const u64 difference =
                            (firstRight + collisionRegionSize - secondRight) %
                            collisionRegionSize;
                        if (seen[difference])
                            throw UnitTestFail(
                                "streaming regular EC repeated a slot difference" LOCATION);
                        seen[difference] = 1;
                    }
                }
            }

            constexpr u64 deployedRegionSize = 80659;
            constexpr u64 deployedLeftDegree = 26;
            constexpr u64 deployedRightDegree = 13;
            constexpr u64 deployedK =
                deployedRightDegree * deployedRegionSize;
            constexpr u64 deployedN =
                deployedLeftDegree * deployedRegionSize;
            for (u64 seedIndex = 0; seedIndex != 1024; ++seedIndex)
            {
                RegularEcStreamingFieldCode<
                    deployedLeftDegree, 4, Fp31> deployedCode;
                deployedCode.config(
                    deployedK, deployedN,
                    block(seedIndex, ~seedIndex), ctx);
                u64 offsetDigest = 0xcbf29ce484222325ull;
                for (u64 region = 0;
                    region != deployedLeftDegree; ++region)
                {
                    for (u64 slot = 0;
                        slot != deployedRightDegree; ++slot)
                    {
                        const u64 offset =
                            deployedCode.rightAt(region, slot) -
                            region * deployedRegionSize;
                        offsetDigest ^= offset;
                        offsetDigest *= 0x100000001b3ull;
                    }
                }
                if (seedIndex == 0 &&
                    offsetDigest != 0x5374e401c8ebc7ebull)
                    throw UnitTestFail(
                        "streaming EC topology replay digest changed" LOCATION);
                for (u64 first = 0; first != deployedRightDegree; ++first)
                {
                    for (u64 second = first + 1;
                        second != deployedRightDegree; ++second)
                    {
                        std::array<u32, deployedLeftDegree> differences;
                        for (u64 region = 0;
                            region != deployedLeftDegree; ++region)
                        {
                            const u64 firstRight =
                                deployedCode.rightAt(region, first) -
                                region * deployedRegionSize;
                            const u64 secondRight =
                                deployedCode.rightAt(region, second) -
                                region * deployedRegionSize;
                            differences[region] = static_cast<u32>(
                                (firstRight + deployedRegionSize - secondRight) %
                                deployedRegionSize);
                            for (u64 prior = 0; prior != region; ++prior)
                            {
                                if (differences[prior] == differences[region])
                                    throw UnitTestFail(
                                        "deployed streaming EC repeated a slot difference" LOCATION);
                            }
                        }
                    }
                }
            }
        }
    }
}
