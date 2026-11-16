#pragma once
#include <cstdint>

namespace osuCrypto
{
    enum class LogVoleChoice { Automatic, Disabled, Enabled };

    // Host dispatch choices. Captured by the table owner at construction;
    // never passed to device kernels. Defaults retain the existing schedules.
    struct LogVoleGpuKernelOptions
    {
        bool mNoGoldH200InverseOpTrace = false;
        bool mNttLog14H200 = true;
        bool mNttLog14H200FixedTransforms = true;
        bool mNoGoldH200CombinedAccumulator = true;
        bool mNoGoldH200AccumulatorPseudo52 = true;
        std::uint32_t mNoGoldH200InverseFp52Threads = 1024u;
        bool mNoGoldH200InverseFp52CacheRoots = true;
        bool mNoGoldH200InverseCachedSuffix = false;
        std::uint32_t mNoGoldH200InverseFp52Schedule = 4u;
        std::uint32_t mNoGoldH200InverseFp52TwoTile = 4u;
        std::uint32_t mNoGoldH200InverseFp52TileCacheStage = 2u;
        std::uint32_t mNoGoldH200InverseFp52Tile1024Mode = 2u;
        // UINT32_MAX selects 64 for hybrid tiles and 0 otherwise.
        std::uint32_t mNoGoldH200InverseFp52TileMinBlocks = 4294967295u;
        std::uint32_t mNoGoldH200InverseFp52PrefixSchedule = 10u;
        std::uint32_t mNoGoldH200InverseFp52StaticOps = 0u;
        bool mNoGoldH200Gadget208 = true;
        bool mNoGoldH200Gadget208Pseudo52 = true;
        bool mNttLog14H200InverseWarp05 = true;
        bool mNttLog14H200InverseDirectLoad = true;
        bool mNttLog14H200InversePairedSuffix = true;
        bool mNttLog14H200ForwardWarp712 = true;
        bool mNttLog14H200ForwardPairedPrefix = true;
        bool mNttLog14H200Centered = true;
        std::uint32_t mNttForwardThreads = 1024u;
        std::uint32_t mNttInverseThreads = 1024u;
        std::uint32_t mNttLog14H200InverseThreads = 512u;
        // Zero inherits mNttInverseThreads.
        std::uint32_t mNttFusedIpThreads = 0u;
        std::uint32_t mCt2PolySeedThreads = 32u;
        bool mCt2SplitAes = true;
        bool mCt2AesSharedSbox = true;
        bool mScaleAndRoundShoup = true;
        bool mScaleAndRoundFastArithmetic = true;
        bool mScaleAndRoundHotRho4 = true;
        bool mScaleAndRoundHotHiCarry = true;
        bool mScaleNttForwardGatherHiCarry = true;
        bool mScaleNttForwardGatherSlotOwned = true;
        bool mNttLog13Specialized = true;
        bool mNttLog13SimpleIndex = true;
        bool mNttLog13VectorShoupLoads = true;
        bool mNttLog13ForwardFusedFirstStage = true;
        bool mNttLog13ForwardFusedLastTwoStages = true;
        bool mNttLog13ForwardWarpStages712 = true;
        bool mNttLog13ForwardCenteredFromFusedLastTwoStages = true;
        bool mNttLog13ForwardPlainBroadcastFusedLastTwoStages = true;
        bool mNttLog13InverseFusedFirstStage = true;
        bool mNttLog13InverseFusedLastTwoStages = true;
        bool mNttLog13InverseFusedLastThreeStages = true;
        bool mNttLog13InverseFusedLastThreeAddNegate = true;
        bool mNttLog13InversePostWarpStages05 = true;
        bool mNttLog13InverseTreeFusedFirstStage = true;
        bool mNttLog13InverseTreeWarpStages = true;
        bool mNttLog13InverseTreeProductWarpStages05 = true;
        bool mNttLog13InverseTreeProductWarpVectorPairs = true;
        bool mNttLog13DirectStore = false;
        bool mNttCenteredDiagonalIdentity = false;
        bool mNttLog13InverseSpecialized = true;
        bool mNttLog13InverseDirectStore = true;
        bool mNttLog13InverseSmallDirect = false;
        bool mNttLog13InverseScatterFixed = true;
        bool mNttLog13InverseFixedIp = true;
        bool mFixedIpMuRowReuse = true;
        bool mFixedIpWideMuRowReuse = true;
        bool mPointwisePseudo55Reduce = true;
        std::uint32_t mRootZetaSampleThreads = 256u;
        std::uint32_t mNttLog13InverseThreads = 512u;
        std::uint32_t mNttLog13InverseMinBlocks = 256u;
        bool mExpandAccumulatorSpecialized = true;
        bool mExpandAccumulatorQ64Complement = true;
        bool mExpandAccumulatorPseudo55 = true;
        bool mExpandAccumulatorGoldenPseudo55Dual = true;
        bool mExpandAccumulatorPseudo55Wide = true;
        bool mExpandAccumulatorPseudo55Dual = true;
        bool mExpandAccumulatorPseudo55DualPackedPairs = true;
        bool mExpandAccumulatorTiled = true;
        bool mDenoiseSpecialized = true;
        bool mDenoiseShoup = true;
        bool mDenoiseHotGeometry = true;
        bool mGoldenValidateShoup = true;
        bool mDenoiseSpecializedRho8 = false;
        bool mNoGoldDenoiseShoup = true;
        bool mNoGoldDenoiseUnroll = true;
        std::uint32_t mNoGoldDenoiseThreads = 128u;
        bool mGadgetHi110Specialized = true;
        bool mGadgetHi110CompactCrt = true;
        bool mGadgetHi110Radix55Reduce = true;
        bool mGadgetHi110Pseudo55SecondFold = true;
        bool mGadgetHi110SparsePair = true;
        bool mGadgetGarner = false;
        std::uint32_t mNoGoldH200RootL2Mode = 3u;
        bool mFusedIp = false;
        bool mNoGoldH200InversePackedRoots = true;
        std::uint32_t mRootL2MiB = 8;
        std::uint32_t mRootL2HitPercent = 100;

        bool valid() const noexcept
        {
            return (mNoGoldH200InverseFp52Threads == 0u || mNoGoldH200InverseFp52Threads == 512u || mNoGoldH200InverseFp52Threads == 1024u) &&
                mNoGoldH200InverseFp52Schedule <= 5u &&
                (mNoGoldH200InverseFp52TwoTile == 0u || mNoGoldH200InverseFp52TwoTile == 1u || mNoGoldH200InverseFp52TwoTile == 2u || mNoGoldH200InverseFp52TwoTile == 4u || mNoGoldH200InverseFp52TwoTile == 8u) &&
                (mNoGoldH200InverseFp52TileCacheStage == 1u || mNoGoldH200InverseFp52TileCacheStage == 2u || mNoGoldH200InverseFp52TileCacheStage == 3u || mNoGoldH200InverseFp52TileCacheStage == 4u || mNoGoldH200InverseFp52TileCacheStage == 5u || mNoGoldH200InverseFp52TileCacheStage == 6u) &&
                mNoGoldH200InverseFp52Tile1024Mode <= 3u &&
                (mNoGoldH200InverseFp52TileMinBlocks == 0u || mNoGoldH200InverseFp52TileMinBlocks == 64u || mNoGoldH200InverseFp52TileMinBlocks == 128u || mNoGoldH200InverseFp52TileMinBlocks == 256u || mNoGoldH200InverseFp52TileMinBlocks == 4294967295u) &&
                mNoGoldH200InverseFp52PrefixSchedule <= 16u &&
                mNoGoldH200InverseFp52StaticOps <= 3u &&
                (mNttForwardThreads == 256u || mNttForwardThreads == 512u || mNttForwardThreads == 1024u) &&
                (mNttInverseThreads == 256u || mNttInverseThreads == 512u || mNttInverseThreads == 1024u) &&
                (mNttLog14H200InverseThreads == 512u || mNttLog14H200InverseThreads == 1024u) &&
                (mNttFusedIpThreads == 0u || mNttFusedIpThreads == 256u || mNttFusedIpThreads == 512u || mNttFusedIpThreads == 1024u) &&
                (mCt2PolySeedThreads == 32u || mCt2PolySeedThreads == 64u || mCt2PolySeedThreads == 128u) &&
                (mRootZetaSampleThreads == 128u || mRootZetaSampleThreads == 256u) &&
                (mNttLog13InverseThreads == 256u || mNttLog13InverseThreads == 512u || mNttLog13InverseThreads == 1024u) &&
                (mNoGoldDenoiseThreads == 128u || mNoGoldDenoiseThreads == 256u || mNoGoldDenoiseThreads == 512u) &&
                mNoGoldH200RootL2Mode <= 3u &&
                (mRootL2MiB == 1u || mRootL2MiB == 2u || mRootL2MiB == 4u || mRootL2MiB == 8u || mRootL2MiB == 12u || mRootL2MiB == 16u) &&
                (mRootL2HitPercent == 25u || mRootL2HitPercent == 50u || mRootL2HitPercent == 75u || mRootL2HitPercent == 100u);
        }
        bool operator==(const LogVoleGpuKernelOptions& other) const noexcept
        {
            return mNoGoldH200InverseOpTrace == other.mNoGoldH200InverseOpTrace &&
                mNttLog14H200 == other.mNttLog14H200 &&
                mNttLog14H200FixedTransforms == other.mNttLog14H200FixedTransforms &&
                mNoGoldH200CombinedAccumulator == other.mNoGoldH200CombinedAccumulator &&
                mNoGoldH200AccumulatorPseudo52 == other.mNoGoldH200AccumulatorPseudo52 &&
                mNoGoldH200InverseFp52Threads == other.mNoGoldH200InverseFp52Threads &&
                mNoGoldH200InverseFp52CacheRoots == other.mNoGoldH200InverseFp52CacheRoots &&
                mNoGoldH200InverseCachedSuffix == other.mNoGoldH200InverseCachedSuffix &&
                mNoGoldH200InverseFp52Schedule == other.mNoGoldH200InverseFp52Schedule &&
                mNoGoldH200InverseFp52TwoTile == other.mNoGoldH200InverseFp52TwoTile &&
                mNoGoldH200InverseFp52TileCacheStage == other.mNoGoldH200InverseFp52TileCacheStage &&
                mNoGoldH200InverseFp52Tile1024Mode == other.mNoGoldH200InverseFp52Tile1024Mode &&
                mNoGoldH200InverseFp52TileMinBlocks == other.mNoGoldH200InverseFp52TileMinBlocks &&
                mNoGoldH200InverseFp52PrefixSchedule == other.mNoGoldH200InverseFp52PrefixSchedule &&
                mNoGoldH200InverseFp52StaticOps == other.mNoGoldH200InverseFp52StaticOps &&
                mNoGoldH200Gadget208 == other.mNoGoldH200Gadget208 &&
                mNoGoldH200Gadget208Pseudo52 == other.mNoGoldH200Gadget208Pseudo52 &&
                mNttLog14H200InverseWarp05 == other.mNttLog14H200InverseWarp05 &&
                mNttLog14H200InverseDirectLoad == other.mNttLog14H200InverseDirectLoad &&
                mNttLog14H200InversePairedSuffix == other.mNttLog14H200InversePairedSuffix &&
                mNttLog14H200ForwardWarp712 == other.mNttLog14H200ForwardWarp712 &&
                mNttLog14H200ForwardPairedPrefix == other.mNttLog14H200ForwardPairedPrefix &&
                mNttLog14H200Centered == other.mNttLog14H200Centered &&
                mNttForwardThreads == other.mNttForwardThreads &&
                mNttInverseThreads == other.mNttInverseThreads &&
                mNttLog14H200InverseThreads == other.mNttLog14H200InverseThreads &&
                mNttFusedIpThreads == other.mNttFusedIpThreads &&
                mCt2PolySeedThreads == other.mCt2PolySeedThreads &&
                mCt2SplitAes == other.mCt2SplitAes &&
                mCt2AesSharedSbox == other.mCt2AesSharedSbox &&
                mScaleAndRoundShoup == other.mScaleAndRoundShoup &&
                mScaleAndRoundFastArithmetic == other.mScaleAndRoundFastArithmetic &&
                mScaleAndRoundHotRho4 == other.mScaleAndRoundHotRho4 &&
                mScaleAndRoundHotHiCarry == other.mScaleAndRoundHotHiCarry &&
                mScaleNttForwardGatherHiCarry == other.mScaleNttForwardGatherHiCarry &&
                mScaleNttForwardGatherSlotOwned == other.mScaleNttForwardGatherSlotOwned &&
                mNttLog13Specialized == other.mNttLog13Specialized &&
                mNttLog13SimpleIndex == other.mNttLog13SimpleIndex &&
                mNttLog13VectorShoupLoads == other.mNttLog13VectorShoupLoads &&
                mNttLog13ForwardFusedFirstStage == other.mNttLog13ForwardFusedFirstStage &&
                mNttLog13ForwardFusedLastTwoStages == other.mNttLog13ForwardFusedLastTwoStages &&
                mNttLog13ForwardWarpStages712 == other.mNttLog13ForwardWarpStages712 &&
                mNttLog13ForwardCenteredFromFusedLastTwoStages == other.mNttLog13ForwardCenteredFromFusedLastTwoStages &&
                mNttLog13ForwardPlainBroadcastFusedLastTwoStages == other.mNttLog13ForwardPlainBroadcastFusedLastTwoStages &&
                mNttLog13InverseFusedFirstStage == other.mNttLog13InverseFusedFirstStage &&
                mNttLog13InverseFusedLastTwoStages == other.mNttLog13InverseFusedLastTwoStages &&
                mNttLog13InverseFusedLastThreeStages == other.mNttLog13InverseFusedLastThreeStages &&
                mNttLog13InverseFusedLastThreeAddNegate == other.mNttLog13InverseFusedLastThreeAddNegate &&
                mNttLog13InversePostWarpStages05 == other.mNttLog13InversePostWarpStages05 &&
                mNttLog13InverseTreeFusedFirstStage == other.mNttLog13InverseTreeFusedFirstStage &&
                mNttLog13InverseTreeWarpStages == other.mNttLog13InverseTreeWarpStages &&
                mNttLog13InverseTreeProductWarpStages05 == other.mNttLog13InverseTreeProductWarpStages05 &&
                mNttLog13InverseTreeProductWarpVectorPairs == other.mNttLog13InverseTreeProductWarpVectorPairs &&
                mNttLog13DirectStore == other.mNttLog13DirectStore &&
                mNttCenteredDiagonalIdentity == other.mNttCenteredDiagonalIdentity &&
                mNttLog13InverseSpecialized == other.mNttLog13InverseSpecialized &&
                mNttLog13InverseDirectStore == other.mNttLog13InverseDirectStore &&
                mNttLog13InverseSmallDirect == other.mNttLog13InverseSmallDirect &&
                mNttLog13InverseScatterFixed == other.mNttLog13InverseScatterFixed &&
                mNttLog13InverseFixedIp == other.mNttLog13InverseFixedIp &&
                mFixedIpMuRowReuse == other.mFixedIpMuRowReuse &&
                mFixedIpWideMuRowReuse == other.mFixedIpWideMuRowReuse &&
                mPointwisePseudo55Reduce == other.mPointwisePseudo55Reduce &&
                mRootZetaSampleThreads == other.mRootZetaSampleThreads &&
                mNttLog13InverseThreads == other.mNttLog13InverseThreads &&
                mNttLog13InverseMinBlocks == other.mNttLog13InverseMinBlocks &&
                mExpandAccumulatorSpecialized == other.mExpandAccumulatorSpecialized &&
                mExpandAccumulatorQ64Complement == other.mExpandAccumulatorQ64Complement &&
                mExpandAccumulatorPseudo55 == other.mExpandAccumulatorPseudo55 &&
                mExpandAccumulatorGoldenPseudo55Dual == other.mExpandAccumulatorGoldenPseudo55Dual &&
                mExpandAccumulatorPseudo55Wide == other.mExpandAccumulatorPseudo55Wide &&
                mExpandAccumulatorPseudo55Dual == other.mExpandAccumulatorPseudo55Dual &&
                mExpandAccumulatorPseudo55DualPackedPairs == other.mExpandAccumulatorPseudo55DualPackedPairs &&
                mExpandAccumulatorTiled == other.mExpandAccumulatorTiled &&
                mDenoiseSpecialized == other.mDenoiseSpecialized &&
                mDenoiseShoup == other.mDenoiseShoup &&
                mDenoiseHotGeometry == other.mDenoiseHotGeometry &&
                mGoldenValidateShoup == other.mGoldenValidateShoup &&
                mDenoiseSpecializedRho8 == other.mDenoiseSpecializedRho8 &&
                mNoGoldDenoiseShoup == other.mNoGoldDenoiseShoup &&
                mNoGoldDenoiseUnroll == other.mNoGoldDenoiseUnroll &&
                mNoGoldDenoiseThreads == other.mNoGoldDenoiseThreads &&
                mGadgetHi110Specialized == other.mGadgetHi110Specialized &&
                mGadgetHi110CompactCrt == other.mGadgetHi110CompactCrt &&
                mGadgetHi110Radix55Reduce == other.mGadgetHi110Radix55Reduce &&
                mGadgetHi110Pseudo55SecondFold == other.mGadgetHi110Pseudo55SecondFold &&
                mGadgetHi110SparsePair == other.mGadgetHi110SparsePair &&
                mGadgetGarner == other.mGadgetGarner &&
                mNoGoldH200RootL2Mode == other.mNoGoldH200RootL2Mode &&
                mFusedIp == other.mFusedIp &&
                mNoGoldH200InversePackedRoots == other.mNoGoldH200InversePackedRoots &&
                mRootL2MiB == other.mRootL2MiB &&
                mRootL2HitPercent == other.mRootL2HitPercent;
        }
    };
}
