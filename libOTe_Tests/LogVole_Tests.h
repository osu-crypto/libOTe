#pragma once

#include <cryptoTools/Common/CLP.h>

#define LIBOTE_LOGVOLE_TESTS(X) \
    X(Civole, RejectsZeroDelta) \
    X(Civole, ValidationAndSidReuse) \
    X(Civole, StateMachineAutoOfflineSequentialSids) \
    X(Core, ModeSelection) \
    X(Core, RuntimeCacheScopePropagatesToParallelWorkers) \
    X(Core, SeedLabelAggSumsTauBlocks) \
    X(Core, GdecompHiUnbundleLiftsOneLimbPerOutput) \
    X(Core, RepOfflineSenderInputGammaOneRepeats) \
    X(Core, RepOfflineSenderInputGammaTauUnbundlesLimbs) \
    X(Core, SeedLabelSampleCt2FromSeedDeterministic) \
    X(Core, SeedLabelDenoiseMatchesShrinkExpandComb) \
    X(Core, RootTruncParamsAndKeyReplication) \
    X(Core, RootScaledNttAddMatchesCoeffDomain) \
    X(Core, RootTopCtNoiselessRelation) \
    X(Core, RootZetaShapeAndBounds) \
    X(Core, RootInnerProductMatchesCoeffDomain) \
    X(Core, RootOfflineSetupFinalizeShapes) \
    X(Core, RootOfflineRejectsMetadataMismatch) \
    X(Core, RootOnlineLocalFlow) \
    X(Core, RootOnlineLocalRelation) \
    X(Core, TwoLevelLocalApiRelation) \
    X(Core, ThreeLevelOfflineMessageAndReuse) \
    X(Core, RecursiveGadgetInputSubproblem) \
    X(Core, RejectsWidthsBelowRandomizedRootBlock) \
    X(Core, TwoLevelCoprotoRelation) \
    X(Core, TwoLevelCoprotoMultiThreadSkipTbkOutput) \
    X(Core, GoldenSeedSearchAcceptsFeasibleParams) \
    X(Core, GoldenSeedFindAndValidateCandidate) \
    X(Encoding, KeyDeriveRequestRoundTrip) \
    X(Encoding, KeyDeriveResponseRoundTrip) \
    X(Encoding, SeedMessageRoundTrip) \
    X(Encoding, RootOfflineMessageRoundTrip) \
    X(Encoding, RootDigestAndResponseRoundTrip) \
    X(KeyDeriveCore, AlgebraicRelation) \
    X(KeyDeriveCore, DeterministicRegressionSeeds) \
    X(KeyDeriveCore, MetadataMismatchRejected) \
    X(KeyDeriveCoproto, HappyPathAndAlgebraicRelation) \
    X(KeyDeriveCoproto, DeterministicRegressionSeeds) \
    X(LheOps, PublicADeterministic) \
    X(LheOps, Enc1ShapeDeterminismAndColumnDecrypt) \
    X(LheOps, ApplyCt1AndDeriveSkxRelation) \
    X(LheOps, TruncApplyCt1AndDeriveSkxRelation) \
    X(LheOps, HashedCt2Deterministic) \
    X(LencOps, EncShapeAndDeterminism) \
    X(LencOps, DigestTreeDeterministic) \
    X(LencOps, EvalMatchesRmulDigestMinusSmulX) \
    X(LencOps, EvalFromPrebuiltTreeMatchesEvalFromX) \
    X(LencOps, EvalRejectsMuMismatch) \
    X(LencOps, TruncEncShapeAndDeterminism) \
    X(LencOps, TruncDigestTreeDeterministic) \
    X(LencOps, TruncEvalFromPrebuiltTreeMatchesEvalFromX) \
    X(LencOps, TruncEvalRejectsMuMismatch) \
    X(LencOps, TruncLeafInputsAreGadgetPath) \
    X(RingOps, NttRoundTrip) \
    X(RingOps, GadgetDecomposeRecompose) \
    X(RingOps, GadgetDecomposeRecomposeBits) \
    X(RingOps, GadgetDecomposeBitsRangeMatchesSlice) \
    X(RingOps, CenteredGadgetDecomposeRecomposeBits) \
    X(RingOps, TensorPackUnpack) \
    X(RingOps, NonceBatchDeterminism) \
    X(ShrinkExpandCoproto, OfflineAndExpandDeterministicRelation) \
    X(ShrinkExpandCoproto, TruncOfflineAndExpandBoundedRelation) \
    X(ShrinkExpandCoproto, FullNoiseTolerance) \
    X(ShrinkExpandCoproto, OfflineStateReuseAcrossQueries) \
    X(ShrinkExpandCore, ParamsValidation) \
    X(ShrinkExpandCore, OfflineStateShapes) \
    X(ShrinkExpandCore, DeterministicRelationExact) \
    X(ShrinkExpandCore, TruncDeterministicRelationBounded) \
    X(ShrinkExpandCore, OfflineMetadataMismatchRejected) \
    X(ShrinkExpandCore, DenoiseCombExactness) \
    X(ShrinkExpandCore, FullNoiseTolerance)

#define LIBOTE_LOGVOLE_DECLARE_TEST(suite, name) void LogVole_##suite##_##name(const oc::CLP& cmd);
LIBOTE_LOGVOLE_TESTS(LIBOTE_LOGVOLE_DECLARE_TEST)
#undef LIBOTE_LOGVOLE_DECLARE_TEST
