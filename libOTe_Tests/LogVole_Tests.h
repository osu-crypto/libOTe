#pragma once

#include <cryptoTools/Common/CLP.h>

#define LIBOTE_LOGVOLE_TESTS(X) \
    X(Civole, RejectsZeroDelta) \
    X(Civole, ValidationAndSidReuse) \
    X(Civole, StateMachineAutoOfflineSequentialSids) \
    X(Core, WideU64OneShiftBounds) \
    X(Core, ZpRingLabelCountCeilNoOverflow) \
    X(Core, RootOnlineLocalRelation) \
    X(Core, TwoLevelCoprotoRelation) \
    X(Core, ThreeLevelOfflineReuseAndInvalidWidth) \
    X(Core, TwoLevelCoprotoMultiThreadSkipTbkOutput) \
    X(Encoding, AllMessageRoundTrips) \
    X(KeyDeriveCore, AlgebraicRelation) \
    X(KeyDeriveCore, DeterministicRegressionSeeds) \
    X(KeyDeriveCore, MetadataMismatchRejected) \
    X(KeyDeriveCoproto, HappyPathAndAlgebraicRelation) \
    X(Core, RepOfflineSenderInputGammaTauUnbundlesResidues) \
    X(Core, RecursiveLiftOracleKeepsSenderResiduesUnscaled) \
    X(LheOps, PublicADeterministic) \
    X(LheOps, Enc1ShapeDeterminismAndColumnDecrypt) \
    X(LheOps, ApplyCt1AndDeriveSkxRelations) \
    X(LheOps, HashedCt2Deterministic) \
    X(LencOps, EncShapeAndDeterminism) \
    X(LencOps, DigestTreeDeterministic) \
    X(LencOps, EvalMatchesRmulDigestMinusSmulX) \
    X(LencOps, TruncEvalFromPrebuiltTreeMatchesEvalFromX) \
    X(LencOps, TruncLeafInputsAreGadgetPath) \
    X(RingOps, NttRoundTrip) \
    X(RingOps, GadgetDecomposeRecomposeBits) \
    X(RingOps, CenteredGadgetDecomposeRecomposeBits) \
    X(ShrinkExpandCoproto, OfflineAndExpandDeterministicRelation) \
    X(ShrinkExpandCoproto, FullNoiseTolerance) \
    X(ShrinkExpandCore, ParamsValidation) \
    X(ShrinkExpandCore, DeterministicRelationExact) \
    X(ShrinkExpandCore, TruncDeterministicRelationBounded) \
    X(ShrinkExpandCore, FullNoiseTolerance)

#define LIBOTE_LOGVOLE_EXTENDED_TESTS(X) \
    X(Core, ModeSelection) \
    X(Core, RuntimeCacheScopePropagatesToParallelWorkers) \
    X(Core, SeedLabelAggSumsTauBlocks) \
    X(Core, GdecompHiUnbundleLiftsOneLimbPerOutput) \
    X(Core, RepOfflineSenderInputGammaOneRepeats) \
    X(Core, SeedLabelSampleCt2FromSeedDeterministic) \
    X(Core, SeedLabelDenoiseMatchesShrinkExpandComb) \
    X(Core, RootTruncParamsAndKeyReplication) \
    X(Core, RootScaledNttAddMatchesCoeffDomain) \
    X(Core, RootTopCtNoiselessRelation) \
    X(Core, RootZetaShapeAndBounds) \
    X(Core, RootInnerProductMatchesCoeffDomain) \
    X(Core, RootOfflineSetupFinalizeShapes) \
    X(Core, RootRandomizerWidthTracksGadgetBase) \
    X(Core, RootOfflineRejectsMetadataMismatch) \
    X(Core, RootOnlineLocalFlow) \
    X(Core, TwoLevelLocalApiRelation) \
    X(Core, RecursiveGadgetInputSubproblem) \
    X(Core, RejectsWidthsBelowRandomizedRootBlock) \
    X(Core, GoldenSeedSearchAcceptsFeasibleParams) \
    X(Core, GoldenSeedRejectsMalformedCandidate) \
    X(Core, GoldenSeedFindAndValidateCandidate) \
    X(LencOps, EvalFromPrebuiltTreeMatchesEvalFromX) \
    X(LencOps, EvalRejectsMuMismatch) \
    X(LencOps, TruncEncShapeAndDeterminism) \
    X(LencOps, TruncDigestTreeDeterministic) \
    X(LencOps, TruncEvalRejectsMuMismatch) \
    X(KeyDeriveCoproto, DeterministicRegressionSeeds) \
    X(RingOps, GadgetDecomposeRecompose) \
    X(RingOps, GadgetDecomposeBitsRangeMatchesSlice) \
    X(RingOps, TensorPackUnpack) \
    X(RingOps, NonceBatchDeterminism) \
    X(ShrinkExpandCoproto, TruncOfflineAndExpandBoundedRelation) \
    X(ShrinkExpandCoproto, OfflineStateReuseAcrossQueries) \
    X(ShrinkExpandCore, OfflineStateShapes) \
    X(ShrinkExpandCore, OfflineMetadataMismatchRejected) \
    X(ShrinkExpandCore, DenoiseCombExactness)

#define LIBOTE_LOGVOLE_DECLARE_TEST(suite, name) void LogVole_##suite##_##name(const oc::CLP& cmd);
LIBOTE_LOGVOLE_TESTS(LIBOTE_LOGVOLE_DECLARE_TEST)
LIBOTE_LOGVOLE_EXTENDED_TESTS(LIBOTE_LOGVOLE_DECLARE_TEST)
#undef LIBOTE_LOGVOLE_DECLARE_TEST
