#pragma once

#include <cryptoTools/Common/CLP.h>

#define LIBOTE_LOGVOLE_TESTS(X) \
    X(Civole, RejectsZeroDelta) \
    X(Civole, ValidationAndSidReuse) \
    X(Civole, StateMachineAutoOfflineSequentialSids) \
    X(Core, RootOnlineLocalRelation) \
    X(Core, TwoLevelCoprotoRelation) \
    X(Core, ThreeLevelOfflineReuseAndInvalidWidth) \
    X(Core, TwoLevelCoprotoMultiThreadSkipTbkOutput) \
    X(Encoding, AllMessageRoundTrips) \
    X(KeyDeriveCore, AlgebraicRelation) \
    X(KeyDeriveCore, DeterministicRegressionSeeds) \
    X(KeyDeriveCore, MetadataMismatchRejected) \
    X(KeyDeriveCoproto, HappyPathAndAlgebraicRelation) \
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

#define LIBOTE_LOGVOLE_DECLARE_TEST(suite, name) void LogVole_##suite##_##name(const oc::CLP& cmd);
LIBOTE_LOGVOLE_TESTS(LIBOTE_LOGVOLE_DECLARE_TEST)
#undef LIBOTE_LOGVOLE_DECLARE_TEST
