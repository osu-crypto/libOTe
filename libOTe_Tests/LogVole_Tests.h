#pragma once

#include <cryptoTools/Common/CLP.h>

#define LIBOTE_LOGVOLE_TESTS(X) \
    X(Encoding, KeyDeriveRequestRoundTrip) \
    X(Encoding, KeyDeriveResponseRoundTrip) \
    X(Encoding, ShrinkExpandOfflineRoundTrip) \
    X(Encoding, PolyMessageRoundTrip) \
    X(Encoding, MalformedPayloadRejected) \
    X(KeyDeriveCore, AlgebraicRelation) \
    X(KeyDeriveCore, MetadataMismatchRejected) \
    X(KeyDeriveCoproto, HappyPathAndAlgebraicRelation) \
    X(LencOps, EncShapeAndDeterminism) \
    X(LencOps, DigestDeterministic) \
    X(LencOps, EvalMatchesRmulDigestMinusSmulX) \
    X(LencOps, EvalRejectsMuMismatch) \
    X(RingOps, NttRoundTrip) \
    X(RingOps, GadgetDecomposeRecompose) \
    X(RingOps, GadgetDecomposeRecomposeBits) \
    X(RingOps, TensorPackUnpack) \
    X(ShrinkExpandCoproto, OfflineAndExpandDeterministicRelation) \
    X(ShrinkExpandCore, DenoiseCombExactness) \
    X(ShrinkExpandCore, DeterministicRelationExact) \
    X(ShrinkExpandCore, FullNoiseTolerance) \
    X(ShrinkExpandCore, OfflineMetadataMismatchRejected)

#define LIBOTE_LOGVOLE2_TESTS(X) \
    X(Encoding, KeyDeriveRequestRoundTrip) \
    X(Encoding, KeyDeriveResponseRoundTrip) \
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

#define LIBOTE_LOGVOLE2_DECLARE_TEST(suite, name) void LogVole2_##suite##_##name(const oc::CLP& cmd);
LIBOTE_LOGVOLE2_TESTS(LIBOTE_LOGVOLE2_DECLARE_TEST)
#undef LIBOTE_LOGVOLE2_DECLARE_TEST
