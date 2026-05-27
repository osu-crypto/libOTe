#pragma once

#include <cryptoTools/Common/CLP.h>

#define LIBOTE_LOGVOLE_TESTS(X) \
    X(CommCounters, ExactByteAndBitAccounting) \
    X(CommInMemory, PingPongHappyPath) \
    X(CommTcp, PingPongOverLoopbackTcp) \
    X(CommUds, PingPongOverUnixDomainSocket) \
    X(CommValidation, PayloadTypeMismatchFails) \
    X(CommValidation, WrongRoundIndexFails) \
    X(KeyderiveProtocol, HappyPathAndAlgebraicRelation) \
    X(KeyderiveProtocol, DeterministicRegressionSeeds) \
    X(KeyderiveValidation, PayloadTypeMismatchFails) \
    X(KeyderiveValidation, MalformedPayloadFails) \
    X(KeyderiveValidation, VersionMismatchFails) \
    X(KeyderiveValidation, SessionMismatchFails) \
    X(LencOps, EncShapeAndDeterminism) \
    X(LencOps, DigestDeterministic) \
    X(LencOps, EvalMatchesRmulDigestMinusSmulX) \
    X(LencOps, EvalRejectsMuMismatch) \
    X(RingOps, NttRoundTrip) \
    X(RingOps, GadgetDecomposeRecompose) \
    X(RingOps, GadgetDecomposeRecomposeBits) \
    X(RingOps, TensorPackUnpack) \
    X(RoundDslCompile, ScriptShapeAndHandlersCompile) \
    X(ShrinkExpandOps, DenoiseCombExactness) \
    X(ShrinkExpandOffline, HappyPathAndCounters) \
    X(ShrinkExpandOnline, DeterministicRelationExact) \
    X(ShrinkExpandOnline, FullNoiseTolerance) \
    X(ShrinkExpandOnline, OfflineStateReuseAcrossQueries) \
    X(ShrinkExpandValidation, PayloadTypeMismatchRejected) \
    X(ShrinkExpandValidation, MalformedPayloadRejected) \
    X(ShrinkExpandValidation, VersionMismatchRejected) \
    X(ShrinkExpandValidation, SessionMismatchRejected) \
    X(ShrinkExpandValidation, RingMetadataMismatchRejected)

#define LIBOTE_LOGVOLE_DECLARE_TEST(suite, name) void LogVole_##suite##_##name(const oc::CLP& cmd);
LIBOTE_LOGVOLE_TESTS(LIBOTE_LOGVOLE_DECLARE_TEST)
#undef LIBOTE_LOGVOLE_DECLARE_TEST
