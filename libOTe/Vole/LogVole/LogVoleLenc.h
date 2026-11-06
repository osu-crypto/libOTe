#pragma once

#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <memory>
#include <span>
#include <vector>

namespace osuCrypto::LogVole
{
    // Both layers use the same immutable ciphertext representation. Keeping one
    // type lets evaluation borrow the offline tensor instead of copying every
    // polynomial at every online chunk.
    using LencLacct = ShrinkExpandLacct;

    struct LencEncodeOutput
    {
        std::vector<RnsPoly> mR;
        std::vector<RnsPoly> mRNtt;
        LencLacct mLacct;
        // Internal GPU setup may retain ciphertext coefficients on device.
        // mLacct keeps its shape; public/default calls return eager host data.
        std::shared_ptr<const LazyRingTensorHostState> mLazyCt;
        std::shared_ptr<const LazyLencRandomizerState> mLazyRandomizers;
    };

    struct KeyDeriveRequest
    {
        u32 mPolyModulusDegree = 0;
        u32 mCoeffModulusCount = 0;
        u32 mTau = 0;
        AlignedUnVec<u64> mDCoeffs;
    };

    struct KeyDeriveResponse
    {
        u32 mPolyModulusDegree = 0;
        u32 mCoeffModulusCount = 0;
        u32 mTau = 0;
        AlignedUnVec<u64> mMNttCoeffs;
    };

    struct KeyDeriveSenderInput
    {
        RingParams mParams;
        std::vector<RnsPoly> mSk1;
        std::vector<RnsPoly> mSk2;
    };

    struct KeyDeriveReceiverInput
    {
        RingParams mParams;
        std::vector<RnsPoly> mD;
    };

    struct KeyDeriveSenderOutput
    {
        std::vector<RnsPoly> mK;
    };

    struct KeyDeriveReceiverOutput
    {
        std::vector<RnsPoly> mM;
    };

    struct DigestTree
    {
        u32 mWidthPadded = 0;
        u32 mLevels = 0;
        RnsPoly mDigest;
        std::vector<std::vector<RnsPoly>> mNodeDecompNtt;
    };

    std::vector<RnsPoly> buildLencPublicBNtt(const RingNttContext& ctx, u32 tau);

    std::shared_ptr<const std::vector<RnsPoly>> sharedLencPublicBNtt(
        const RingNttContext& ctx, u32 tau);

    // Internal device-resident view of the same deterministic cached batch.
    // It is exact-role/run/device scoped and does not create a host snapshot.
    std::shared_ptr<const gpu::RetainedPublicUniform> retainedLencPublicBNtt(
        const RingNttContext& ctx, u32 tau);

    bool prepareKeyDeriveRequest(
        const KeyDeriveReceiverInput& input,
        KeyDeriveRequest& out);

    bool processKeyDeriveRequest(
        const KeyDeriveSenderInput& input,
        const KeyDeriveRequest& request,
        KeyDeriveResponse& response,
        KeyDeriveSenderOutput& output);

    bool finalizeKeyDeriveResponse(
        const KeyDeriveReceiverInput& input,
        const KeyDeriveResponse& response,
        KeyDeriveReceiverOutput& output);

    // Tree widths are powers of two and at least two. Automatic padding adds
    // a zero leaf for a singleton; an explicit width below two is rejected.
    // The same convention applies to full/truncated encoding and digests.
    bool buildDigestTree(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tau,
        u32 gadgetLogBase,
        DigestTree& out,
        u32 requestedWidthPadded = 0,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1);

    bool buildDigestTree(
        const RingNttContext& ctx,
        std::span<const RnsPoly> x,
        u32 tau,
        u32 gadgetLogBase,
        DigestTree& out,
        u32 requestedWidthPadded = 0,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1);

    bool lencEnc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& s,
        u32 tau,
        u32 gadgetLogBase,
        PRNG& prng,
        LencEncodeOutput& out,
        double noiseStandardDeviation = 0.0,
        double noiseMaxDeviation = 0.0,
        u32 requestedWidthPadded = 0,
        bool emitRCoeffDomain = true,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1,
        bool deferCiphertextHost = false);

    bool lencDigest(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tau,
        u32 gadgetLogBase,
        RnsPoly& out,
        u32 widthPadded = 0);

    bool lencEval(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const std::vector<RnsPoly>& x,
        u32 mu,
        u32 tau,
        u32 gadgetLogBase,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1);

    bool lencEval(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const DigestTree& tree,
        u32 mu,
        u32 tau,
        u32 gadgetLogBase,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1);

    bool buildDigestTreeTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        DigestTree& out,
        u32 requestedWidthPadded = 0,
        bool leafInputsAreGadget = false,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1);

    bool buildDigestTreeTrunc(
        const RingNttContext& ctx,
        std::span<const RnsPoly> x,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        DigestTree& out,
        u32 requestedWidthPadded = 0,
        bool leafInputsAreGadget = false,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1);

    bool lencEncTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& s,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        PRNG& prng,
        LencEncodeOutput& out,
        double noiseStandardDeviation = 0.0,
        double noiseMaxDeviation = 0.0,
        u32 requestedWidthPadded = 0,
        bool emitRCoeffDomain = true,
        bool leafInputsAreGadget = false,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1,
        bool deferCiphertextHost = false,
        bool deferRandomizerHost = false,
        const gpu::DeviceBatch* seedLabelDevice = nullptr,
        const LazySeedLabelHostState* seedLabelHost = nullptr);

    bool lencDigestTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        RnsPoly& out,
        u32 widthPadded = 0,
        bool leafInputsAreGadget = false);

    bool lencEvalTrunc(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const std::vector<RnsPoly>& x,
        u32 mu,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1,
        bool leafInputsAreGadget = false);

    bool lencEvalTrunc(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const DigestTree& tree,
        u32 mu,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1,
        bool leafInputsAreGadget = false);

    // out -= Eval(tree) in the NTT domain, consuming each existing output row
    // as the path-product accumulator. out must contain mu canonical NTT
    // polynomials and must not alias the ciphertext or tree storage.
    bool lencSubtractEvalTruncNttInplace(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const DigestTree& tree,
        u32 mu,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1,
        bool leafInputsAreGadget = false);
}
