#pragma once
#include "libOTe/Vole/LogVole/LogVoleCpuRows.h"
#include "libOTe/Vole/LogVole/LogVoleCpuBenchmark.h"

#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include "cryptoTools/Crypto/PRNG.h"

#include "macoro/task.h"

#include <memory>
#include <span>
#include <vector>

namespace macoro { class thread_pool; }

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

    std::vector<RnsPoly> buildLencPublicBNtt(const RingNttContext& ctx, u32 tau, ProtocolCacheScopeView scope = currentProtocolCacheScope());

    std::shared_ptr<const std::vector<RnsPoly>> sharedLencPublicBNtt(
        const RingNttContext& ctx, u32 tau, ProtocolCacheScopeView scope = currentProtocolCacheScope());

    // Internal device-resident view of the same deterministic cached batch.
    // It is exact-role/run/device scoped and does not create a host snapshot.
    std::shared_ptr<const gpu::RetainedPublicUniform> retainedLencPublicBNtt(
        const RingNttContext& ctx, u32 tau, ProtocolCacheScopeView scope = currentProtocolCacheScope());

    bool prepareKeyDeriveRequest(
        const KeyDeriveReceiverInput& input,
        KeyDeriveRequest& out);

    bool processKeyDeriveRequest(
        const KeyDeriveSenderInput& input,
        const KeyDeriveRequest& request,
        KeyDeriveResponse& response,
        KeyDeriveSenderOutput& output, ProtocolCacheScopeView scope = currentProtocolCacheScope());

    bool finalizeKeyDeriveResponse(
        const KeyDeriveReceiverInput& input,
        const KeyDeriveResponse& response,
        KeyDeriveReceiverOutput& output, ProtocolCacheScopeView scope = currentProtocolCacheScope());

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

    macoro::task<bool> lencEncTrunc(
        macoro::thread_pool& executor, std::span<u8> setupResults,
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
        const LazySeedLabelHostState* seedLabelHost = nullptr,
        LogVoleGpuSetupOptions options = {}, CpuBenchmarkState cpuBenchmark = {}, ProtocolCacheScope setupScope = currentProtocolCacheScope());

    bool lencDigestTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        RnsPoly& out,
        u32 widthPadded = 0,
        bool leafInputsAreGadget = false);

    // One caller-owned pointer workspace per chunk. Reserve each vector for
    // 2 * lacct.mLevels * (tauHi + 1) pointers before use; no pool is retained.
    struct LencEvalBuffer
    {
        std::vector<const RnsPoly*> mCiphertexts, mNodes;
        bool mOk = true;
    };

    enum class LencEvalMode { Coefficient, Ntt, SubtractNtt };

    // CPU-only, lazy evaluation using a prepared tree and output batch.
    // out contains mu correctly sized polynomials; SubtractNtt additionally
    // requires canonical NTT coefficients. Other modes overwrite the values.
    // out must not alias ciphertext/tree storage. All referenced objects remain
    // alive and unchanged until completion, with exclusive output and buffers.
    // Unstarted tasks may be dropped; started tasks must finish before reuse.
    // One chunk executes inline. The caller may resume on an executor worker;
    // destroy/join the executor from outside its workers. Validation leaves out
    // unchanged; execution failure may leave partial output. Chunk pointer lists
    // are cleared on leaf exit, including exceptions, and retain their capacity.
    macoro::task<bool> lencEvalTrunc(
        macoro::thread_pool& executor, std::span<LencEvalBuffer> buffers,
        const RingNttContext& ctx, const LencLacct& lacct, const DigestTree& tree,
        u32 mu, u32 tauHi, u32 gadgetLogBase, u32 plaintextModulusBits,
        std::vector<RnsPoly>& out, LencEvalMode mode,
        bool leafInputsAreGadget = false, CpuBenchmarkState cpuBenchmark = {});

    [[deprecated("Use async LENC evaluation with explicit executor and buffers")]]
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
        bool leafInputsAreGadget = false, CpuBenchmarkState cpuBenchmark = {},
        detail::CpuRowScratch* cpuScratch = nullptr);

    [[deprecated("Use async LENC evaluation with explicit executor and buffers")]]
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
        bool leafInputsAreGadget = false, CpuBenchmarkState cpuBenchmark = {},
        detail::CpuRowScratch* cpuScratch = nullptr);

    // out -= Eval(tree) in the NTT domain, consuming each existing output row
    // as the path-product accumulator. out must contain mu canonical NTT
    // polynomials and must not alias the ciphertext or tree storage.
    [[deprecated("Use async lencEvalTrunc with LencEvalMode::SubtractNtt")]]
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
        bool leafInputsAreGadget = false, CpuBenchmarkState cpuBenchmark = {},
        detail::CpuRowScratch* cpuScratch = nullptr);
}
