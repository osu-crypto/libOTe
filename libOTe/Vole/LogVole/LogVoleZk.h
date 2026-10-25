#pragma once

// VOLE-based zero-knowledge proofs on top of the LogVole chosen-input VOLE.
//
// CI-VOLE hands the prover, for a vector x that the prover picks itself, MACs
//
//     M[i] = K[i] + x[i] * Delta   (mod p)
//
// with the verifier holding the keys K and the scalar Delta. That is an
// information-theoretic commitment to every entry of x, and it is *linearly*
// homomorphic for free: for public coefficients c, both parties can form the
// commitment to sum_i c_i x[i] locally, without talking. The chosen-input part
// is what makes it useful as a ZK commitment - with a random VOLE the prover
// would have to send a derandomisation vector as long as x, which is the linear
// message LogVole exists to remove.
//
// This file adds the one thing linear homomorphism does not give - a check that
// one committed value is the product of two others - in the QuickSilver / LPZK
// shape, and then builds two statements on it:
//
//   ZkMulCircuit : a layered arithmetic circuit of multiplication gates. This is
//                  the "ZK multiplication gates/s" metric.
//   ZkMatMul     : C = A * B for private n x n matrices A, B and public C,
//                  checking all n^2 length-n inner products directly.
//
// == The multiplication check ==
//
// For a gate with committed operands x, y and committed output z, write the
// prover's MACs as M[.] and the verifier's keys as K[.] = M[.] - (.) * Delta.
// The prover forms
//
//     A0 = M[x] * M[y]
//     A1 = M[z] - x * M[y] - y * M[x]
//
// and the verifier forms
//
//     B  = K[x] * K[y] + K[z] * Delta.
//
// Substituting K = M - (.)*Delta gives
//
//     B = A0 + A1 * Delta + (x*y - z) * Delta^2,
//
// so B == A0 + A1 * Delta exactly when z = x*y, and a prover who cheats on the
// gate has to predict Delta^2 to keep the identity. Neither party needs the
// other's share to compute its own side, so the whole check is local.
//
// All gates are batched into one identity with a verifier-chosen challenge chi:
// the prover sends U = sum_g chi^(g+1) A0_g and V = sum_g chi^(g+1) A1_g, and
// the verifier tests sum_g chi^(g+1) B_g == U + V * Delta. A dishonest gate
// survives only if a degree-|gates| polynomial in chi vanishes at the challenge,
// i.e. with probability |gates| / p.
//
// Zero knowledge needs U and V masked, because A0 alone would leak. One extra
// authenticated random value r does it: with A0* = M[r] and A1* = -r the
// verifier's matching side is B* = M[r] - r*Delta = K[r], which it already
// knows. So the prover sends U + M[r] and V - r and the verifier adds K[r] to
// its sum. That is one extra VOLE entry per proof, and it is why every
// statement here reserves a trailing "mask" slot in its wire vector.
//
// == Bit-exactness ==
//
// Sums of products modulo p are order independent as long as every partial sum
// is reduced, so the multi-threaded host path, the single-threaded host path and
// the GPU tree reductions all produce the *same* U, V and B. The benchmark
// checks that equality rather than only checking that the proof verifies.

#include "libOTe/config.h"

#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleTypes.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <memory>
#include <span>
#include <vector>

namespace osuCrypto::LogVole
{
    // The prover's response, and the only thing that travels per proof.
    struct ZkProof
    {
        u64 mU = 0;
        u64 mV = 0;
    };

    // ---- multiplication-gate circuit -------------------------------------
    //
    // A layered circuit: layer 0 is mWidth committed input wires, and each of
    // the mDepth following layers is mWidth multiplication gates whose two
    // operands are wires of the layer below. Wire l*mWidth + j belongs to layer
    // l, so gate g in [0, gateCount) owns output wire mWidth + g - the output
    // wires are contiguous, which is what lets the check read them as a stream
    // and keeps only the two operand gathers irregular.
    //
    // Layers exist for one reason: the prover has to evaluate the circuit to
    // know its own witness, and a layered shape makes that evaluation
    // mWidth-parallel instead of a serial chain of gateCount dependencies. The
    // proof itself does not care about the shape at all.
    struct ZkMulCircuit
    {
        u64 mWidth = 0;
        u64 mDepth = 0;

        // 2 * gateCount absolute wire indices; gate g reads mOperands[2g] and
        // mOperands[2g + 1], both in layer (g / mWidth).
        AlignedUnVec<u32> mOperands;

        // Optional party-owned device copy of mOperands (see
        // zkMulUploadOperands). Copies made inside one party may share this
        // immutable allocation. Separate parties must construct separate
        // handles, even when their public wiring bytes are identical.
        std::shared_ptr<void> mOperandsDevice;

        u64 gateCount() const { return mWidth * mDepth; }
        u64 wireCount() const { return mWidth * (mDepth + 1); }

        // Wire vector layout handed to the VOLE: every wire, then the ZK mask.
        u64 voleCount() const { return wireCount() + 1; }
        u64 maskIndex() const { return wireCount(); }
        u64 outputWire(u64 gate) const { return mWidth + gate; }
    };

    // Wiring is public, so it is drawn from a seed both parties can hold. Each
    // gate picks two uniform wires from the layer below.
    bool makeZkMulCircuit(u64 gateCount, u64 depth, block seed, ZkMulCircuit& out);

    // The CI-VOLE request size to ask for when `voleCount` values need
    // committing.
    //
    // This rounds up to a power of two, and the reason is a shape limitation in
    // the CUDA backend rather than anything about the proof. A request of `m`
    // scalars becomes w = ceil(m / N) ring labels, and the recursion takes
    // w -> ceil(w / muHi) * tauHi * rho at each level. When that chain reaches an
    // interior level whose width is not a whole number of chunks, the GPU path
    // diverges from the CPU path: the golden-seed search then never accepts (it
    // is validating against a tbk the receiver did not produce) and the
    // no-golden-seed setting hangs. Reproduce with
    //     frontend_libOTe -lvbench -n 163840 -gpu 1    # w = 20, fails
    //     frontend_libOTe -lvbench -n 163840 -gpu 0    # w = 20, fine
    // A power-of-two request keeps every level a whole number of chunks, which
    // is also why the existing -lvbench numbers are all powers of two.
    //
    // The padding is not free - it is VOLE work on values the statement does not
    // use - so callers that can pick their own statement size should use
    // makeZkMulCircuitForBudget and fill the request instead.
    u64 zkVoleRequestSize(u64 voleCount);

    // The largest layered circuit of the given depth whose committed values fit
    // in `voleBudget` (which should be a zkVoleRequestSize value). This is how a
    // multiplication-gate benchmark avoids paying for padding.
    bool makeZkMulCircuitForBudget(u64 voleBudget, u64 depth, block seed, ZkMulCircuit& out);

    // Evaluate the circuit from random inputs, so the witness actually satisfies
    // every gate, and draw the ZK mask into the trailing slot. This is the
    // prover's own computation, not part of the proof.
    //
    // `voleSize` (0 = circuit.voleCount()) sizes the output for a padded request;
    // the slack is zeroed and never read by the check.
    bool zkMulWitness(
        const ZkMulCircuit& circuit, u64 modulus, PRNG& prng, AlignedUnVec<u64>& wires,
        u64 voleSize = 0);

    // Evaluate each independent layer with a bounded worker count. Random
    // input/mask draws retain the sequential API's exact PRNG consumption.
    bool zkMulWitness(
        const ZkMulCircuit& circuit, u64 modulus, PRNG& prng, AlignedUnVec<u64>& wires,
        u64 voleSize, u32 threads);

    // U = sum_g chi^(g+1) * M[x_g] * M[y_g]                      + M[r]
    // V = sum_g chi^(g+1) * (M[z_g] - x_g*M[y_g] - y_g*M[x_g])    - r
    bool zkMulProverResponse(
        const ZkMulCircuit& circuit,
        std::span<const u64> wires,
        std::span<const u64> macs,
        u64 chi,
        u64 modulus,
        u32 threads,
        ZkProof& out);

    // B = sum_g chi^(g+1) * (K[x_g]*K[y_g] + K[z_g]*Delta) + K[r]
    bool zkMulVerifierValue(
        const ZkMulCircuit& circuit,
        std::span<const u64> keys,
        u64 chi,
        u64 delta,
        u64 modulus,
        u32 threads,
        u64& out);

    // ---- matrix multiplication ------------------------------------------
    //
    // For every (i,j), check sum_k A[i,k]*B[k,j] = C[i,j], where C is the
    // application's public product. The verifier must supply C explicitly.
    // A and B are authenticated; C is public and needs no VOLE entries.
    // Each repetition batches the n^2 inner-product equations with an independent
    // coefficient for every entry. The CPU computes the unweighted inner
    // products once, using O(n^3 + repetitions*n^2) work. CUDA currently uses
    // O(repetitions*n^3) work. Challenge storage is O(repetitions*n^2).
    // There is no matrix projection.
    //
    // The residual batching error is at most (1/p)^repetitions for a fixed
    // nonzero product error. Each equation has a fresh authenticated mask and is
    // checked separately. All equations share the base-field Delta, so total
    // authentication soundness remains O(1/p). The VOLE threat model is unchanged.
    struct ZkMatMulStatement
    {
        u64 mDim = 0;
        u32 mReps = 1;

        u32 repetitions() const { return mReps ? mReps : 1u; }
        u64 entries() const { return mDim * mDim; }
        // A, then B, then one independent mask per repetition.
        // Validate the statement before using these size calculations.
        u64 voleCount() const { return 2 * entries() + repetitions(); }
        u64 offsetA() const { return 0; }
        u64 offsetB() const { return entries(); }
        u64 maskIndex(u32 repetition = 0) const { return 2 * entries() + repetition; }
    };

    bool validateZkMatMulStatement(const ZkMatMulStatement& st);

    // Random A and B plus independent ZK masks.
    bool zkMatMulWitnessInputs(
        const ZkMatMulStatement& st, u64 modulus, PRNG& prng, AlignedUnVec<u64>& wires,
        u64 voleSize = 0);

    // Construct the public product C = A*B mod p separately from the private
    // witness. Honest statement preparation is excluded from proof timing.
    bool zkMatMulFillProduct(
        const ZkMatMulStatement& st, u64 modulus, u32 threads,
        std::span<const u64> wires, AlignedUnVec<u64>& publicProduct);

    // Both of the above.
    bool zkMatMulWitness(
        const ZkMatMulStatement& st, u64 modulus, u32 threads, PRNG& prng,
        AlignedUnVec<u64>& wires, AlignedUnVec<u64>& publicProduct, u64 voleSize = 0);

    // Independent, uniform field coefficients for every output entry and
    // repetition, expanded from one 16-byte verifier seed after authentication.
    struct ZkMatMulChallenge
    {
        // repetitions() * entries() entries, including possible zero values.
        AlignedUnVec<u64> mCoefficients;
    };

    void zkMatMulChallenge(
        const ZkMatMulStatement& st, block seed, u64 modulus, ZkMatMulChallenge& out);

    // Batching scalar for the multiplication-gate statement.
    u64 zkChallengeScalar(block seed, u64 modulus);

    // Square-and-multiply modular exponentiation, exposed because both the host
    // and the device check paths need the same challenge powers.
    u64 zkPowMod(u64 base, u64 exp, u64 modulus);

    bool zkMatMulProverResponse(
        const ZkMatMulStatement& st,
        std::span<const u64> wires,
        std::span<const u64> macs,
        const ZkMatMulChallenge& ch,
        u64 modulus,
        u32 threads,
        ZkProof& out);

    // Repeated matrix checks retain every equation. The scalar overloads above
    // and below reject statements with more than one repetition.
    bool zkMatMulProverResponse(
        const ZkMatMulStatement& st,
        std::span<const u64> wires,
        std::span<const u64> macs,
        const ZkMatMulChallenge& ch,
        u64 modulus,
        u32 threads,
        std::vector<ZkProof>& out);

    bool zkMatMulVerifierValue(
        const ZkMatMulStatement& st,
        std::span<const u64> keys,
        std::span<const u64> publicProduct,
        const ZkMatMulChallenge& ch,
        u64 delta,
        u64 modulus,
        u32 threads,
        u64& out);

    bool zkMatMulVerifierValue(
        const ZkMatMulStatement& st,
        std::span<const u64> keys,
        std::span<const u64> publicProduct,
        const ZkMatMulChallenge& ch,
        u64 delta,
        u64 modulus,
        u32 threads,
        std::vector<u64>& out);

    bool zkMatMulAccept(std::span<const ZkProof> proofs, std::span<const u64> values,
        u64 delta, u64 modulus);

    // The verifier's final test, shared by both statements.
    bool zkAccept(const ZkProof& proof, u64 verifierValue, u64 delta, u64 modulus);
}

#if defined(ENABLE_LOGVOLE_CUDA)
namespace osuCrypto::LogVole::gpu
{
    // Declared in cuda/LogVoleGpuProtocol.h.
    class DeviceScalars;
    using DeviceScalarsPtr = std::shared_ptr<DeviceScalars>;
    struct HostModulus;

    // Synchronous exact descriptor generation, cached by device, party role,
    // and actual modulus. The output is unchanged on failure.
    bool prepareZkModulusDevice(u64 modulus, HostModulus& out);
    // Performs the final acceptance equation on the GPU. A successful call
    // may report accepted=false; execution failure leaves accepted unchanged.
    bool zkAcceptDevice(const ZkProof& proof, u64 verifierValue, u64 delta,
        u64 modulus, bool& accepted);
    struct ZkMulDeviceState;
    std::shared_ptr<ZkMulDeviceState> makeZkMulDeviceState(const ZkMulCircuit& circuit);
    bool zkMulProverResponseDevice(const ZkMulCircuit& circuit,
        const DeviceScalars& wires, const DeviceScalars& macs, u64 chi, u64 modulus,
        ZkMulDeviceState& state, ZkProof& out);
    bool zkMulVerifierValueDevice(const ZkMulCircuit& circuit,
        const DeviceScalars& keys, u64 chi, u64 delta, u64 modulus,
        ZkMulDeviceState& state, u64& out);

    // Exact fresh PRNG(seed) A/B inputs and masks, with zero request padding.
    DeviceScalarsPtr zkMatMulWitnessInputsDevice(
        const ZkMatMulStatement& st, u64 modulus, block seed, u64 voleSize = 0);

    // Construct the public product in a separate device allocation.
    bool zkMatMulFillProductDevice(
        const DeviceScalars& wires, const ZkMatMulStatement& st, u64 modulus,
        DeviceScalars& publicProduct);

    // Uploads the circuit's wiring once and stores the handle in
    // circuit.mOperandsDevice, so internal copies owned by the same party can
    // reuse one device allocation. A separate party must generate or upload
    // its own copy. Optional: a device state that finds no handle uploads its own.
    bool zkMulUploadOperands(ZkMulCircuit& circuit);

    // Replace a device handle with an independent device allocation containing
    // identical public wiring. Host bytes and the input remain unchanged on
    // failure. This is local ownership detachment, not a transport operation.
    bool zkMulDetachOperands(ZkMulCircuit& circuit);

    // Exact seeded wiring generated on the GPU. The public host vector remains
    // empty until explicitly materialized; copies within that party may share
    // immutable device wiring.
    bool makeZkMulCircuitForBudgetDevice(
        u64 voleBudget, u64 depth, block seed, ZkMulCircuit& out);
    bool zkMulMaterializeOperands(ZkMulCircuit& circuit);

    // The prover's circuit evaluation, on the device, producing a witness that is
    // already where the proof wants it.
    //
    // `inputs` supplies the mWidth layer-0 values and the ZK mask, drawn from the
    // host PRNG so that the host and device paths prove the same statement; only
    // those (2 MB at 2^24 gates, against 134 MB for the whole witness) are
    // uploaded. Every gate of a layer is independent, so this is `depth` launches.
    // Bit-identical to zkMulWitness.
    DeviceScalarsPtr zkMulWitnessDevice(
        const ZkMulCircuit& circuit, u64 modulus, std::span<const u64> inputs, u64 voleSize);
    // Exact fresh PRNG(seed) inputs and mask, generated and retained on device.
    DeviceScalarsPtr zkMulWitnessDevice(
        const ZkMulCircuit& circuit, u64 modulus, block seed, u64 voleSize);
}
#endif

namespace osuCrypto
{
    // ---- protocol wrappers ----------------------------------------------
    //
    // The prover is the CI-VOLE *receiver* (it chooses the committed vector) and
    // the verifier is the CI-VOLE *sender* (it holds Delta). Both wrappers own
    // their VOLE object, so a caller drives one offline phase and then any
    // number of proofs against it.
    //
    // Device mode (mUseDevice) keeps the whole proof on the GPU: the witness is
    // handed in as device memory, the MACs and keys are left in device memory by
    // the VOLE, and the check runs there too. Then the only bytes that cross
    // PCIe per proof are the 16-byte challenge and the 16-byte response.

    class ZkMulProver : public TimerAdapter
    {
    public:
        LogVole::ZkMulCircuit mCircuit;
        LogVoleReceiver mVole;

        // Run the check on the GPU over device-resident MACs. Ignored when the
        // CUDA backend is not in use.
        bool mUseDevice = false;

        // LogVole::gpu::DeviceScalars holding mCircuit.voleCount() wire values.
        // With device VOLE input, the host `wires` argument supplies its size
        // and receives the refreshed mask; other host entries are not read.
        std::shared_ptr<void> mWiresDevice;


        // Whether the VOLE itself may take its input from mWiresDevice. Set false
        // to hand the VOLE the host span instead while the check still runs on the
        // device: the CUDA backend's device-input path hangs for the
        // no-golden-seed parameter set (reproduce with
        //   frontend_libOTe -lvbench -nn 20 -nogold 1 -gpu 1 -devout 1 -devin 1
        // against the same command with -devin 0), and this is the switch that
        // keeps that setting usable. Costs one host-to-device transfer of the
        // witness.
        bool mVoleDeviceInput = true;

        // Require device-resident witness and MAC output, with no host-sized
        // spans. Opt in explicitly; the public host/fallback behavior is default.
        bool mDeviceOnlyHostSpans = false;

        // MACs, when the check runs on the host. Left allocated but untouched on
        // the device path, where the VOLE never writes them.
        LogVole::AlignedUnVec<u64> mMacs;

        // Cached device wiring and reduction scratch, allocated on the first
        // proof. Opaque LogVole::gpu::ZkMulDeviceState.
        std::shared_ptr<void> mDeviceState;

        LogVole::ZkProof mLastProof;
        u64 mLastChallenge = 0;
        block mLastSeed;

        // Wall time of the check itself, i.e. what the ZK layer adds on top of
        // the VOLE. Set by every prove() call.
        double mCheckMs = 0;

        // Wall time spent waiting for the VOLE's own device work to finish before
        // the check can read its output. That is VOLE cost, not check cost: with
        // the output left on the GPU the VOLE does not drain its stream, so
        // whoever reads it first absorbs the tail.
        double mDrainMs = 0;

        // Whether the last check actually ran on the device. False when the VOLE
        // declined to keep its output there and the host path took over.
        bool mCheckOnDevice = false;

        // `voleRequest` (0 = exactly the circuit's committed count) is the size
        // handed to the VOLE; see LogVole::zkVoleRequestSize.
        void configure(
            LogVole::ZkMulCircuit circuit,
            u32 plaintextModulusBits = 55,
            u32 numThreads = 1,
            LogVole::CivoleSetting setting = LogVole::CivoleSetting::GoldenSeed,
            u64 voleRequest = 0);

        u64 modulus() const { return mVole.modulus(); }
        u64 voleRequest() const { return mVoleRequest; }

        task<> offline(Socket& sock);
        // Refreshes only the trailing mask slot from the private PRNG before
        // VOLE commitment, on both host and device when present. The remaining
        // witness can be reused. The mutable span avoids copying the witness.
        task<> prove(std::span<u64> wires, PRNG& prng, Socket& sock);

    private:
        u64 mVoleRequest = 0;
    };

    class ZkMulVerifier : public TimerAdapter
    {
    public:
        LogVole::ZkMulCircuit mCircuit;
        LogVoleSender mVole;
        // Set before configure() to retain device-only wiring. Configuration
        // takes a moved unique allocation or detaches shared input handles;
        // CPU configuration materializes an independent host copy.
        bool mUseDevice = false;

        // Require device-resident key output without allocating a host key span.
        // The public host/fallback behavior remains the default.
        bool mDeviceOnlyHostSpans = false;

        LogVole::AlignedUnVec<u64> mKeys;
        std::shared_ptr<void> mDeviceState;

        bool mAccepted = false;
        bool mAcceptOnDevice = false;
        u64 mLastChallenge = 0;
        u64 mLastValue = 0;
        block mLastSeed;
        double mCheckMs = 0;
        double mDrainMs = 0;
        bool mCheckOnDevice = false;

        void configure(
            LogVole::ZkMulCircuit circuit,
            u32 plaintextModulusBits = 55,
            u32 numThreads = 1,
            LogVole::CivoleSetting setting = LogVole::CivoleSetting::GoldenSeed,
            u64 voleRequest = 0);

        u64 modulus() const { return mVole.modulus(); }
        u64 voleRequest() const { return mVoleRequest; }

        task<> offline(u64 delta, PRNG& prng, Socket& sock);
        task<> verify(PRNG& prng, Socket& sock);

    private:
        u64 mVoleRequest = 0;
    };

    class ZkMatMulProver : public TimerAdapter
    {
    public:
        LogVole::ZkMatMulStatement mStatement;
        LogVoleReceiver mVole;
        bool mUseDevice = false;
        std::shared_ptr<void> mWiresDevice;

        LogVole::AlignedUnVec<u64> mMacs;
        std::shared_ptr<void> mDeviceState;

        // See ZkMulProver::mVoleDeviceInput.
        bool mVoleDeviceInput = true;

        LogVole::ZkProof mLastProof;
        // mLastProof is the first equation; all repetitions are retained here.
        std::vector<LogVole::ZkProof> mLastProofs;
        block mLastSeed;
        double mCheckMs = 0;
        double mDrainMs = 0;
        bool mCheckOnDevice = false;

        void configure(
            LogVole::ZkMatMulStatement statement,
            u32 plaintextModulusBits = 55,
            u32 numThreads = 1,
            LogVole::CivoleSetting setting = LogVole::CivoleSetting::GoldenSeed,
            u64 voleRequest = 0);

        u64 modulus() const { return mVole.modulus(); }
        u64 voleRequest() const { return mVoleRequest; }

        task<> offline(Socket& sock);
        // Refreshes the independent trailing mask slots on host and device before
        // VOLE commitment; A, B and request padding remain unchanged.
        task<> prove(std::span<u64> wires, PRNG& prng, Socket& sock);

    private:
        u64 mVoleRequest = 0;
    };

    class ZkMatMulVerifier : public TimerAdapter
    {
    public:
        LogVole::ZkMatMulStatement mStatement;
        LogVoleSender mVole;
        bool mUseDevice = false;

        LogVole::AlignedUnVec<u64> mKeys;
        std::shared_ptr<void> mDeviceState;

        bool mAccepted = false;
        u64 mLastValue = 0;
        // mLastValue is the first equation's value.
        std::vector<u64> mLastValues;
        block mLastSeed;
        double mCheckMs = 0;
        double mDrainMs = 0;
        bool mCheckOnDevice = false;

        void configure(
            LogVole::ZkMatMulStatement statement,
            u32 plaintextModulusBits = 55,
            u32 numThreads = 1,
            LogVole::CivoleSetting setting = LogVole::CivoleSetting::GoldenSeed,
            u64 voleRequest = 0);

        u64 modulus() const { return mVole.modulus(); }
        u64 voleRequest() const { return mVoleRequest; }

        task<> offline(u64 delta, PRNG& prng, Socket& sock);
        // Snapshot the application's public C before authentication/challenge.
        // C must contain exactly mDim*mDim canonical field elements.
        task<> verify(std::span<const u64> publicProduct, PRNG& prng, Socket& sock);

    private:
        u64 mVoleRequest = 0;
    };
}
