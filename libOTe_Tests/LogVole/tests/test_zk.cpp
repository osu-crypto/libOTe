#include "libOTe/Vole/LogVole/LogVoleZk.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCpuZk.h"
#include "libOTe_Tests/LogVole_TestUtil.h"
#include "cryptoTools/Common/CLP.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#endif

#include <algorithm>
#include <tuple>
#include <type_traits>
#include <string>
#include <array>
#include <limits>

using namespace osuCrypto;
using namespace osuCrypto::LogVole;

namespace
{
    void checkMatMulCpuTerms()
    {
#if defined(__SIZEOF_INT128__)
        struct Case { u64 modulus; std::size_t dimension; bool extreme; };
        // The p61 cases exceed the safe whole-dot accumulator length, while
        // n1025/p54 overflows an unbounded IFMA high-limb cross accumulator.
        // Only two output rows are computed, keeping these boundary cases O(n^2).
        const std::array<Case, 12> cases{{
            {97, 17, false}, {2251799813554177, 9, false},
            {18014398508400641, 1, true}, {2251799813554177, 513, true},
            {18014398508400641, 1025, true},
            {18014398508400641, 1024, true}, {2251799813554177, 1024, true},
            {2251799813554177, 1025, true},
            {(u64{1} << 51) - ((u64{1} << 23) + 1), 65, true},
            {(u64{1} << 54) - ((u64{1} << 23) + 1), 65, true},
            {2305843009213693951, 33, true}, {2305843009213693951, 65, true}
        }};
        constexpr u64 guard = std::numeric_limits<u64>::max() - 37;
        for (const auto& test : cases)
        {
            const auto n = test.dimension, entries = n * n;
            const auto p = test.modulus;
            const seal::Modulus mod(p);
            // The extra input words also make masked tail loads observable.
            // Offsetting by one word exercises unaligned vector loads.
            std::vector<u64> aStorage(entries + 9, guard), maStorage(entries + 9, guard),
                btStorage(entries + 9, guard), mbtStorage(entries + 9, guard);
            auto* a = aStorage.data() + 1;
            auto* ma = maStorage.data() + 1;
            auto* bt = btStorage.data() + 1;
            auto* mbt = mbtStorage.data() + 1;
            for (std::size_t i = 0; i < entries; ++i)
            {
                a[i] = test.extreme ? p - 1 : (i * 11 + 3) % p;
                ma[i] = test.extreme ? p - 1 : (i * 17 + 5) % p;
                bt[i] = test.extreme ? p - 1 : (p - 1 - (i * 23) % p);
                mbt[i] = test.extreme ? p - 1 : (i * 29 + 7) % p;
            }
            if (n > 1)
            {
                // Distinguish the final column and its masked k tail.
                bt[(n - 1) * n] = 0;
                mbt[(n - 1) * n + n - 1] = 1;
            }
            std::vector<u64> a0Storage(entries + 2, guard), crossStorage(entries + 2, guard),
                productsStorage(entries + 2, guard);
            auto* a0 = a0Storage.data() + 1;
            auto* cross = crossStorage.data() + 1;
            auto* products = productsStorage.data() + 1;
            for (const auto begin : {std::size_t{0}, n - 1})
            {
                const auto end = begin + 1;
                LOGVOLE_REQUIRE_TRUE(LogVole::detail::cpuZkMatMulProverTerms(
                    a, ma, bt, mbt, a0, cross, n, begin, end, mod));
                LOGVOLE_REQUIRE_TRUE(LogVole::detail::cpuZkMatMulVerifierTerms(
                    ma, mbt, products, n, begin, end, mod));
                for (std::size_t j = 0; j < n; ++j)
                {
                    u64 expectedA0 = 0, expectedCross = 0;
                    for (std::size_t k = 0; k < n; ++k)
                    {
                        const auto ia = begin * n + k, ib = j * n + k;
                        expectedA0 = mulAddMod(ma[ia], mbt[ib], expectedA0, mod);
                        expectedCross = mulAddMod(a[ia], mbt[ib], expectedCross, mod);
                        expectedCross = mulAddMod(bt[ib], ma[ia], expectedCross, mod);
                    }
                    const auto output = begin * n + j;
                    LOGVOLE_REQUIRE_EQ(a0[output], expectedA0);
                    LOGVOLE_REQUIRE_EQ(cross[output], expectedCross);
                    LOGVOLE_REQUIRE_EQ(products[output], expectedA0);
                }
            }
            if (test.extreme && n > 1)
            {
                // An independent closed form catches raw-sum overflow even if
                // a reference arithmetic implementation accidentally changes.
                LOGVOLE_REQUIRE_EQ(a0[(n - 1) * n], static_cast<u64>(n) % p);
                LOGVOLE_REQUIRE_EQ(cross[(n - 1) * n], (2 * static_cast<u64>(n)) % p);
            }
            for (std::size_t row = 1; row + 1 < n; ++row)
                for (std::size_t j = 0; j < n; ++j)
                {
                    LOGVOLE_REQUIRE_EQ(a0[row * n + j], guard);
                    LOGVOLE_REQUIRE_EQ(cross[row * n + j], guard);
                    LOGVOLE_REQUIRE_EQ(products[row * n + j], guard);
                }
            for (const auto* output : {&a0Storage, &crossStorage, &productsStorage})
            {
                LOGVOLE_REQUIRE_EQ(output->front(), guard);
                LOGVOLE_REQUIRE_EQ(output->back(), guard);
            }
        }

        // Descriptor failures must not partially overwrite the output rows.
        const seal::Modulus mod(97), zeroMod(0);
        std::array<u64, 4> input{1, 2, 3, 4};
        std::array<u64, 4> output{guard, guard, guard, guard}, other = output;
        const auto unchanged = [&] {
            LOGVOLE_REQUIRE_TRUE(std::all_of(output.begin(), output.end(),
                [](u64 v) { return v == guard; }));
            LOGVOLE_REQUIRE_TRUE(std::all_of(other.begin(), other.end(),
                [](u64 v) { return v == guard; }));
        };
        for (const auto range : {std::array<std::size_t, 3>{0, 0, 0},
             std::array<std::size_t, 3>{2, 2, 1},
             std::array<std::size_t, 3>{2, 0, 3},
             std::array<std::size_t, 3>{std::numeric_limits<std::size_t>::max(), 0, 1}})
        {
            LOGVOLE_REQUIRE_TRUE(!LogVole::detail::cpuZkMatMulProverTerms(input.data(), input.data(),
                input.data(), input.data(), output.data(), other.data(),
                range[0], range[1], range[2], mod));
            LOGVOLE_REQUIRE_TRUE(!LogVole::detail::cpuZkMatMulVerifierTerms(input.data(), input.data(),
                output.data(), range[0], range[1], range[2], mod));
            unchanged();
        }
        LOGVOLE_REQUIRE_TRUE(!LogVole::detail::cpuZkMatMulProverTerms(nullptr, input.data(),
            input.data(), input.data(), output.data(), other.data(), 2, 0, 1, mod));
        LOGVOLE_REQUIRE_TRUE(!LogVole::detail::cpuZkMatMulVerifierTerms(input.data(), nullptr,
            output.data(), 2, 0, 1, mod));
        LOGVOLE_REQUIRE_TRUE(!LogVole::detail::cpuZkMatMulProverTerms(input.data(), input.data(),
            input.data(), input.data(), output.data(), other.data(), 2, 0, 1, zeroMod));
        LOGVOLE_REQUIRE_TRUE(!LogVole::detail::cpuZkMatMulVerifierTerms(input.data(), input.data(),
            output.data(), 2, 0, 1, zeroMod));
        unchanged();
        LOGVOLE_REQUIRE_TRUE(LogVole::detail::cpuZkMatMulProverTerms(nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr, 2, 1, 1, mod));
        LOGVOLE_REQUIRE_TRUE(LogVole::detail::cpuZkMatMulVerifierTerms(nullptr, nullptr,
            nullptr, 2, 1, 1, mod));
#endif
    }

    template<typename Prover, typename Verifier, typename Statement>
    void checkFreshMasks(const Statement& statement, CivoleSetting setting, bool device)
    {
        constexpr bool multiplication = std::is_same_v<Prover, ZkMulProver>;
        Prover prover;
        Verifier verifier;
        prover.mUseDevice = verifier.mUseDevice = device;
        const u64 request = device ? 65536 : 16;
        prover.configure(statement, 55, 1, setting, request);
        verifier.configure(statement, 55, 1, setting, request);
        const u64 p = prover.modulus(), delta = 19, maskIndex = statement.maskIndex();
        u32 maskCount = 1;
        if constexpr (!multiplication) maskCount = statement.repetitions();
        const seal::Modulus modulus(p);
        PRNG witnessPrng(toBlock(0x5749544e455353, 1));
        AlignedUnVec<u64> wires, publicProduct;
        if constexpr (multiplication)
            LOGVOLE_REQUIRE_TRUE(zkMulWitness(statement, p, witnessPrng, wires, request));
        else
            LOGVOLE_REQUIRE_TRUE(zkMatMulWitness(statement, p, 1, witnessPrng, wires, publicProduct, request));
        const auto original = wires;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (device)
        {
            auto storage = std::make_shared<gpu::DeviceScalars>();
            LOGVOLE_REQUIRE_TRUE(storage->resize(request));
            LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(storage->data(), wires.data(),
                wires.size() * sizeof(u64), gpu::threadStream().raw()));
            LOGVOLE_REQUIRE_TRUE(gpu::threadStream().sync());
            prover.mWiresDevice = storage;
        }
#endif
        PRNG senderPrng(toBlock(0x53454e444552, 1));
        auto sockets = coproto::LocalAsyncSocket::makePair();
        auto offline = macoro::sync_wait(macoro::when_all_ready(
            verifier.offline(delta, senderPrng, sockets[0]), prover.offline(sockets[1])));
        std::get<0>(offline).result();
        std::get<1>(offline).result();

        u64 previousMask = original[maskIndex];
        for (u64 instance = 0; instance != 3; ++instance)
        {
            // Replay only the mask draw from a distinct private query seed.
            // These fixed seeds have distinct masks; independence in general
            // permits collisions and does not require rejecting a previous r.
            const block seed = toBlock(0x50524f4f464d4153, instance + 1);
            PRNG receiverPrng(seed), maskOracle(seed);
            const u64 threshold = (u64{0} - p) % p;
            std::vector<u64> expectedMasks(maskCount);
            for (u64& expected : expectedMasks)
            {
                u64 draw;
                do { draw = maskOracle.get<u64>(); } while (draw < threshold);
                expected = draw % p;
            }
            LOGVOLE_REQUIRE_TRUE(expectedMasks.front() != previousMask);

            const bool deviceOnly = device && multiplication && instance == 2;
            prover.mVoleDeviceInput = instance != 0;
            if constexpr (multiplication)
            {
                prover.mDeviceOnlyHostSpans = deviceOnly;
                verifier.mDeviceOnlyHostSpans = deviceOnly;
            }
            auto hostInput = deviceOnly ? std::span<u64>{}
                : std::span<u64>(wires.data(), wires.size());
            auto verification = [&] {
                if constexpr (multiplication)
                    return verifier.verify(senderPrng, sockets[0]);
                else
                    return verifier.verify(publicProduct, senderPrng, sockets[0]);
            };
            auto online = macoro::sync_wait(macoro::when_all_ready(
                verification(), prover.prove(hostInput, receiverPrng, sockets[1])));
            std::get<0>(online).result();
            std::get<1>(online).result();
            LOGVOLE_REQUIRE_TRUE(verifier.mAccepted);
            if (!deviceOnly)
                for (u32 rep = 0; rep < maskCount; ++rep)
                    LOGVOLE_REQUIRE_EQ(wires[maskIndex + rep], expectedMasks[rep]);

            AlignedUnVec<u64> actual = wires, macs = prover.mMacs, keys = verifier.mKeys;
#if defined(ENABLE_LOGVOLE_CUDA)
            if (device)
            {
                LOGVOLE_REQUIRE_TRUE(prover.mCheckOnDevice && verifier.mCheckOnDevice);
                macs.resize(request);
                keys.resize(request);
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(
                    *std::static_pointer_cast<gpu::DeviceScalars>(prover.mWiresDevice), actual));
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(
                    *std::static_pointer_cast<gpu::DeviceScalars>(prover.mVole.outputDevice()), macs));
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(
                    *std::static_pointer_cast<gpu::DeviceScalars>(verifier.mVole.outputDevice()), keys));
            }
#endif
            for (u32 rep = 0; rep < maskCount; ++rep)
                LOGVOLE_REQUIRE_EQ(actual[maskIndex + rep], expectedMasks[rep]);
            LOGVOLE_REQUIRE_EQ(macs.size(), request);
            LOGVOLE_REQUIRE_EQ(keys.size(), request);
            for (u64 i = 0; i < request; ++i)
            {
                if (i < maskIndex || i >= maskIndex + maskCount)
                    LOGVOLE_REQUIRE_EQ(actual[i], original[i]);
                LOGVOLE_REQUIRE_EQ(macs[i], mulAddMod(actual[i], delta, keys[i], modulus));
            }
            if constexpr (multiplication)
            {
                ZkProof expectedProof;
                LOGVOLE_REQUIRE_TRUE(zkMulProverResponse(statement, actual, macs,
                    prover.mLastChallenge, p, 1, expectedProof));
                LOGVOLE_REQUIRE_EQ(prover.mLastProof.mU, expectedProof.mU);
                LOGVOLE_REQUIRE_EQ(prover.mLastProof.mV, expectedProof.mV);
            }
            else
            {
                ZkMatMulChallenge challenge;
                zkMatMulChallenge(statement, prover.mLastSeed, p, challenge);
                std::vector<ZkProof> expectedProofs;
                LOGVOLE_REQUIRE_TRUE(zkMatMulProverResponse(statement, actual, macs,
                    challenge, p, 1, expectedProofs));
                LOGVOLE_REQUIRE_EQ(prover.mLastProofs.size(), maskCount);
                LOGVOLE_REQUIRE_EQ(verifier.mLastValues.size(), maskCount);
                for (u32 rep = 0; rep < maskCount; ++rep)
                {
                    LOGVOLE_REQUIRE_EQ(prover.mLastProofs[rep].mU, expectedProofs[rep].mU);
                    LOGVOLE_REQUIRE_EQ(prover.mLastProofs[rep].mV, expectedProofs[rep].mV);
                    LOGVOLE_REQUIRE_TRUE(zkAccept(prover.mLastProofs[rep],
                        verifier.mLastValues[rep], delta, p));
                }
            }
            previousMask = expectedMasks.front();
        }
    }

    void checkBothStatements(CivoleSetting setting, bool device)
    {
        ZkMulCircuit circuit;
        LOGVOLE_REQUIRE_TRUE(makeZkMulCircuit(4, 2, toBlock(0x43495243554954, 1), circuit));
        checkFreshMasks<ZkMulProver, ZkMulVerifier>(circuit, setting, device);
        ZkMatMulStatement matrix;
        matrix.mDim = 2;
        checkFreshMasks<ZkMatMulProver, ZkMatMulVerifier>(matrix, setting, device);
        matrix.mReps = 3;
        checkFreshMasks<ZkMatMulProver, ZkMatMulVerifier>(matrix, setting, device);
    }

#if defined(ENABLE_LOGVOLE_CUDA)
    struct GpuScope
    {
        bool previous = gpu::enabled();
        ~GpuScope() { gpu::setEnabled(previous); }
    };
#endif
}

void LogVole_Zk_FreshMaskCpu(const CLP&)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    GpuScope scope;
    gpu::setEnabled(false);
#endif
    checkBothStatements(CivoleSetting::GoldenSeed, false);
    checkBothStatements(CivoleSetting::NoGoldenSeed, false);
}

void LogVole_Zk_FreshMaskGpu(const CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    GpuScope scope;
    const bool requested = cmd.getOr("gpu", 0) != 0;
    gpu::setEnabled(requested);
    if (!requested) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    LOGVOLE_REQUIRE_TRUE(gpu::enabled());
    checkBothStatements(CivoleSetting::GoldenSeed, true);
    // Resident NoGoldenSeed witness packing currently targets H200.
    if (gpu::deviceDescription().find("H200") != std::string::npos)
        checkBothStatements(CivoleSetting::NoGoldenSeed, true);
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires CUDA support";
#endif
}

void LogVole_Zk_MatMulIndependentRepetitions(const CLP&)
{
    checkMatMulCpuTerms();
    constexpr u64 p = 17, delta = 3;
    const seal::Modulus modulus(p);
    ZkMatMulStatement statement{1, 2};
    LOGVOLE_REQUIRE_TRUE(validateZkMatMulStatement(statement));
    LOGVOLE_REQUIRE_EQ(statement.voleCount(), 4u);
    std::array<u64, 4> wires{0, 0, 5, 9};
    std::array<u64, 4> keys{2, 7, 3, 4}, macs{};
    for (std::size_t i = 0; i < wires.size(); ++i)
        macs[i] = mulAddMod(wires[i], delta, keys[i], modulus);
    std::array<u64, 1> publicProduct{1};
    ZkMatMulChallenge challenge;
    assignValues<u64>(challenge.mCoefficients, {1, p - 1});
    std::vector<ZkProof> proofs;
    std::vector<u64> values;
    LOGVOLE_REQUIRE_TRUE(zkMatMulProverResponse(statement, wires, macs, challenge, p, 1, proofs));
    LOGVOLE_REQUIRE_TRUE(zkMatMulVerifierValue(statement, keys, publicProduct, challenge,
        delta, p, 1, values));
    LOGVOLE_REQUIRE_EQ(proofs.size(), 2u);
    // Opposite coefficients produce nonzero residuals that sum to zero. Each
    // repetition must reject independently when public C=1 but A=B=0.
    LOGVOLE_REQUIRE_TRUE(!zkAccept(proofs[0], values[0], delta, p));
    LOGVOLE_REQUIRE_TRUE(!zkAccept(proofs[1], values[1], delta, p));
    LOGVOLE_REQUIRE_TRUE(!zkMatMulAccept(proofs, values, delta, p));
    LOGVOLE_REQUIRE_TRUE(!zkMatMulAccept(std::span<const ZkProof>(proofs.data(), 1), values, delta, p));
    ZkProof scalar{13, 14};
    u64 scalarValue = 15;
    LOGVOLE_REQUIRE_TRUE(!zkMatMulProverResponse(statement, wires, macs, challenge, p, 1, scalar));
    LOGVOLE_REQUIRE_TRUE(!zkMatMulVerifierValue(statement, keys, publicProduct, challenge,
        delta, p, 1, scalarValue));
    LOGVOLE_REQUIRE_EQ(scalar.mU, 13u);
    LOGVOLE_REQUIRE_EQ(scalarValue, 15u);

    // Changing only the verifier's public statement changes acceptance. The
    // private witness has no C slot from which an expected result can be inferred.
    publicProduct[0] = 0;
    LOGVOLE_REQUIRE_TRUE(zkMatMulVerifierValue(statement, keys, publicProduct, challenge,
        delta, p, 1, values));
    LOGVOLE_REQUIRE_TRUE(zkMatMulAccept(proofs, values, delta, p));
    proofs[1].mU = (proofs[1].mU + 1u) % p;
    LOGVOLE_REQUIRE_TRUE(!zkMatMulAccept(proofs, values, delta, p));

    // A full coefficient matrix distinguishes a residual whose row and column
    // sums vanish. The former u=v=(1,1) projection would miss this entire error.
    ZkMatMulStatement dense{2, 1};
    AlignedUnVec<u64> denseWires, denseKeys, denseMacs;
    denseWires.resize(dense.voleCount());
    denseKeys.resize(dense.voleCount());
    denseMacs.resize(dense.voleCount());
    std::fill(denseWires.begin(), denseWires.end(), u64{0});
    denseWires[dense.maskIndex()] = 11;
    for (u64 i = 0; i < dense.voleCount(); ++i)
    {
        denseKeys[i] = (2 * i + 1) % p;
        denseMacs[i] = mulAddMod(denseWires[i], delta, denseKeys[i], modulus);
    }
    ZkMatMulChallenge denseChallenge;
    assignValues<u64>(denseChallenge.mCoefficients, {1, 2, 3, 5});
    std::array<u64, 4> wrongProduct{p - 1, 1, 1, p - 1};
    LOGVOLE_REQUIRE_TRUE(zkMatMulProverResponse(dense, denseWires, denseMacs,
        denseChallenge, p, 1, scalar));
    LOGVOLE_REQUIRE_TRUE(zkMatMulVerifierValue(dense, denseKeys, wrongProduct,
        denseChallenge, delta, p, 1, scalarValue));
    LOGVOLE_REQUIRE_TRUE(!zkAccept(scalar, scalarValue, delta, p));
    std::array<u64, 4> zeroProduct{};
    LOGVOLE_REQUIRE_TRUE(zkMatMulVerifierValue(dense, denseKeys, zeroProduct,
        denseChallenge, delta, p, 1, scalarValue));
    LOGVOLE_REQUIRE_TRUE(zkAccept(scalar, scalarValue, delta, p));
    std::array<u64, 4> identity{1, 0, 0, 1};
    LOGVOLE_REQUIRE_TRUE(zkMatMulVerifierValue(dense, denseKeys, identity,
        denseChallenge, delta, p, 1, scalarValue));
    LOGVOLE_REQUIRE_TRUE(!zkAccept(scalar, scalarValue, delta, p));

    // Bind the last public output as well as the first. Checking only a prefix
    // of a packed output array must never accept a changed trailing entry.
    std::array<u64, 4> trailingError{0, 0, 0, 1};
    LOGVOLE_REQUIRE_TRUE(zkMatMulVerifierValue(dense, denseKeys, trailingError,
        denseChallenge, delta, p, 1, scalarValue));
    LOGVOLE_REQUIRE_TRUE(!zkAccept(scalar, scalarValue, delta, p));

    // Check the exact per-entry equations with an independent triple-loop
    // oracle. This includes nonzero A/B and a public product computed without
    // any matrix-proof helper, over both small and actual batching fields.
    for (u64 field : {u64{97}, u64{2251799813554177}, u64{18014398508400641},
        u64{2305843009213693951}})
    for (const ZkMatMulStatement direct : {ZkMatMulStatement{3, 1},
        ZkMatMulStatement{9, 3}, ZkMatMulStatement{17, 2}})
    {
        const seal::Modulus fieldMod(field);
        AlignedUnVec<u64> inputs, directKeys, directMacs;
        inputs.resize(direct.voleCount());
        directKeys.resize(direct.voleCount());
        directMacs.resize(direct.voleCount());
        for (u64 i = 0; i < direct.voleCount(); ++i)
        {
            inputs[i] = (i * 19 + 7) % field;
            directKeys[i] = (field - 1 - i * 23 % field) % field;
            directMacs[i] = mulAddMod(inputs[i], delta, directKeys[i], fieldMod);
        }
        AlignedUnVec<u64> expectedProduct;
        expectedProduct.resize(direct.entries());
        for (u64 i = 0; i < direct.mDim; ++i)
        for (u64 j = 0; j < direct.mDim; ++j)
        {
            u64 value = 0;
            for (u64 k = 0; k < direct.mDim; ++k)
                value = mulAddMod(inputs[direct.offsetA() + i * direct.mDim + k],
                    inputs[direct.offsetB() + k * direct.mDim + j], value, fieldMod);
            expectedProduct[i * direct.mDim + j] = value;
        }
        AlignedUnVec<u64> computedProduct;
        LOGVOLE_REQUIRE_TRUE(zkMatMulFillProduct(direct, field, 2, inputs, computedProduct));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(computedProduct, expectedProduct));
        ZkMatMulChallenge directChallenge;
        const block seed = toBlock(0x646972656374, field);
        zkMatMulChallenge(direct, seed, field, directChallenge);
        LOGVOLE_REQUIRE_EQ(directChallenge.mCoefficients.size(),
            direct.entries() * direct.repetitions());
        PRNG coefficientOracle(seed);
        const u64 threshold = (u64{0} - field) % field;
        for (u64 coefficient : directChallenge.mCoefficients)
        {
            u64 draw;
            do { draw = coefficientOracle.get<u64>(); } while (draw < threshold);
            LOGVOLE_REQUIRE_EQ(coefficient, draw % field);
        }
        std::vector<ZkProof> singleProofs;
        std::vector<u64> singleValues;
        LOGVOLE_REQUIRE_TRUE(zkMatMulProverResponse(direct, inputs, directMacs,
            directChallenge, field, 1, singleProofs));
        LOGVOLE_REQUIRE_TRUE(zkMatMulVerifierValue(direct, directKeys, expectedProduct,
            directChallenge, delta, field, 1, singleValues));
        LOGVOLE_REQUIRE_TRUE(zkMatMulProverResponse(direct, inputs, directMacs,
            directChallenge, field, 3, proofs));
        LOGVOLE_REQUIRE_TRUE(zkMatMulVerifierValue(direct, directKeys, expectedProduct,
            directChallenge, delta, field, 3, values));
        for (u32 rep = 0; rep < direct.repetitions(); ++rep)
        {
            LOGVOLE_REQUIRE_EQ(proofs[rep].mU, singleProofs[rep].mU);
            LOGVOLE_REQUIRE_EQ(proofs[rep].mV, singleProofs[rep].mV);
            LOGVOLE_REQUIRE_EQ(values[rep], singleValues[rep]);
        }
        for (u32 rep = 0; rep < direct.repetitions(); ++rep)
        {
            u64 oracleU = 0, oracleV = 0, oracleB = 0;
            for (u64 i = 0; i < direct.mDim; ++i)
            for (u64 j = 0; j < direct.mDim; ++j)
            {
                u64 a0 = 0, linear = 0, b = 0;
                for (u64 k = 0; k < direct.mDim; ++k)
                {
                    const auto aIdx = direct.offsetA() + i * direct.mDim + k;
                    const auto bIdx = direct.offsetB() + k * direct.mDim + j;
                    a0 = mulAddMod(directMacs[aIdx], directMacs[bIdx], a0, fieldMod);
                    linear = mulAddMod(inputs[aIdx], directMacs[bIdx], linear, fieldMod);
                    linear = mulAddMod(inputs[bIdx], directMacs[aIdx], linear, fieldMod);
                    b = mulAddMod(directKeys[aIdx], directKeys[bIdx], b, fieldMod);
                }
                const auto idx = i * direct.mDim + j;
                const u64 coefficient = directChallenge.mCoefficients[rep * direct.entries() + idx];
                oracleU = mulAddMod(coefficient, a0, oracleU, fieldMod);
                oracleV = mulAddMod(coefficient, linear ? field - linear : 0, oracleV, fieldMod);
                const u64 publicTerm = mulMod(expectedProduct[idx],
                    mulMod(delta, delta, fieldMod), fieldMod);
                const u64 publicResidual = b >= publicTerm ? b - publicTerm : field - (publicTerm - b);
                oracleB = mulAddMod(coefficient, publicResidual, oracleB, fieldMod);
            }
            oracleU = addMod(oracleU, directMacs[direct.maskIndex(rep)], fieldMod);
            const auto mask = inputs[direct.maskIndex(rep)];
            oracleV = oracleV >= mask ? oracleV - mask : field - (mask - oracleV);
            oracleB = addMod(oracleB, directKeys[direct.maskIndex(rep)], fieldMod);
            LOGVOLE_REQUIRE_EQ(proofs[rep].mU, oracleU);
            LOGVOLE_REQUIRE_EQ(proofs[rep].mV, oracleV);
            LOGVOLE_REQUIRE_EQ(values[rep], oracleB);
        }
        LOGVOLE_REQUIRE_TRUE(zkMatMulAccept(proofs, values, delta, field));

        // Public CPU entry points retain their scalar arithmetic semantics for
        // noncanonical matrix entries. The new packing stage must normalize
        // even inputs whose equivalent lift is close to UINT64_MAX.
        auto liftedInputs = inputs, liftedMacs = directMacs, liftedKeys = directKeys;
        const auto lift = [field](u64 value) {
            return value + ((std::numeric_limits<u64>::max() - value) / field) * field;
        };
        for (u64 i = 0; i < 2 * direct.entries(); ++i)
        {
            liftedInputs[i] = lift(liftedInputs[i]);
            liftedMacs[i] = lift(liftedMacs[i]);
            liftedKeys[i] = lift(liftedKeys[i]);
        }
        LOGVOLE_REQUIRE_TRUE(zkMatMulProverResponse(direct, liftedInputs, liftedMacs,
            directChallenge, field, 3, singleProofs));
        LOGVOLE_REQUIRE_TRUE(zkMatMulVerifierValue(direct, liftedKeys, expectedProduct,
            directChallenge, delta, field, 3, singleValues));
        for (u32 rep = 0; rep < direct.repetitions(); ++rep)
        {
            LOGVOLE_REQUIRE_EQ(proofs[rep].mU, singleProofs[rep].mU);
            LOGVOLE_REQUIRE_EQ(proofs[rep].mV, singleProofs[rep].mV);
            LOGVOLE_REQUIRE_EQ(values[rep], singleValues[rep]);
        }
    }

    // Invalid public statements and coefficient arrays fail before replacing
    // caller-owned output. Both scalar and vector callers retain their values.
    std::vector<ZkProof> sentinelProofs{{13, 14}};
    std::vector<u64> sentinelValues{15};
    auto assertUnchanged = [&] {
        LOGVOLE_REQUIRE_EQ(sentinelProofs.size(), 1u);
        LOGVOLE_REQUIRE_EQ(sentinelProofs[0].mU, 13u);
        LOGVOLE_REQUIRE_EQ(sentinelProofs[0].mV, 14u);
        LOGVOLE_REQUIRE_EQ(sentinelValues.size(), 1u);
        LOGVOLE_REQUIRE_EQ(sentinelValues[0], 15u);
    };
    for (const auto& invalid : {std::vector<u64>{},
        std::vector<u64>{0}, std::vector<u64>{0, 0, 0, 0, 0}, std::vector<u64>{0, 0, 0, p}})
    {
        LOGVOLE_REQUIRE_TRUE(!zkMatMulVerifierValue(dense, denseKeys, invalid,
            denseChallenge, delta, p, 1, sentinelValues));
        scalarValue = 15;
        LOGVOLE_REQUIRE_TRUE(!zkMatMulVerifierValue(dense, denseKeys, invalid,
            denseChallenge, delta, p, 1, scalarValue));
        LOGVOLE_REQUIRE_EQ(scalarValue, 15u);
        assertUnchanged();
    }
    for (const auto& invalid : {std::vector<u64>{},
        std::vector<u64>{1}, std::vector<u64>{1, 2, 3, 4, 5}, std::vector<u64>{1, 2, 3, p}})
    {
        ZkMatMulChallenge invalidChallenge;
        assignRange(invalidChallenge.mCoefficients, invalid.begin(), invalid.end());
        LOGVOLE_REQUIRE_TRUE(!zkMatMulProverResponse(dense, denseWires, denseMacs,
            invalidChallenge, p, 1, sentinelProofs));
        LOGVOLE_REQUIRE_TRUE(!zkMatMulVerifierValue(dense, denseKeys, zeroProduct,
            invalidChallenge, delta, p, 1, sentinelValues));
        scalar = {13, 14};
        scalarValue = 15;
        LOGVOLE_REQUIRE_TRUE(!zkMatMulProverResponse(dense, denseWires, denseMacs,
            invalidChallenge, p, 1, scalar));
        LOGVOLE_REQUIRE_TRUE(!zkMatMulVerifierValue(dense, denseKeys, zeroProduct,
            invalidChallenge, delta, p, 1, scalarValue));
        LOGVOLE_REQUIRE_EQ(scalar.mU, 13u);
        LOGVOLE_REQUIRE_EQ(scalar.mV, 14u);
        LOGVOLE_REQUIRE_EQ(scalarValue, 15u);
        assertUnchanged();
    }
    LOGVOLE_REQUIRE_TRUE(!validateZkMatMulStatement({0, 1}));
    LOGVOLE_REQUIRE_TRUE(!validateZkMatMulStatement({std::numeric_limits<u64>::max(), 1}));
}

void LogVole_Zk_MatMulReconfigure(const CLP& cmd)
{
    bool device = false;
#if defined(ENABLE_LOGVOLE_CUDA)
    GpuScope scope;
    device = cmd.getOr("gpu", 0) != 0;
    gpu::setEnabled(device);
    if (device) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
#else
    (void)cmd;
#endif
    ZkMatMulProver prover;
    ZkMatMulVerifier verifier;
    prover.mUseDevice = verifier.mUseDevice = device;
    PRNG witnessPrng(toBlock(0x7265636f6e666967, 1));
    PRNG senderPrng(toBlock(0x7265636f6e666967, 2));
    PRNG receiverPrng(toBlock(0x7265636f6e666967, 3));
    // A sentinel exercises reset even in CPU builds. A real GPU run replaces
    // it with the first statement's allocations before increasing both sizes.
    prover.mDeviceState = std::make_shared<int>(1);
    verifier.mDeviceState = std::make_shared<int>(1);
    std::vector<ZkMatMulStatement> statements{{1, 1}, {4, 3}};
    // The final GPU case crosses both the 256-thread k stride and 65535
    // output cells; it also grows allocations after a repeated statement.
    if (device) statements.push_back({257, 1});
    for (const auto statement : statements)
    {
        const u64 request = std::max<u64>(device ? 65536 : 64,
            zkVoleRequestSize(statement.voleCount()));
        prover.configure(statement, 55, 1, CivoleSetting::GoldenSeed, request);
        verifier.configure(statement, 55, 1, CivoleSetting::GoldenSeed, request);
        LOGVOLE_REQUIRE_TRUE(!prover.mDeviceState && !verifier.mDeviceState);
        AlignedUnVec<u64> wires, publicProduct;
        LOGVOLE_REQUIRE_TRUE(zkMatMulWitness(statement, prover.modulus(), 1, witnessPrng,
            wires, publicProduct, request));
#if defined(ENABLE_LOGVOLE_CUDA)
        if (device)
        {
            prover.mWiresDevice = gpu::uploadScalars(wires);
            LOGVOLE_REQUIRE_TRUE(prover.mWiresDevice != nullptr);
        }
#endif
        auto sockets = coproto::LocalAsyncSocket::makePair();
        auto offline = macoro::sync_wait(macoro::when_all_ready(
            verifier.offline(19, senderPrng, sockets[0]), prover.offline(sockets[1])));
        std::get<0>(offline).result();
        std::get<1>(offline).result();
        // Changing public C in either direction must update device verifier
        // state too; the private inputs and configured dimensions stay fixed.
        for (bool corrupt : {false, true, false})
        {
            auto expectedProduct = publicProduct;
            if (corrupt) expectedProduct[0] = (expectedProduct[0] + 1) % prover.modulus();
            auto online = macoro::sync_wait(macoro::when_all_ready(
                verifier.verify(expectedProduct, senderPrng, sockets[0]),
                prover.prove(wires, receiverPrng, sockets[1])));
            std::get<0>(online).result();
            std::get<1>(online).result();
            LOGVOLE_REQUIRE_TRUE(verifier.mAccepted != corrupt);
            LOGVOLE_REQUIRE_EQ(prover.mLastProofs.size(), statement.repetitions());
            LOGVOLE_REQUIRE_EQ(verifier.mLastValues.size(), statement.repetitions());
            if (device)
                LOGVOLE_REQUIRE_TRUE(prover.mCheckOnDevice && verifier.mCheckOnDevice);
        }
#if defined(ENABLE_LOGVOLE_CUDA)
        if (device)
        {
            // Compare the actual resident proof against the independent host
            // path after changing public C away from, then back to, its value.
            AlignedUnVec<u64> actual, macs, keys;
            actual.resize(request);
            macs.resize(request);
            keys.resize(request);
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(
                *std::static_pointer_cast<gpu::DeviceScalars>(prover.mWiresDevice), actual));
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(
                *std::static_pointer_cast<gpu::DeviceScalars>(prover.mVole.outputDevice()), macs));
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(
                *std::static_pointer_cast<gpu::DeviceScalars>(verifier.mVole.outputDevice()), keys));
            ZkMatMulChallenge challenge;
            zkMatMulChallenge(statement, prover.mLastSeed, prover.modulus(), challenge);
            std::vector<ZkProof> expectedProofs;
            std::vector<u64> expectedValues;
            LOGVOLE_REQUIRE_TRUE(zkMatMulProverResponse(statement, actual, macs,
                challenge, prover.modulus(), 1, expectedProofs));
            LOGVOLE_REQUIRE_TRUE(zkMatMulVerifierValue(statement, keys, publicProduct,
                challenge, 19, prover.modulus(), 1, expectedValues));
            for (u32 rep = 0; rep < statement.repetitions(); ++rep)
            {
                LOGVOLE_REQUIRE_EQ(prover.mLastProofs[rep].mU, expectedProofs[rep].mU);
                LOGVOLE_REQUIRE_EQ(prover.mLastProofs[rep].mV, expectedProofs[rep].mV);
                LOGVOLE_REQUIRE_EQ(verifier.mLastValues[rep], expectedValues[rep]);
            }
        }
#endif
    }
}
