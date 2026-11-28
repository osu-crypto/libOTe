#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussian.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussianKernels.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussianMath.cuh"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cfenv>
#include <cmath>
#include <cstring>
#include <limits>
#include <memory>
#include <random>
#include <stdexcept>
#if defined(__linux__) && defined(__x86_64__)
#include <dlfcn.h>
#include <link.h>
#include <xmmintrin.h>
#endif

namespace osuCrypto::LogVole::gpu
{
    namespace
    {
        struct PinnedPrefixCache
        {
            std::shared_ptr<u64> mData;
            std::size_t mCapacity = 0;

            std::shared_ptr<u64> acquire(std::size_t bytes)
            {
                if (mData && mData.use_count() == 1 && mCapacity >= bytes) return mData;
                // Never overwrite a buffer still held by a normal-transform
                // reader. Geometric growth avoids repeated pinning for nearby
                // batch sizes; the caller already bounds bytes to 256 MiB.
                if (mData && mData.use_count() == 1)
                {
                    mData.reset();
                    mCapacity = 0;
                }
                std::size_t capacity = 4096;
                while (capacity < bytes) capacity *= 2u;
                std::shared_ptr<PinnedHostBuffer> allocation;
                try { allocation = std::make_shared<PinnedHostBuffer>(capacity); }
                catch (...) { return {}; }
                auto next = std::shared_ptr<u64>(allocation, static_cast<u64*>(allocation->data()));
                mData = next;
                mCapacity = capacity;
                return next;
            }
        };
    }

    struct GpuGaussianScratch
    {
        PinnedPrefixCache prefixes;
        PinnedPrefixCache output;
    };

    void GpuGaussianScratchDeleter::operator()(GpuGaussianScratch* scratch) const noexcept
    {
        delete scratch;
    }

    GpuGaussianScratch& GpuStream::gaussianScratch()
    {
        if (!mGaussianScratch) mGaussianScratch.reset(new GpuGaussianScratch());
        return *mGaussianScratch;
    }

    bool GaussianHostCompatibility::compatible()
    {
        // The exact operation mapping is deliberately narrow. Other C++/libm
        // implementations retain the original CPU distribution, even when their
        // statistical distribution would be indistinguishable.
#if defined(__linux__) && defined(__x86_64__) && defined(__GLIBC__) && \
    defined(__GNUC__) && !defined(__clang__) && __GNUC__ == 14 && \
    defined(_GLIBCXX_RELEASE) && _GLIBCXX_RELEASE == 14 && \
    defined(__AVX512F__) && defined(__OPTIMIZE__) && !defined(__FAST_MATH__)
        if (std::fegetround() != FE_TONEAREST || (_mm_getcsr() & 0xe040u)) return false;
        if (mReady.load(std::memory_order_acquire)) return mCompatible;
        std::lock_guard lock(mMutex);
        if (mReady.load(std::memory_order_relaxed)) return mCompatible;
        const bool recognized = [] {
            Dl_info info{};
            // Taking &std::log can yield the executable's PLT stub in a non-PIE
            // build. Resolve the actual symbol selected by the dynamic linker.
            const void* logarithm = dlsym(RTLD_DEFAULT, "log");
            if (!logarithm || !dladdr(logarithm, &info) || !info.dli_fbase)
                return false;
            const auto* base = static_cast<const u8*>(info.dli_fbase);
            const void* finiteLog = dlvsym(RTLD_DEFAULT, "__log_finite", "GLIBC_2.15");
            Dl_info finiteInfo{};
            if (!finiteLog || !dladdr(finiteLog, &finiteInfo) || finiteInfo.dli_fbase != base)
                return false;
            struct LogFingerprint
            {
                std::uintptr_t mLogOffset;
                std::uintptr_t mFiniteLogOffset;
                std::array<u8, 20> mBuildId;
            };
            // Both FMA implementations match the CUDA helper over the positive
            // normal radii admitted by the polar sampler.
            constexpr std::array<LogFingerprint, 2> fingerprints{{
                {0x356f0, 0x69610, {0x0f,0x68,0xdf,0x2e,0xcc,0x3b,0xf9,0x01,0x98,0x4f,
                    0xb2,0x85,0x21,0x90,0x26,0xd6,0x73,0x56,0xbc,0x58}},
                // glibc-2.34-283.el9_8.x86_64
                {0x357f0, 0x6ff70, {0x25,0xc2,0xa6,0x50,0xe3,0xe6,0xc2,0xf3,0x25,0xc8,
                    0xad,0x80,0x3d,0xbb,0x58,0xb3,0x13,0x89,0x9c,0x93}},
            }};
            const auto baseAddress = reinterpret_cast<std::uintptr_t>(base);
            const auto logOffset = reinterpret_cast<std::uintptr_t>(logarithm) - baseAddress;
            const auto finiteLogOffset = reinterpret_cast<std::uintptr_t>(finiteLog) - baseAddress;
            const auto fingerprint = std::find_if(fingerprints.begin(), fingerprints.end(),
                [=](const LogFingerprint& known) {
                    return logOffset == known.mLogOffset && finiteLogOffset == known.mFiniteLogOffset;
                });
            if (fingerprint == fingerprints.end()) return false;
            const auto& buildId = fingerprint->mBuildId;
            const auto* header = reinterpret_cast<const ElfW(Ehdr)*>(base);
            if (std::memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) return false;
            const auto* programs = reinterpret_cast<const ElfW(Phdr)*>(base + header->e_phoff);
            for (unsigned i = 0; i < header->e_phnum; ++i)
            {
                if (programs[i].p_type != PT_NOTE) continue;
                const u8* cursor = base + programs[i].p_vaddr;
                const u8* end = cursor + programs[i].p_memsz;
                while (static_cast<std::size_t>(end - cursor) >= sizeof(ElfW(Nhdr)))
                {
                    const auto* note = reinterpret_cast<const ElfW(Nhdr)*>(cursor);
                    cursor += sizeof(ElfW(Nhdr));
                    const std::size_t nameSize = (static_cast<std::size_t>(note->n_namesz) + 3) & ~std::size_t{3};
                    const std::size_t dataSize = (static_cast<std::size_t>(note->n_descsz) + 3) & ~std::size_t{3};
                    if (nameSize > static_cast<std::size_t>(end - cursor) ||
                        dataSize > static_cast<std::size_t>(end - cursor) - nameSize) break;
                    if (note->n_type == NT_GNU_BUILD_ID && note->n_namesz == 4 &&
                        std::memcmp(cursor, "GNU", 4) == 0 && note->n_descsz == buildId.size() &&
                        std::memcmp(cursor + nameSize, buildId.data(), buildId.size()) == 0)
                        return true;
                    cursor += nameSize + dataSize;
                }
            }
            return false;
        }();
        const bool arithmeticCompatible = recognized && [] {
            // Canary for the actual compiler's libstdc++ distribution, not
            // just its version macros. In each case replacing radius's FMA
            // with separate multiply/add changes at least one output bit.
            // This supplements the tested GCC14/libm mapping; a finite canary
            // does not establish compatibility with arbitrary toolchains.
            struct Case
            {
                std::array<u32, 4> words;
                std::array<u64, 2> unit;
                std::array<u64, 2> scaled;
            };
            constexpr std::array<Case, 3> cases{{
                {{0x99e3e62bu, 0x4d2c220eu, 0x5e271ffcu, 0xac0876d2u},
                    {0x3ff0cf598b4b84fdull, 0xbff3676152c235d4ull},
                    {0x400ae55c12126e62ull, 0xc00f0bceead05620ull}},
                {{0xbbca7857u, 0xc3248796u, 0xec1717afu, 0x2304a279u},
                    {0xbfe13166779e4ad6ull, 0x3fd8d48be547ff80ull},
                    {0xbffb823d8c3077bdull, 0x3ff3dd3cb76ccc67ull}},
                {{0x6c51ba46u, 0x705d40e6u, 0xaecff512u, 0xc276316eu},
                    {0x3ff8b1b590fd7aa8ull, 0xbfd73cf66aa40c5eull},
                    {0x4013c15e0d979554ull, 0xbff2972b88833d18ull}}
            }};
            struct FixedWords
            {
                using result_type = u32;
                // Volatile reads prevent constant folding into a different
                // compiler-provided logarithm instead of the runtime libm.
                const volatile u32* words;
                std::size_t count, position = 0;
                static constexpr result_type min() { return 0; }
                static constexpr result_type max() { return 0xffffffffu; }
                result_type operator()()
                {
                    if (position == count) throw std::out_of_range("Gaussian canary exhausted");
                    return words[position++];
                }
            };
            try
            {
                for (const auto& test : cases)
                    for (bool scaled : {false, true})
                        for (bool rejectFirst : {false, true})
                        {
                            // The all-ones pair also exercises generate_canonical's
                            // upper clamp and the polar rejection before this pair.
                            std::array<u32, 8> words{0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
                                test.words[0], test.words[1], test.words[2], test.words[3]};
                            FixedWords engine{words.data() + (rejectFirst ? 0 : 4), rejectFirst ? 8u : 4u};
                            std::normal_distribution<double> normal(0.0, scaled ? 3.2 : 1.0);
                            const auto& expected = scaled ? test.scaled : test.unit;
                            for (u64 pattern : expected)
                            {
                                const double value = normal(engine);
                                u64 actual = 0;
                                static_assert(sizeof(actual) == sizeof(value));
                                std::memcpy(&actual, &value, sizeof(actual));
                                // The cached second sample consumes no new words.
                                if (actual != pattern || engine.position != engine.count) return false;
                            }
                        }
            }
            catch (...) { return false; }
            return true;
        }();
        mCompatible = arithmeticCompatible;
        mReady.store(true, std::memory_order_release);
        return mCompatible;
#else
        return false;
#endif
    }

    static bool sampleGaussianCompactImpl(
        GpuStream& stream,
        std::span<const std::array<u64, 8>> seeds, u32 coefficients,
        double sigma, double clip, u64 modulus, GaussianSampleBuffer* hostOut,
        GaussianDeviceSampleBuffer* deviceOut, u32 wordsPerPrefix, std::span<const u8> active, const LogVoleFailureOptions& failures)
    {
        HostStep totalStep(stream.hostProfiler(), "setup: Gaussian GPU transform");
        if (!stream.raw() || !stream.gaussianCompatibility().compatible() || seeds.empty() || seeds.size() > 65535u ||
            !coefficients || modulus < 2 || !std::isfinite(sigma) || sigma < 0 ||
            !std::isfinite(clip) || clip < 0 ||
            static_cast<long double>(clip) >= static_cast<long double>(modulus >> 1u) ||
            (!active.empty() && active.size() != seeds.size()) || (!hostOut && !deviceOut)) return false;
        const bool decline = failures.mGaussianTransform;
        if (decline) return false;
        const bool residentDecline = failures.mGaussianResident;
        if (deviceOut && residentDecline) return false;
        std::vector<std::array<u64, 8>> selectedSeeds;
        std::vector<u32> outputRows;
        std::span<const std::array<u64, 8>> activeSeeds = seeds;
        if (!active.empty())
        {
            for (std::size_t row = 0; row < seeds.size(); ++row)
                if (active[row])
                {
                    selectedSeeds.push_back(seeds[row]);
                    outputRows.push_back(static_cast<u32>(row));
                }
            activeSeeds = selectedSeeds;
        }
        const u64 defaultWords = ((static_cast<u64>(coefficients) * 3u + 1023u) / 1024u) * 512u;
        if (!wordsPerPrefix)
        {
            if (defaultWords > std::numeric_limits<u32>::max()) return false;
            wordsPerPrefix = static_cast<u32>(defaultWords);
        }
        if (!wordsPerPrefix || wordsPerPrefix % 512u) return false;
        constexpr std::size_t maxBytes = std::size_t{256} << 20;
        const std::size_t prefixBytes = static_cast<std::size_t>(wordsPerPrefix) * sizeof(u64);
        const std::size_t outputRowBytes = static_cast<std::size_t>(coefficients) * sizeof(u64);
        const std::size_t countRowBytes = static_cast<std::size_t>(wordsPerPrefix / 512u) * sizeof(u32);
        const std::size_t rowBytes = prefixBytes * 2 + countRowBytes +
            sizeof(std::array<u64, 8>) + 176u + sizeof(u8) + sizeof(u32);
        const std::size_t outputBytes = seeds.size() * outputRowBytes;
        if (prefixBytes > maxBytes / 2 || outputRowBytes > maxBytes || rowBytes > maxBytes ||
            outputBytes > maxBytes || activeSeeds.size() > (maxBytes - outputBytes) / rowBytes) return false;
        const std::size_t allPrefixBytes = activeSeeds.size() * prefixBytes;
        OwnedGpuBuffer deviceSeeds, prefixes, candidates, counts, complete, deviceRows, keys;
        auto samples = std::make_shared<DeviceScalars>();
        auto pinned = hostOut ? stream.gaussianScratch().output.acquire(outputBytes) : std::shared_ptr<u64>{};
        if (hostOut && !pinned) return false;
        std::vector<u8> completed(seeds.size(), 1), activeCompleted(activeSeeds.size());
        StreamDrain drain{stream};
        if (!samples->resize(outputBytes / sizeof(u64), stream) ||
            !gpuMemsetZero(samples->data(), outputBytes, stream.raw())) return false;
        if (!activeSeeds.empty())
        {
            deviceSeeds = tryAllocateGpuBuffer(stream, activeSeeds.size_bytes());
            prefixes = tryAllocateGpuBuffer(stream, allPrefixBytes);
            candidates = tryAllocateGpuBuffer(stream, allPrefixBytes);
            counts = tryAllocateGpuBuffer(stream, activeSeeds.size() * countRowBytes);
            complete = tryAllocateGpuBuffer(stream, activeSeeds.size());
            keys = tryAllocateGpuBuffer(stream, activeSeeds.size() * 176u);
            if (!outputRows.empty()) deviceRows = tryAllocateGpuBuffer(stream, outputRows.size() * sizeof(u32));
            if (!deviceSeeds || !prefixes || !candidates || !counts || !complete || !keys ||
                (!outputRows.empty() && (!deviceRows || !gpuMemcpyH2D(deviceRows.data(), outputRows.data(),
                    outputRows.size() * sizeof(u32), stream.raw()))) ||
                !gpuMemcpyH2D(deviceSeeds.data(), activeSeeds.data(), activeSeeds.size_bytes(), stream.raw())) return false;
            HostStep step(stream.hostProfiler(), "setup: Gaussian GPU transform PRG");
            if (!launchAesPrngStream(static_cast<const u64*>(deviceSeeds.data()),
                    static_cast<u64*>(prefixes.data()), wordsPerPrefix, static_cast<u32>(activeSeeds.size()),
                    static_cast<unsigned char*>(keys.data()), keys.size(), stream.raw()))
                return false;
        }
        if (!activeSeeds.empty())
        {
            HostStep step(stream.hostProfiler(), "setup: Gaussian GPU transform launch");
            if (!launchGaussianTransform(static_cast<const u64*>(prefixes.data()), wordsPerPrefix,
                    static_cast<u32>(activeSeeds.size()), coefficients, sigma, clip, modulus,
                    static_cast<u64*>(candidates.data()), static_cast<u32*>(counts.data()),
                    samples->data(), static_cast<u8*>(complete.data()), stream.raw(),
                    static_cast<const u32*>(deviceRows.data())) ||
                !gpuMemcpyD2H(activeCompleted.data(), complete.data(), activeCompleted.size(), stream.raw())) return false;
        }
        if ((hostOut && !gpuMemcpyD2H(pinned.get(), samples->data(), outputBytes, stream.raw())) || !stream.sync())
            return false;
        samples->markReady();
        for (std::size_t i = 0; i < activeCompleted.size(); ++i)
            completed[outputRows.empty() ? i : outputRows[i]] = activeCompleted[i];
        if (hostOut)
        {
            GaussianSampleBuffer next;
            next.mValues.mData = std::move(pinned);
            next.mValues.mWords = outputBytes / sizeof(u64);
            next.mComplete = std::move(completed);
            *hostOut = std::move(next);
        }
        else
        {
            GaussianDeviceSampleBuffer next;
            next.mValues = std::move(samples);
            next.mComplete = std::move(completed);
            *deviceOut = std::move(next);
        }
        return true;
    }

    bool sampleGaussianCompactDevice(
        GpuStream& stream,
        std::span<const std::array<u64, 8>> seeds, u32 coefficients,
        double sigma, double clip, u64 modulus, GaussianSampleBuffer& out, u32 wordsPerPrefix, const LogVoleFailureOptions& failures)
    {
        return sampleGaussianCompactImpl(stream, seeds, coefficients, sigma, clip, modulus, &out, nullptr, wordsPerPrefix, {}, failures);
    }

    bool sampleGaussianCompactResidentDevice(
        GpuStream& stream,
        std::span<const std::array<u64, 8>> seeds, u32 coefficients,
        double sigma, double clip, u64 modulus, GaussianDeviceSampleBuffer& out,
        u32 wordsPerPrefix, std::span<const u8> active, const LogVoleFailureOptions& failures)
    {
        return sampleGaussianCompactImpl(stream, seeds, coefficients, sigma, clip, modulus, nullptr, &out, wordsPerPrefix, active, failures);
    }

    bool sampleGaussianPrngPrefixesDevice(
        GpuStream& stream,
        std::span<const std::array<u64, 8>> seeds,
        u32 wordsPerPrefix,
        GaussianPrngPrefixBuffer& out, const LogVoleFailureOptions& failures)
    {
        HostStep totalStep(stream.hostProfiler(), "setup: Gaussian GPU PRG prefixes");
        if (!stream.raw() || seeds.empty() || !wordsPerPrefix || wordsPerPrefix % 512u ||
            seeds.size() > std::numeric_limits<u32>::max()) return false;
        const bool decline = failures.mGaussianPrg;
        if (decline) return false;
        constexpr std::size_t maxPrefixBytes = std::size_t(256) << 20;
        const std::size_t prefixBytes = static_cast<std::size_t>(wordsPerPrefix) * sizeof(u64);
        if (prefixBytes > maxPrefixBytes || seeds.size() > maxPrefixBytes / prefixBytes) return false;
        const std::size_t bytes = seeds.size() * prefixBytes;

        OwnedGpuBuffer deviceSeeds, devicePrefixes, keys;
        auto pinned = stream.gaussianScratch().prefixes.acquire(bytes);
        if (!pinned) return false;
        StreamDrain drain{stream};
        deviceSeeds = tryAllocateGpuBuffer(stream, seeds.size_bytes());
        devicePrefixes = tryAllocateGpuBuffer(stream, bytes);
        keys = tryAllocateGpuBuffer(stream, seeds.size() * 176u);
        if (!deviceSeeds || !devicePrefixes || !keys ||
            !gpuMemcpyH2D(deviceSeeds.data(), seeds.data(), seeds.size_bytes(), stream.raw()) ||
            !launchAesPrngStream(static_cast<const u64*>(deviceSeeds.data()),
                static_cast<u64*>(devicePrefixes.data()), wordsPerPrefix,
                static_cast<u32>(seeds.size()), static_cast<unsigned char*>(keys.data()),
                keys.size(), stream.raw())) return false;

        if (!gpuMemcpyD2H(pinned.get(), devicePrefixes.data(), bytes, stream.raw()) || !stream.sync()) return false;
        out.mData = std::move(pinned);
        out.mWords = bytes / sizeof(u64);
        return true;
    }
}
