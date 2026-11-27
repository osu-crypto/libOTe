#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussianKernels.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussianMath.cuh"

#include <cuda_runtime.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <random>
#include <stdexcept>
#include <vector>

namespace gm = osuCrypto::LogVole::gpu::gaussian_math;
namespace gpu = osuCrypto::LogVole::gpu;
using u64 = std::uint64_t;
using u32 = std::uint32_t;

void require(bool ok, const char* message)
{
    if (!ok) throw std::runtime_error(message);
}
void check(cudaError_t result)
{
    if (result != cudaSuccess) throw std::runtime_error(cudaGetErrorString(result));
}
template<class T> struct Device
{
    T* data = nullptr;
    explicit Device(std::size_t count) { check(cudaMalloc(&data, count * sizeof(T))); }
    ~Device() { cudaFree(data); }
};

__global__ void logarithms(const double* input, double* output, std::size_t count)
{
    const std::size_t i = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i < count) output[i] = gm::log(input[i]);
}

void test_logarithms()
{
    constexpr std::size_t count = 1u << 20;
    std::mt19937_64 random(0xabc12943);
    std::vector<double> input(count), output(count);
    for (std::size_t i = 0; i < count; ++i)
    {
        const u64 exponent = 1023 - (random() % 107);
        input[i] = gm::from_bits((random() & 0xfffffffffffffULL) | (exponent << 52));
        if (i % 3 == 0) input[i] = gm::from_bits(0x3ff0000000000000ULL - random() % 0x4000000000000ULL);
        if (i % 11 == 0)
        {
            // Exercise both sides of every range-reduction and near-one boundary.
            const u64 base = 0x3fe6000000000000ULL + ((i % 128) << 45);
            input[i] = gm::from_bits(base + (i % 3) - 1);
        }
    }
    input[0] = 1.0;
    input[1] = 0x1p-106;
    Device<double> in(count), out(count);
    check(cudaMemcpy(in.data, input.data(), count * sizeof(double), cudaMemcpyHostToDevice));
    logarithms<<<(count + 255) / 256, 256>>>(in.data, out.data, count);
    check(cudaGetLastError());
    check(cudaMemcpy(output.data(), out.data, count * sizeof(double), cudaMemcpyDeviceToHost));
    for (std::size_t i = 0; i < count; ++i)
    {
        const double reference = std::log(input[i]);
        if (gm::bits(output[i]) != gm::bits(reference))
        {
            std::fprintf(stderr, "log mismatch input=%a GPU=%a CPU=%a index=%zu\n",
                input[i], output[i], reference, i);
            throw std::runtime_error("GPU logarithm differs from CPU libm");
        }
    }
    std::printf("logarithms: %zu bit-exact values\n", count);
}

struct PrefixEngine
{
    using result_type = u32;
    const u32* words;
    std::size_t count, position = 0;
    static constexpr result_type min() { return 0; }
    static constexpr result_type max() { return 0xffffffffu; }
    result_type operator()()
    {
        if (position == count) throw std::out_of_range("finite prefix exhausted");
        return words[position++];
    }
};

void test_samples(u32 wordsPerRow, u32 rows, u32 coefficients, double sigma, double clip)
{
    constexpr u64 modulus = 2251799813554177ULL;
    std::mt19937_64 random(0x75913 + coefficients);
    std::vector<u64> prefixes(static_cast<std::size_t>(rows) * wordsPerRow);
    for (auto& word : prefixes) word = random();
    // Radius zero rejection, radius one acceptance, nextafter(1,0) canonical clamp.
    const std::array<u64, 8> edge = {0x8000000000000000ULL,0x8000000000000000ULL,
        0,0x8000000000000000ULL,~u64{0},~u64{0},0x8000000000000001ULL,0x8000000000000001ULL};
    std::copy(edge.begin(), edge.end(), prefixes.begin());
    Device<u64> input(prefixes.size()), candidates(prefixes.size()), output(static_cast<std::size_t>(rows) * coefficients);
    Device<u32> counts(static_cast<std::size_t>(rows) * (wordsPerRow / 512));
    Device<std::uint8_t> complete(rows);
    check(cudaMemcpy(input.data, prefixes.data(), prefixes.size() * sizeof(u64), cudaMemcpyHostToDevice));
    check(cudaMemset(output.data, 0, static_cast<std::size_t>(rows) * coefficients * sizeof(u64)));
    require(gpu::launchGaussianTransform(input.data, wordsPerRow, rows, coefficients, sigma, clip,
        modulus, candidates.data, counts.data, output.data, complete.data, nullptr), "transform launch failed");
    std::vector<u64> actual(static_cast<std::size_t>(rows) * coefficients);
    std::vector<std::uint8_t> flags(rows);
    check(cudaMemcpy(actual.data(), output.data, actual.size() * sizeof(u64), cudaMemcpyDeviceToHost));
    check(cudaMemcpy(flags.data(), complete.data, flags.size(), cudaMemcpyDeviceToHost));
    for (u32 row = 0; row < rows; ++row)
    {
        PrefixEngine engine{reinterpret_cast<const u32*>(prefixes.data() + static_cast<std::size_t>(row) * wordsPerRow),
            static_cast<std::size_t>(wordsPerRow) * 2};
        std::normal_distribution<double> normal(0.0, sigma);
        std::vector<u64> expected;
        try
        {
            while (expected.size() < coefficients)
            {
                const double value = normal(engine);
                if (std::abs(value) <= clip)
                {
                    const auto sample = static_cast<std::int64_t>(value);
                    expected.push_back(static_cast<u64>(sample) + (sample < 0 ? modulus : 0));
                }
            }
        }
        catch (const std::out_of_range&) {}
        require(flags[row] == (expected.size() == coefficients), "incorrect completion flag");
        for (std::size_t i = 0; i < expected.size(); ++i)
            if (expected[i] != actual[static_cast<std::size_t>(row) * coefficients + i])
            {
                std::fprintf(stderr, "sample mismatch row=%u coefficient=%zu sigma=%a clip=%a\n", row,i,sigma,clip);
                throw std::runtime_error("GPU compact samples differ from std::normal_distribution");
            }
    }
}

int main()
{
    try
    {
        test_logarithms();
        std::size_t cases = 0;
        for (u32 coefficients : {1u, 1024u, 8192u, 16384u})
        for (u32 rows : {1u, 4u, 32u})
        for (double sigma : {0.0, 3.2, 1.0, 0x1p-1000})
        for (double clip : {0.0, 0.125, 19.2})
        {
            const u32 words = ((coefficients * 3u + 1023u) / 1024u) * 512u;
            test_samples(words, rows, coefficients, sigma, clip);
            ++cases;
        }
        // Deliberately exhausted prefixes exercise incomplete-row replay metadata.
        test_samples(512, 4, 16384, 3.2, 19.2);
        std::printf("Gaussian ordered transform: %zu cases plus exhausted-prefix case passed\n", cases);
        return 0;
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
