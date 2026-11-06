#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussianKernels.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussianMath.cuh"

#include <cuda_runtime.h>

namespace osuCrypto::LogVole::gpu
{
    namespace
    {
        constexpr unsigned threads = 256;

        __global__ void transformPairs(
            const std::uint64_t* prefixes, std::uint32_t wordsPerRow,
            double sigma, double clip, std::uint64_t modulus,
            std::uint64_t* candidates, std::uint32_t* blockCounts)
        {
            using namespace gaussian_math;
            __shared__ unsigned scan[threads];
            const auto pairIndex = static_cast<std::size_t>(blockIdx.x) * threads + threadIdx.x;
            const auto row = blockIdx.y;
            unsigned accepted = 0;
            std::uint64_t first = 0, second = 0;
            if (pairIndex < wordsPerRow / 2u)
            {
                const auto* words = reinterpret_cast<const std::uint32_t*>(
                    prefixes + static_cast<std::size_t>(row) * wordsPerRow) + 4u * pairIndex;
                double x, y, radius;
                pair(words, x, y, radius);
                if (radius <= 1.0 && radius != 0.0)
                {
                    const double multiplier = gaussian_math::sqrt(
                        div(mul(-2.0, gaussian_math::log(radius)), radius));
                    const double values[2] = {scaled(y, multiplier, sigma), scaled(x, multiplier, sigma)};
                    for (unsigned j = 0; j < 2; ++j)
                    {
                        if (fabs(values[j]) <= clip)
                        {
                            const auto sample = static_cast<std::int64_t>(values[j]);
                            const auto residue = static_cast<std::uint64_t>(sample) +
                                (sample < 0 ? modulus : std::uint64_t{0});
                            if (accepted == 0) first = residue;
                            else second = residue;
                            ++accepted;
                        }
                    }
                }
            }
            scan[threadIdx.x] = accepted;
            __syncthreads();
            for (unsigned offset = 1; offset < threads; offset *= 2)
            {
                const unsigned preceding = threadIdx.x >= offset ? scan[threadIdx.x - offset] : 0;
                __syncthreads();
                scan[threadIdx.x] += preceding;
                __syncthreads();
            }
            const unsigned position = scan[threadIdx.x] - accepted;
            const auto block = static_cast<std::size_t>(row) * gridDim.x + blockIdx.x;
            auto* output = candidates + block * (2u * threads);
            if (accepted) output[position] = first;
            if (accepted == 2) output[position + 1] = second;
            if (threadIdx.x == threads - 1) blockCounts[block] = scan[threadIdx.x];
        }

        __global__ void compactBlocks(
            const std::uint64_t* candidates, const std::uint32_t* blockCounts,
            std::uint32_t coefficients, std::uint64_t* output, std::uint8_t* complete,
            const std::uint32_t* outputRows)
        {
            __shared__ std::uint32_t offset, count;
            const auto row = blockIdx.y;
            const auto block = static_cast<std::size_t>(row) * gridDim.x + blockIdx.x;
            if (threadIdx.x == 0)
            {
                std::uint32_t preceding = 0;
                for (unsigned i = 0; i < blockIdx.x; ++i)
                    preceding += blockCounts[static_cast<std::size_t>(row) * gridDim.x + i];
                offset = preceding;
                count = blockCounts[block];
                if (blockIdx.x == gridDim.x - 1)
                    complete[row] = preceding + count >= coefficients;
            }
            __syncthreads();
            for (unsigned i = threadIdx.x; i < count && offset + i < coefficients; i += threads)
                output[static_cast<std::size_t>(outputRows ? outputRows[row] : row) * coefficients + offset + i] =
                    candidates[block * (2u * threads) + i];
        }
    }

    bool launchGaussianTransform(
        const std::uint64_t* prefixes, std::uint32_t wordsPerRow,
        std::uint32_t rows, std::uint32_t coefficients, double sigma, double clip,
        std::uint64_t modulus, std::uint64_t* candidates, std::uint32_t* blockCounts,
        std::uint64_t* output, std::uint8_t* complete, void* stream,
        const std::uint32_t* outputRows)
    {
        if (!prefixes || !wordsPerRow || wordsPerRow % 512u || !rows || rows > 65535u ||
            !coefficients || !candidates || !blockCounts || !output || !complete) return false;
        const dim3 blocks(wordsPerRow / 512u, rows);
        const auto raw = static_cast<cudaStream_t>(stream);
        transformPairs<<<blocks, threads, 0, raw>>>(prefixes, wordsPerRow, sigma, clip,
            modulus, candidates, blockCounts);
        if (cudaGetLastError() != cudaSuccess) return false;
        compactBlocks<<<blocks, threads, 0, raw>>>(candidates, blockCounts, coefficients, output, complete, outputRows);
        return cudaGetLastError() == cudaSuccess;
    }
}
