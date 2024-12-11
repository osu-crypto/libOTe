#include "ParallelSyndromeDecoding.h"
#include <cuda_runtime.h>
#include <iostream>

namespace osuCrypto {

    __global__ void test_kernel() {
        printf("CUDA Kernel Executed\n");
    }

    void parallelSD() {
        test_kernel << <1, 1 >> > ();
        cudaError_t err = cudaDeviceSynchronize();
        if (err != cudaSuccess) {
            std::cerr << "CUDA Error: " << cudaGetErrorString(err) << std::endl;
            return;
        }
        std::cout << "CUDA included successfully!" << std::endl;
    }

} // namespace osuCrypto