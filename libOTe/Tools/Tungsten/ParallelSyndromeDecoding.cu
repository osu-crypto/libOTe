#include "ParallelSyndromeDecoding.h"
#include <algorithm>
#include <chrono>
#include <cuda_runtime.h>
#include <iostream>
#include <numeric>
#include <random>
#include <vector>
// TODO need to include cryptoTools
//#include "cryptoTools/Common/Matrix.h"
#include <thrust/shuffle.h>
#include <thrust/random.h>
#include <thrust/device_vector.h>
#include <thrust/host_vector.h>
#include <thrust/transform.h>
#include <thrust/for_each.h>
#include <thrust/transform_reduce.h>
#include <thrust/execution_policy.h>


namespace osuCrypto {

    __global__ void test_kernel() {
        printf("CUDA Kernel Executed\n");
    }

    void test_cuda_compiled() {
        test_kernel << <1, 1 >> > ();
        cudaError_t err = cudaDeviceSynchronize();
        if (err != cudaSuccess) {
            std::cerr << "CUDA Error: " << cudaGetErrorString(err) << std::endl;
            return;
        }
        std::cout << "CUDA included successfully!" << std::endl;
    }

    // Functor to initialize sequence values
    struct sequence_functor {
        __host__ __device__ int operator()(const int& i) const {
            return i;
        }
    };

    void benchmark_permutations(int n) {
        // Step 2: Set up a random number generator
        unsigned int seed = static_cast<unsigned int>(time(0)); // Random seed
        thrust::default_random_engine rng(seed);

        //
        // GPU device_vector thrust::shuffle
        //

        // Step 1: Create a device_vector with some data
        thrust::device_vector<uint64_t> d_vec(n);
        // Step 2: Fill the vector with sequential values (0, 1, 2, ..., n-1)
        thrust::transform(thrust::make_counting_iterator(0),
            thrust::make_counting_iterator(n),
            d_vec.begin(),
            sequence_functor());

        // Step 3: Set up CUDA events for timing
        cudaEvent_t start_device, stop_device;
        cudaEventCreate(&start_device);
        cudaEventCreate(&stop_device);

        // Step 4: Record the start time
        cudaEventRecord(start_device);

        // Step 5: Shuffle the device_vector
        thrust::shuffle(d_vec.begin(), d_vec.end(), rng);

        // Step 6: Record the stop time
        cudaEventRecord(stop_device);
        cudaEventSynchronize(stop_device); // Ensure GPU operations are finished

        // Step 7: Calculate the elapsed time
        float milliseconds = 0;
        cudaEventElapsedTime(&milliseconds, start_device, stop_device);

        // Print the result
        std::cout << "Time to thrust::shuffle a thrust::device_vector (GPU): " << milliseconds << " ms" << std::endl;


        // Step 8: Copy the result back to the host for printing
        // thrust::host_vector<uint64_t> h_vec = d_vec;

        //std::cout << "Shuffled GPU vector: ";
        //for (int val : h_vec) {
        //    std::cout << val << " ";
        //}
        //std::cout << std::endl;

        //
        // CPU host_vector thrust::shuffle
        //

        // Step 1: Create a host_vector with some data
        thrust::host_vector<uint64_t> h_vec(n);
        // Step 2: Fill the vector with sequential values (0, 1, 2, ..., n-1)
        thrust::transform(thrust::make_counting_iterator(0),
            thrust::make_counting_iterator(n),
            h_vec.begin(),
            sequence_functor());

        // Step 3: Measure the time to shuffle using std::chrono
        auto start_host = std::chrono::high_resolution_clock::now();

        // Step 4: Shuffle the device_vector
        thrust::shuffle(h_vec.begin(), h_vec.end(), rng);

        auto stop_host = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed_host = stop_host - start_host;

        // Step 5: Print the elapsed time
        std::cout << "Time to thrust::shuffle host_vector (CPU): " << elapsed_host.count() << " ms" << std::endl;

        //
        // CPU std::vector std::shuffle
        //

        // Step 1: Create and initialize a vector
        std::vector<int> vector_std(n);
        std::iota(vector_std.begin(), vector_std.end(), 0); // Fill with 0, 1, 2, ..., N-1

        // Step 2: Set up the random number generator
        std::random_device rd;                  // Random seed
        std::default_random_engine rng_vector(rd());   // Random number engine

        // Step 3: Measure the time to shuffle using std::chrono
        auto start_vector = std::chrono::high_resolution_clock::now();

        std::shuffle(vector_std.begin(), vector_std.end(), rng_vector);

        auto stop_vector = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed_vector = stop_vector - start_vector;

        // Step 4: Print the elapsed time
        std::cout << "Time to std::shuffle std::vector: " << elapsed_vector.count() << " ms" << std::endl;

        //std::cout << "Shuffled CPU vector: ";
        //for (int val : cpu_vector) {
        //    std::cout << val << " ";
        //}
        //std::cout << std::endl;

    }

    // Functor for Binary Block-Vector Multiplication (Column-wise)
    struct BlockVectorColumnMultiply {
        const uint8_t* matrix;  // Pointer to block matrix Gi (flattened, row-major)
        const uint8_t* vector;  // Pointer to corresponding vector slice x_i
        uint8_t* result;        // Pointer to result slice
        int sigma;             // Number of rows in the block
        int block_cols;        // Number of columns in the block (sigma * e)

        BlockVectorColumnMultiply(const uint8_t* matrix, 
            const uint8_t* vector, uint8_t* result, int sigma, int block_cols)
            : matrix(matrix), vector(vector), result(result), sigma(sigma), block_cols(block_cols) {}

        // Function can be executed on CPU (host) or GPU (device)
        __host__ __device__
            void operator()(int col) const {
            uint8_t sum = 0;
            for (int row = 0; row < sigma; ++row) {
                // Binary AND between vector value and matrix element
                sum ^= (vector[row] & matrix[row * block_cols + col]);
            }
            result[col] = sum;
        }
    };


    void parallelSD() {

        test_cuda_compiled();

        constexpr int n = 1 << 21;
        std::cout << "n: " << n << std::endl;

        benchmark_permutations(n);



    }

} // namespace osuCrypto