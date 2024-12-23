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

        // Is cuda included properly into cmake?
        test_cuda_compiled();

        //
        // client sets
        //
        constexpr int k = 9;// 1 << 20; // Total rows of G and size of vector x
        constexpr int e = 2; // Scaling factor (n/k)
        constexpr int n = e * k; // Total columns of G
        constexpr int sigma = 3;// 32; // Block row size
        constexpr int block_cols = sigma * e; // Block column size
        constexpr int t = k / sigma; // Number of blocks

        std::cout << "k: " << k << std::endl;
        std::cout << "n: " << n << std::endl;
        std::cout << "e: " << e << std::endl;
        std::cout << "sigma: " << sigma << std::endl;
        std::cout << "t: " << t << std::endl;

        // set up pseudorandom generator
        unsigned int seed = static_cast<unsigned int>(time(0)); // Random seed
        thrust::default_random_engine rng(seed);

        //
        // Benchmark different permutations
        //
        benchmark_permutations(n);

        //
        // test block multiply
        //
        // test_block_multiply();

        //
        // block multiply
        //

        using T = uint8_t; // Binary representation as uint8_t

        // --- Host Input Vector x ---
        std::vector<T> h_vector = { 1, 1, 1, 
                                            0, 0, 1, 
                                                    1, 0, 1 }; // Binary vector of size k

        // --- Host Block Matrices (G1, G2, ..., Gt) ---
        // std::vector<std::vector<T>> h_blocks(t, std::vector<T>(sigma * (sigma * e), 1));
        std::vector<std::vector<T>> h_blocks = { {1,0,1,1,1,0,
                                                  1,1,1,0,0,0,
                                                  0,1,0,1,0,1}, 
                                                               {1,1,1,1,1,1,
                                                                0,0,0,0,0,0,
                                                                1,1,1,0,0,0}, 
                                                                             {1,1,0,0,1,1,
                                                                              1,0,1,1,1,0,
                                                                              0,0,0,1,0,1} };
        // --- Host Expected xG ---
        std::vector<T> h_expected_result = {0,0,0,0,1,1,
                                                        1,1,1,0,0,0,
                                                                    1,1,0,1,1,0};

        // --- Host Result Vector ---
        std::vector<T> h_result(n, 0);

        // --- Transfer Data to GPU ---
        thrust::device_vector<T> d_vector = h_vector; // Vector x on GPU
        thrust::device_vector<T> d_result(n, 0);      // Final result vector on GPU

        for (int i = 0; i < t; ++i) {
            
            // Transfer current block Gi to GPU
            thrust::device_vector<T> d_block = h_blocks[i];
            thrust::device_vector<T> d_block_result(block_cols, 0);

            // Extract the relevant slice of vector x (size sigma)
            thrust::device_vector<T> d_vector_slice(
                d_vector.begin() + i * sigma,
                d_vector.begin() + (i + 1) * sigma
            );

            // Perform binary matrix-vector multiplication (column-wise)
            thrust::for_each(
                thrust::device,
                thrust::counting_iterator<int>(0),
                thrust::counting_iterator<int>(block_cols),
                BlockVectorColumnMultiply(
                    thrust::raw_pointer_cast(d_block.data()),
                    thrust::raw_pointer_cast(d_vector_slice.data()),
                    thrust::raw_pointer_cast(d_block_result.data()),
                    sigma,
                    block_cols
                )
            );

            // Place block result into the correct section of the final result vector
            thrust::copy(
                d_block_result.begin(),
                d_block_result.end(),
                d_result.begin() + i * block_cols
            );
        }

        // Copy results back to host
        thrust::host_vector<T> h_result_gpu = d_result;

        // Verify correctness
        for (size_t i = 0; i < n; i++) {
            std::cout << "expected at index " << i << ": " << static_cast<int>(h_expected_result[i]) << std::endl;
            std::cout << "computed at index " << i << ": " << static_cast<int>(h_result_gpu[i]) << std::endl;
            if (h_result_gpu[i] != h_expected_result[i])
                throw std::runtime_error("Computed result not as expected");
        }
        std::cout << std::endl;
    }

} // namespace osuCrypto