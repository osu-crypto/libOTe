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
#include <thrust/sequence.h>


namespace osuCrypto {

    using T = uint8_t; // Binary representation as uint8_t

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

    void benchmark_permutations() {
        constexpr int n = 1 << 21;

        // Set up a random number generator
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

        auto start_device_chrono = std::chrono::high_resolution_clock::now();

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

        auto stop_device_chrono = std::chrono::high_resolution_clock::now();

        // Print the result
        std::cout << "Time to thrust::shuffle a thrust::device_vector (GPU) using cuda events: " << 
            milliseconds << " ms" << std::endl;

        std::chrono::duration<double, std::milli> elapsed_device_chrono = stop_device_chrono - start_device_chrono;

        // Step 5: Print the elapsed time
        std::cout << "Time to thrust::shuffle a thrust::device_vector (GPU) using chrono: " << elapsed_device_chrono.count() << " ms" << std::endl;


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

    // block multiply function with thrust
    void test_thrust_block_multiply() {
        constexpr int k = 9;// 1 << 20; // Total rows of G and size of vector x
        constexpr int e = 2; // Scaling factor (n/k)
        constexpr int n = e * k; // Total columns of G
        constexpr int sigma = 3;// 32; // Block row size
        constexpr int block_cols = sigma * e; // Block column size
        constexpr int t = k / sigma; // Number of blocks

        //
        // block multiply
        //

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
        std::vector<T> h_expected_result = { 0,0,0,0,1,1,
                                                        1,1,1,0,0,0,
                                                                    1,1,0,1,1,0 };

        // --- Transfer Data to GPU ---
        thrust::device_vector<T> d_vector = h_vector; // Vector x on GPU

        // --- Final Result Vector on GPU ---
        thrust::device_vector<T> d_result(n, 0);      

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
            // std::cout << "expected at index " << i << ": " << static_cast<int>(h_expected_result[i]) << std::endl;
            // std::cout << "computed at index " << i << ": " << static_cast<int>(h_result_gpu[i]) << std::endl;
            if (h_result_gpu[i] != h_expected_result[i])
                throw std::runtime_error("Computed result not as expected");
        }
        std::cout << std::endl;
    }

    // TODO Incomplete (Entirely implemented in thrust)
    void test_code_thrust() {

        // Set up pseudorandom generator
        unsigned int seed = static_cast<unsigned int>(time(0)); // Random seed
        thrust::default_random_engine rnggpu(seed);
        std::mt19937 rngcpu(std::random_device{}()); // Random number generator
        std::bernoulli_distribution dist(0.5);    // 50% chance for 0 or 1
        /*
        //
        // Initialize x, G, and empty xG, and move them from host to device
        //
        // --- Host Input Vector x ---
        std::vector<T> h_x(k); // Binary vector of size k
        for (auto& val : h_x) {
            val = dist(rngcpu); // Generate 0 or 1 and assign to the vector
            // std::cout << static_cast<int>(val);
        }

        // --- Host Block Matrices (G1, G2, ..., Gt) ---
        std::vector<std::vector<T>> h_G(t, std::vector<T>(sigma * (sigma * e)));

        // Fill the vector with random binary values
        for (size_t i = 0; i < t; ++i) {
            for (size_t j = 0; j < h_G[0].size(); ++j) {
                h_G[i][j] = dist(rngcpu); // Assign random 0 or 1
            }
        }

        // --- Host Result Vector ---
        std::vector<T> h_xG(n, 0);

        // --- Transfer Data to GPU ---
        thrust::device_vector<T> d_x = h_x; // Vector x on GPU
        thrust::device_vector<T> d_xG(n, 0); // Final result vector on GPU
        */
        //
        // Expanding block multiply (G: kxn)
        // TODO


        //
        // Permute
        // TODO

        //
        // Block Multiply (G: nxn)
        // TODO
    }


    // Data structure for sparse matrices
    // CSR-like representation for the diagonal blocks of G (compressed sparse row)
    struct BlockMatrix {
        thrust::device_vector<T> data;      // Non-zero entries (flattened)
        thrust::device_vector<int> blockOffsets; // Starting index of each block in data
        thrust::device_vector<int> rowIndices;   // Row indices of non-zero blocks
        thrust::device_vector<int> colIndices;   // Column indices of non-zero blocks
        int sigma; // Block size
        int e;     // Expansion factor (e = n / k)
        int t;     // Number of diagonal blocks (t = k / sigma)
    };

    void initialize_block_matrix(BlockMatrix& mat, int k, int n, int sigma, 
        std::bernoulli_distribution &dist, std::mt19937 &rngcpu) {
        mat.sigma = sigma;
        mat.e = n / k;
        mat.t = k / sigma;

        // Allocate memory for block data
        mat.data.resize(mat.t * sigma * (sigma * mat.e)); // Only store non-zero blocks
        mat.blockOffsets.resize(mat.t + 1); // Start of each block in data
        mat.rowIndices.resize(mat.t); // Row start for each block
        mat.colIndices.resize(mat.t); // Col start for each block

        // Fill the vector with random binary values
        std::vector<T> h_mat(mat.data.size());
        for (size_t i = 0; i < mat.data.size(); ++i) {
            h_mat[i] = dist(rngcpu); // Assign random 0 or 1
        }
        mat.data = h_mat;
        // 0, sigma(sigma*e), 2sigma(sigma*e), 3sigma(sigma*e), etc.
        thrust::sequence(mat.blockOffsets.begin(), mat.blockOffsets.end(), 0, sigma * (sigma * mat.e));
        // 0, sigma, 2sigma, 3sigma, etc.
        thrust::sequence(mat.rowIndices.begin(), mat.rowIndices.end(), 0, sigma);
        // 0, sigma * e, 2sigma * e, 3sigma * e, etc.
        thrust::sequence(mat.colIndices.begin(), mat.colIndices.end(), 0, sigma * mat.e);
    }

    __global__ void sparse_vector_matrix_mul(
        const T* x,
        const T* blockData,
        const int* blockOffsets,
        const int* rowIndices,
        const int* colIndices,
        T* result,
        int sigma, int e, int t) {
        int blockIdxGlobal = blockIdx.x; // [0,t)
        int threadIdxLocal = threadIdx.x; // [0,sigma*e)

        if (blockIdxGlobal < t) {
            int row_start = rowIndices[blockIdxGlobal];
            int col_start = colIndices[blockIdxGlobal];
            int data_start = blockOffsets[blockIdxGlobal];

            if (threadIdxLocal < sigma * e) {
                T temp = 0;
                for (int row = 0; row < sigma; ++row) {
                    temp ^= (x[row_start + row] & blockData[data_start + threadIdxLocal + row * (sigma * e)]);
                }
                result[col_start + threadIdxLocal] = temp;
            }
        }
    }

    void sparse_vector_matrix_mul_host(const thrust::device_vector<T>& x,
        const BlockMatrix& mat,
        thrust::device_vector<T>& result) {
        int threadsPerBlock = mat.sigma * mat.e;
        int numBlocks = mat.t;

        sparse_vector_matrix_mul << <numBlocks, threadsPerBlock >> > (
            thrust::raw_pointer_cast(x.data()),
            thrust::raw_pointer_cast(mat.data.data()),
            thrust::raw_pointer_cast(mat.blockOffsets.data()),
            thrust::raw_pointer_cast(mat.rowIndices.data()),
            thrust::raw_pointer_cast(mat.colIndices.data()),
            thrust::raw_pointer_cast(result.data()),
            mat.sigma, mat.e, mat.t
            );

        cudaDeviceSynchronize();
    }

    void gpu_shuffle(thrust::device_vector<T>& data) {
        thrust::default_random_engine rnggpu(static_cast<unsigned int>(time(0)));
        thrust::shuffle(data.begin(), data.end(), rnggpu);
    }

    void code_cuda(const thrust::device_vector<T>& x,
        const BlockMatrix& G,
        const BlockMatrix& H,
        thrust::device_vector<T>& result) {
        thrust::device_vector<T> intermediate_result(result.size());

         // Step 1: xG Multiplication
         sparse_vector_matrix_mul_host(x, G, intermediate_result);

         // Step 2: Shuffle
         gpu_shuffle(intermediate_result);

         // Step 3: xH Multiplication
         sparse_vector_matrix_mul_host(intermediate_result, H, result);
    }

    // block multiply function with cuda written kernels
    void test_cuda_block_multiply() {
        constexpr int k = 9;// 1 << 20; // Total rows of G and size of vector x
        constexpr int e = 2; // Scaling factor (n/k)
        constexpr int n = e * k; // Total columns of G
        constexpr int sigma = 3;// 32; // Block row size
        constexpr int t = k / sigma; // Number of blocks

        //
        // block multiply
        //

        // --- Host Input Vector x ---
        std::vector<T> h_vector = { 1, 1, 1,
                                            0, 0, 1,
                                                    1, 0, 1 }; // Binary vector of size k

        // --- Host Block Matrices (G1, G2, ..., Gt) ---
        // std::vector<std::vector<T>> h_blocks(t, std::vector<T>(sigma * (sigma * e), 1));
        std::vector<T> h_blocks = { 1,0,1,1,1,0,
                                    1,1,1,0,0,0,
                                    0,1,0,1,0,1,
                                                1,1,1,1,1,1,
                                                0,0,0,0,0,0,
                                                1,1,1,0,0,0,
                                                            1,1,0,0,1,1,
                                                            1,0,1,1,1,0,
                                                            0,0,0,1,0,1 };
        BlockMatrix d_blocks;
        d_blocks.data = h_blocks;
        d_blocks.blockOffsets.resize(t + 1);
        d_blocks.rowIndices.resize(t);
        d_blocks.colIndices.resize(t);
        thrust::sequence(d_blocks.blockOffsets.begin(), d_blocks.blockOffsets.end(), 0, sigma * (sigma * e));
        thrust::sequence(d_blocks.rowIndices.begin(), d_blocks.rowIndices.end(), 0, sigma);
        thrust::sequence(d_blocks.colIndices.begin(), d_blocks.colIndices.end(), 0, sigma * e);
        d_blocks.sigma = sigma;
        d_blocks.e = e;
        d_blocks.t = t;

        // --- Host Expected xG ---
        std::vector<T> h_expected_result = { 0,0,0,0,1,1,
                                                        1,1,1,0,0,0,
                                                                    1,1,0,1,1,0 };

        // --- Transfer Data to GPU ---
        thrust::device_vector<T> d_vector = h_vector; // Vector x on GPU

        // --- Final Result Vector on GPU ---
        thrust::device_vector<T> d_result(n, 0);

        sparse_vector_matrix_mul_host(d_vector, d_blocks, d_result);

        // Copy results back to host
        thrust::host_vector<T> h_result_gpu = d_result;

        // Verify correctness
        for (size_t i = 0; i < n; i++) {
            // std::cout << "expected at index " << i << ": " << static_cast<int>(h_expected_result[i]) << std::endl;
            // std::cout << "computed at index " << i << ": " << static_cast<int>(h_result_gpu[i]) << std::endl;
            if (h_result_gpu[i] != h_expected_result[i])
                throw std::runtime_error("Computed result not as expected");
        }
        std::cout << std::endl;
    }


    void benchmark_code_cuda() {

        // Set up pseudorandom generator
        std::mt19937 rngcpu(std::random_device{}()); // Random number generator
        std::bernoulli_distribution dist(0.5);    // 50% chance for 0 or 1

        constexpr int k = 1 << 20; // 2^20
        constexpr int n = 1 << 21; // 2^21
        constexpr int sigma = 64;  // Block size

        std::cout << "k: " << k << std::endl;
        std::cout << "n: " << n << std::endl;
        std::cout << "sigma: " << sigma << std::endl;

        //
        // Initialize x, G, and empty xG, and move them from host to device
        //
        // --- Host Input Vector x ---
        std::vector<T> h_x(k); // Binary vector of size k
        for (auto& val : h_x) {
            val = dist(rngcpu); // Generate 0 or 1 and assign to the vector
            // std::cout << static_cast<int>(val);
        }

        // --- Transfer Data to GPU ---
        thrust::device_vector<T> d_x = h_x; // Vector x on GPU
        // --- Final result vector on GPU ---

        thrust::device_vector<T> d_xG(n, 0);

        BlockMatrix G, H;
        initialize_block_matrix(G, k, n, sigma, dist, rngcpu);
        initialize_block_matrix(H, n, k, sigma, dist, rngcpu);

        auto start = std::chrono::high_resolution_clock::now();
        code_cuda(d_x, G, H, d_xG);
        auto stop = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = stop - start;

        // Step 4: Print the elapsed time
        std::cout << "Time to compute the code implemented with cuda kernels: " << 
            elapsed.count() << " ms" << std::endl;

        // Optionally copy results back to host
        // thrust::host_vector<T> h_xG = d_xG;        
    }


    void parallelSD() {

        // Is cuda included properly into cmake?
        test_cuda_compiled();

        //
        // test block multiply with thrust and cuda
        //
        test_thrust_block_multiply();
        test_cuda_block_multiply();

        //
        // Benchmark different permutations
        //
        benchmark_permutations();

        //
        // TODO INCOMPLETE test_code_thrust()
        //

        //
        // TODO test code cuda
        //
        benchmark_code_cuda();

    }

} // namespace osuCrypto