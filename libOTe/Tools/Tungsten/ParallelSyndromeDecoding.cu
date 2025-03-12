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
        std::cout << "CUDA included successfully!\n" << std::endl;
    }

    // Functor to initialize sequence values
    struct sequence_functor {
        __host__ __device__ int operator()(const int& i) const {
            return i;
        }
    };


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

    template <typename RandomIterator, typename URBG>
    void shuffle_chunks(
        thrust::cuda_cub::par_t exec,
        RandomIterator first, RandomIterator last,
        std::size_t chunk_size, URBG&& g) {
        using InputType = typename thrust::iterator_value_t<RandomIterator>;

        // Total number of elements
        std::size_t total_size = last - first;

        // Iterate over each chunk
        for (std::size_t chunk_start = 0; chunk_start < total_size; chunk_start += chunk_size) {
            // Calculate the start and end of the current chunk
            auto chunk_end = thrust::min(chunk_start + chunk_size, total_size);

            // Create a temporary vector for the current chunk
            thrust::device_vector<InputType> temp(first + chunk_start, first + chunk_end);

            // Shuffle the temporary vector
            thrust::shuffle(temp.begin(), temp.end(), g);

            // Copy the shuffled data back to the original range
            thrust::copy(exec, temp.begin(), temp.end(), first + chunk_start);
        }
    }

    // block multiply function with thrust
    // NOTE currently tests only for uint8_t as BlockVectorColumnMultiply is for uint8_t only
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
        std::vector<uint8_t> h_vector = { 1, 1, 1,
                                                   0, 0, 1,
                                                            1, 0, 1 }; // Binary vector of size k

        // --- Host Block Matrices (G1, G2, ..., Gt) ---
        // std::vector<std::vector<uint8_t>> h_blocks(t, std::vector<uint8_t>(sigma * (sigma * e), 1));
        std::vector<std::vector<uint8_t>> h_blocks = { {1,0,1,1,1,0,
                                                        1,1,1,0,0,0,
                                                        0,1,0,1,0,1},
                                                                   {1,1,1,1,1,1,
                                                                    0,0,0,0,0,0,
                                                                    1,1,1,0,0,0},
                                                                                 {1,1,0,0,1,1,
                                                                                  1,0,1,1,1,0,
                                                                                  0,0,0,1,0,1} };
        // --- Host Expected xG ---
        std::vector<uint8_t> h_expected_result = { 0,0,0,0,1,1,
                                                               1,1,1,0,0,0,
                                                                           1,1,0,1,1,0 };

        // --- Transfer Data to GPU ---
        thrust::device_vector<uint8_t> d_vector = h_vector; // Vector x on GPU

        // --- Final Result Vector on GPU ---
        thrust::device_vector<uint8_t> d_result(n, 0);

        for (int i = 0; i < t; ++i) {

            // Transfer current block Gi to GPU
            thrust::device_vector<uint8_t> d_block = h_blocks[i];
            thrust::device_vector<uint8_t> d_block_result(block_cols, 0);

            // Extract the relevant slice of vector x (size sigma)
            thrust::device_vector<uint8_t> d_vector_slice(
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
        thrust::host_vector<uint8_t> h_result_gpu = d_result;

        // Verify correctness
        for (size_t i = 0; i < n; i++) {
            // std::cout << "expected at index " << i << ": " << static_cast<int>(h_expected_result[i]) << std::endl;
            // std::cout << "computed at index " << i << ": " << static_cast<int>(h_result_gpu[i]) << std::endl;
            if (h_result_gpu[i] != h_expected_result[i])
                throw std::runtime_error("Computed result not as expected");
        }
        std::cout << std::endl;
    }

    // mixing hash function (MurmurHash3)
    __device__
        unsigned int murmurhashhash(unsigned int x) {
        x ^= x >> 16;
        x *= 0x85ebca6b;
        x ^= x >> 13;
        x *= 0xc2b2ae35;
        x ^= x >> 16;
        return x;
    }

    // Xorshift-based hash function
    __device__
        unsigned int xorshifthash(unsigned int x) {
        // Force x to be non-zero using a bitwise OR with 1
        x |= 1;

        // Xorshift operations
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        return x;
    }

    // Functor for generating random binary values (0 or 1)
    struct RandomBinaryFunctor {
        unsigned int seed;

        __host__ __device__
            RandomBinaryFunctor(unsigned int seed) : seed(seed) {}

        __device__
            int operator()(const int& index) const {
            // Combine the seed and index for pseudo-randomness
            //unsigned int value = murmurhashhash(seed ^ index);
            unsigned int value = xorshifthash(seed ^ index);
            return value & 1; // Return the least significant bit (0 or 1)
        }
    };


    // Data structure for sparse matrices
    // CSR-like representation for the diagonal blocks of G (compressed sparse row)
    struct BlockMatrix {
        thrust::device_vector<uint8_t> data;      // Non-zero entries (flattened)
        thrust::device_vector<int> blockOffsets; // Starting index of each block in data
        thrust::device_vector<int> rowIndices;   // Row indices of non-zero blocks
        thrust::device_vector<int> colIndices;   // Column indices of non-zero blocks
        int sigma; // Block size
        int e;     // Expansion factor (e = n / k)
        int t;     // Number of diagonal blocks (t = k / sigma)
    };

    struct MulHelper {
        thrust::device_vector<int> blockOffsets; // Starting index of each block in data
        thrust::device_vector<int> rowIndices;   // Row indices of non-zero blocks
        thrust::device_vector<int> colIndices;   // Column indices of non-zero blocks
        int sigma; // Block size
        int e;     // Expansion factor (e = n / k)
        int t;     // Number of diagonal blocks (t = k / sigma at the beginning, n/sigma afterward)
    };

    struct MulHelperV2 {
        thrust::device_vector<int> blockOffsets; // Starting index of each block in data
        thrust::device_vector<int> rowIndices;   // Row indices of non-zero blocks
        thrust::device_vector<int> colIndices;   // Column indices of non-zero blocks
        int sigma; // Block size
        int e;     // Expansion factor (e = n / k)
        int t;     // Number of diagonal blocks (t = k / sigma at the beginning, n/sigma afterward)
        int block_num_rows; // sigma if expanding, sigma * e if compressing
        int block_num_cols; // sigma * e if expanding, sigma if compressing
    };

    struct MulHelperV3 {
        thrust::device_vector<int> rowIndices;   // Row indices of non-zero blocks
        thrust::device_vector<int> colIndices;   // Column indices of non-zero blocks
        int t;     // Number of diagonal blocks (t = k / sigma at the beginning, n/sigma afterward)
        int block_num_rows; // sigma if expanding, sigma * e if compressing
        int block_num_cols; // sigma * e if expanding, sigma if compressing
    };

    void initialize_block_matrix(BlockMatrix& mat, int sigma, int k, int n, 
        std::bernoulli_distribution &dist, std::mt19937 &rngcpu) {
        mat.sigma = sigma;
        mat.e = n/k;
        mat.t = k/sigma;

        // Allocate memory for block data
        mat.data.resize(mat.t * sigma * (sigma * mat.e)); // Only store non-zero blocks
        mat.blockOffsets.resize(mat.t + 1); // Start of each block in data
        mat.rowIndices.resize(mat.t); // Row start for each block
        mat.colIndices.resize(mat.t); // Col start for each block

        // Fill the vector with random binary values
        std::vector<uint8_t> h_mat(mat.data.size());
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

    void initialize_block_matrix_v2(BlockMatrix& mat, int sigma, int e, int t) {
        mat.sigma = sigma;
        mat.e = e;
        mat.t = t;

        // Allocate memory for block data
        mat.data.resize(mat.t * mat.sigma * (mat.sigma * mat.e)); // Only store non-zero blocks
        mat.blockOffsets.resize(mat.t + 1); // Start of each block in data
        mat.rowIndices.resize(mat.t); // Row start for each block
        mat.colIndices.resize(mat.t); // Col start for each block

        // Fill the vector with random binary values - with help of murmurhash3 or xorshift hash function
        // directly on GPU but currently slow as  randombinaryfunctor not done well
        thrust::transform(
            thrust::device,
            thrust::counting_iterator<int>(0),
            thrust::counting_iterator<int>(mat.data.size()),
            mat.data.begin(),
            RandomBinaryFunctor(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch()).count())
        );

        // Copy back to host to print
        //thrust::host_vector<int> host_data = mat.data;
        //for (int i = 0; i < mat.data.size(); i++) {
        //    std::cout << host_data[i] << " ";
        //}
        //std::cout << std::endl;

        // 0, sigma(sigma*e), 2sigma(sigma*e), 3sigma(sigma*e), etc.
        thrust::sequence(mat.blockOffsets.begin(), mat.blockOffsets.end(), 0, sigma * (sigma * mat.e));
        // 0, sigma, 2sigma, 3sigma, etc.
        thrust::sequence(mat.rowIndices.begin(), mat.rowIndices.end(), 0, sigma);
        // 0, sigma * e, 2sigma * e, 3sigma * e, etc.
        thrust::sequence(mat.colIndices.begin(), mat.colIndices.end(), 0, sigma * mat.e);
    }

    void initialize_random_block_matrix(
        thrust::device_vector<uint8_t>& data, int sigma, int e, int t) {
        // Make sure data is of the right size
        // note that the memory has already been allocated to avoid allocating memory each time we invoke it
        if (data.size() != (t * sigma * (sigma * e))) throw std::runtime_error("data not of the right size");

        // Fill the vector with random binary values - with help of murmurhash3 or xorshift hash function
        // directly on GPU but currently slow as  randombinaryfunctor not done well
        thrust::transform(
            thrust::device,
            thrust::counting_iterator<int>(0),
            thrust::counting_iterator<int>(data.size()),
            data.begin(),
            RandomBinaryFunctor(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch()).count())
        );

        // Copy back to host to print
        //thrust::host_vector<int> host_data = data;
        //for (int i = 0; i < data.size(); i++) {
        //    std::cout << host_data[i] << " ";
        //}
        //std::cout << std::endl;
    }

    void initialize_mul_helper(MulHelper& mul_helper, int sigma, int e, int t) {
        mul_helper.sigma = sigma;
        mul_helper.e = e;
        mul_helper.t = t;

        // Allocate memory for block data
        mul_helper.blockOffsets.resize(t + 1); // Start of each block in data
        mul_helper.rowIndices.resize(t); // Row start for each block
        mul_helper.colIndices.resize(t); // Col start for each block

        // 0, sigma(sigma*e), 2sigma(sigma*e), 3sigma(sigma*e), etc.
        thrust::sequence(mul_helper.blockOffsets.begin(), 
            mul_helper.blockOffsets.end(), 0, sigma * (sigma * e));
        // 0, sigma, 2sigma, 3sigma, etc.
        thrust::sequence(mul_helper.rowIndices.begin(), mul_helper.rowIndices.end(), 0, sigma);
        // 0, sigma * e, 2sigma * e, 3sigma * e, etc.
        thrust::sequence(mul_helper.colIndices.begin(), mul_helper.colIndices.end(), 0, sigma * e);
    }

    void initialize_mul_helper_expandorequal(MulHelperV2& mul_helper, int sigma, int e, int t) {
        mul_helper.sigma = sigma;
        mul_helper.e = e;
        mul_helper.t = t;
        mul_helper.block_num_rows = sigma;
        mul_helper.block_num_cols = sigma * e;
        
        // Allocate memory for block data
        mul_helper.blockOffsets.resize(t + 1); // Start of each block in data
        mul_helper.rowIndices.resize(t); // Row start for each block
        mul_helper.colIndices.resize(t); // Col start for each block

        // 0, sigma(sigma*e), 2sigma(sigma*e), 3sigma(sigma*e), etc.
        thrust::sequence(mul_helper.blockOffsets.begin(),
            mul_helper.blockOffsets.end(), 0, sigma * (sigma * e));
        // 0, sigma, 2sigma, 3sigma, etc.
        thrust::sequence(mul_helper.rowIndices.begin(), mul_helper.rowIndices.end(), 0, sigma);
        // 0, sigma * e, 2sigma * e, 3sigma * e, etc.
        thrust::sequence(mul_helper.colIndices.begin(), mul_helper.colIndices.end(), 0, sigma * e);
    }

    void initialize_mul_helper_expandorequal_v2(MulHelperV3& mul_helper, int sigma, int e, int t) {
        mul_helper.t = t;
        mul_helper.block_num_rows = sigma;
        mul_helper.block_num_cols = sigma * e;

        // Allocate memory for block data
        mul_helper.rowIndices.resize(t); // Row start for each block
        mul_helper.colIndices.resize(t); // Col start for each block

        // 0, sigma, 2sigma, 3sigma, etc.
        thrust::sequence(mul_helper.rowIndices.begin(), mul_helper.rowIndices.end(), 0, sigma);
        // 0, sigma * e, 2sigma * e, 3sigma * e, etc.
        thrust::sequence(mul_helper.colIndices.begin(), mul_helper.colIndices.end(), 0, sigma * e);
    }

    void initialize_mul_helper_compress(MulHelperV2& mul_helper, int sigma, int e, int t) {
        mul_helper.sigma = sigma;
        mul_helper.e = e;
        mul_helper.t = t;
        mul_helper.block_num_rows = sigma * e;
        mul_helper.block_num_cols = sigma;

        // Allocate memory for block data
        mul_helper.blockOffsets.resize(t + 1); // Start of each block in data
        mul_helper.rowIndices.resize(t); // Row start for each block
        mul_helper.colIndices.resize(t); // Col start for each block

        // 0, sigma(sigma*e), 2sigma(sigma*e), 3sigma(sigma*e), etc.
        thrust::sequence(mul_helper.blockOffsets.begin(),
            mul_helper.blockOffsets.end(), 0, sigma * (sigma * e));
        // 0, sigma * e, 2sigma * e, 3sigma * e, etc.
        thrust::sequence(mul_helper.rowIndices.begin(), mul_helper.rowIndices.end(), 0, sigma * e);
        // 0, sigma, 2sigma, 3sigma, etc.
        thrust::sequence(mul_helper.colIndices.begin(), mul_helper.colIndices.end(), 0, sigma);
    }

    void initialize_mul_helper_compress_v2(MulHelperV3& mul_helper, int sigma, int e, int t) {
        mul_helper.t = t;
        mul_helper.block_num_rows = sigma * e;
        mul_helper.block_num_cols = sigma;

        // Allocate memory for block data
        mul_helper.rowIndices.resize(t); // Row start for each block
        mul_helper.colIndices.resize(t); // Col start for each block

        // 0, sigma * e, 2sigma * e, 3sigma * e, etc.
        thrust::sequence(mul_helper.rowIndices.begin(), mul_helper.rowIndices.end(), 0, sigma * e);
        // 0, sigma, 2sigma, 3sigma, etc.
        thrust::sequence(mul_helper.colIndices.begin(), mul_helper.colIndices.end(), 0, sigma);
    }

    template <typename T>
    __global__ void sparse_vector_matrix_mul(
        const T* x, // field
        const uint8_t* blockData, // binary
        const int* blockOffsets,
        const int* rowIndices,
        const int* colIndices,
        T* result, // field
        int sigma, int e, int t) {
        int blockIdxGlobal = blockIdx.x; // [0,t)
        int threadIdxLocal = threadIdx.x; // [0,sigma*e)

        if (blockIdxGlobal < t) {
            int row_start = rowIndices[blockIdxGlobal];
            int col_start = colIndices[blockIdxGlobal];
            int data_start = blockOffsets[blockIdxGlobal];

            // good memory coalescing
            if (threadIdxLocal < sigma * e) {
                T temp = 0;
                for (int row = 0; row < sigma; ++row) {
                    // line below if both binary
                    //temp ^= (x[row_start + row] & blockData[data_start + threadIdxLocal + row * (sigma * e)]);
                    temp += x[row_start + row] &
                        static_cast<T>(
                            -static_cast<int8_t>(
                                blockData[data_start + threadIdxLocal + row * (sigma * e)]
                            )
                        );
                }
                result[col_start + threadIdxLocal] = temp;
            }
        }
    }

    template <typename T>
    __global__ void sparse_vector_matrix_mul_v2(
        const T* x, // field
        const uint8_t* blockData, // binary
        const int* blockOffsets,
        const int* rowIndices,
        const int* colIndices,
        T* result, // field
        int sigma, int e, int t) {

        uint64_t tid = threadIdx.x + blockIdx.x * blockDim.x; // [0-n): Compute global thread ID
        uint64_t code_block_idx = tid / (sigma * e);  // [0,t): Identify the block (the chunk of the array i am multiplying)
        int code_block_idx_within = tid % (sigma * e); // [0, sigma * e)

        if (code_block_idx < t) {
            int row_start = rowIndices[code_block_idx];
            int col_start = colIndices[code_block_idx];
            int data_start = blockOffsets[code_block_idx];

            // good memory coalescing
            if (code_block_idx_within < sigma * e) {
                T temp = 0;
                for (int row = 0; row < sigma; ++row) {
                    // line below if both binary
                    //temp ^= (x[row_start + row] & blockData[data_start + code_block_idx_within + row * (sigma * e)]);
                    temp += x[row_start + row] &
                        static_cast<T>(
                            -static_cast<int8_t>(
                                blockData[data_start + code_block_idx_within + row * (sigma * e)]
                                )
                            );
                }
                result[col_start + code_block_idx_within] = temp;
            }
        }
    }



    template <typename T>
    __global__ void sparse_vector_matrix_mul_v3(
        const T* x, // field
        const uint8_t* blockData, // binary
        const int* blockOffsets,
        const int* rowIndices,
        const int* colIndices,
        T* result, // field
        int sigma, int t,
        int block_num_rows,
        int block_num_cols) {

        uint64_t tid = threadIdx.x + blockIdx.x * blockDim.x; // [0-n) if expanding or [0-k) if compressing: Compute global thread ID
        uint64_t code_block_idx = tid / block_num_cols;  // [0,t): Identify the block (the chunk of the array i am multiplying)
        int code_block_idx_within = tid % block_num_cols; // [0, sigma * e) if expanding or [0,sigma] if compressing

        if (code_block_idx < t) {
            int row_start = rowIndices[code_block_idx];
            int col_start = colIndices[code_block_idx];
            int data_start = blockOffsets[code_block_idx];

            // good memory coalescing
            if (code_block_idx_within < block_num_cols) {
                T temp = 0;
                for (int row = 0; row < block_num_rows; ++row) {
                    // line below if both binary
                    //temp ^= (x[row_start + row] & blockData[data_start + code_block_idx_within + row * (sigma * e)]);
                    // but x is gf128
                    temp += x[row_start + row] &
                        static_cast<T>(
                            -static_cast<int8_t>(
                                blockData[data_start + row * block_num_cols + code_block_idx_within]
                                )
                            ); // note that these casts ensure the value is 1111....1 if blockData is 1
                }
                result[col_start + code_block_idx_within] = temp;
            }
        }
    }


    template <typename T>
    __global__ void sparse_vector_matrix_mul_v4(
        const T* x, // field
        const int* rowIndices,
        const int* colIndices,
        T* result, // field
        int t,
        int block_num_rows,
        int block_num_cols,
        unsigned int seed) {

        uint64_t tid = threadIdx.x + blockIdx.x * blockDim.x; // [0-n) if expanding or [0-k) if compressing: Compute global thread ID
        uint64_t code_block_idx = tid / block_num_cols;  // [0,t): Identify the block (the chunk of the array i am multiplying)
        int code_block_idx_within = tid % block_num_cols; // [0, sigma * e) if expanding or [0,sigma] if compressing

        if (code_block_idx < t) {
            int row_start = rowIndices[code_block_idx];
            int col_start = colIndices[code_block_idx];

            // good memory coalescing
            if (code_block_idx_within < block_num_cols) {
                T temp = 0;
                //for (int row = 0; row < block_num_rows; ++row) {
                //    // line below if both binary
                //    //temp ^= (x[row_start + row] & blockData[data_start + code_block_idx_within + row * (sigma * e)]);
                //    // but x is gf128
                //    temp += x[row_start + row] &
                //        static_cast<T>(
                //            -static_cast<int>(
                //                xorshifthash(seed ^ tid ^ row) & 1
                //                )
                //            ); // note that these casts ensure the value is 1111....1 if blockData is 1
                //}

                for (int row = 0; row < block_num_rows; row += 32) {
                    unsigned int mask = xorshifthash(seed ^ tid ^ row); // 32-bit output
                    for (int bit_pos = 0; bit_pos < 32; bit_pos++) {
                        temp += x[row_start + row + bit_pos] &
                            static_cast<T>(
                                -static_cast<int>(
                                    (mask >> bit_pos) & 1
                                    )
                                ); // note that these casts ensure the value is 1111....1 if blockData is 1
                    }
                }
                result[col_start + code_block_idx_within] = temp;
            }
        }
    }


    // DEPRECATED
    template <typename T>
    void sparse_vector_matrix_mul_host(
        const thrust::device_vector<T>& x,
        const BlockMatrix& mat,
        thrust::device_vector<T>& result) {
        std::cout << "DEPRECATED, USE V2 INSTEAD" << std::endl;

        int threadsPerBlock = mat.sigma * mat.e;
        int numBlocks = mat.t;

        if (threadsPerBlock > 1024) {
            throw std::runtime_error("Block can have at most 1024 threads");
        }

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

        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            throw std::runtime_error(cudaGetErrorString(err));
        }
    }

    template <typename T>
    void sparse_vector_matrix_mul_host_v2(
        const thrust::device_vector<T>& x,
        const BlockMatrix& mat,
        thrust::device_vector<T>& result) {
        int threadsPerBlock = 256;
        int numBlocks = (mat.sigma * mat.e * mat.t + threadsPerBlock - 1) / threadsPerBlock;

        sparse_vector_matrix_mul_v2 << <numBlocks, threadsPerBlock >> > (
            thrust::raw_pointer_cast(x.data()),
            thrust::raw_pointer_cast(mat.data.data()),
            thrust::raw_pointer_cast(mat.blockOffsets.data()),
            thrust::raw_pointer_cast(mat.rowIndices.data()),
            thrust::raw_pointer_cast(mat.colIndices.data()),
            thrust::raw_pointer_cast(result.data()),
            mat.sigma, mat.e, mat.t
        );

        cudaDeviceSynchronize();

        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            throw std::runtime_error(cudaGetErrorString(err));
        }
    }

    // DEPRECATED
    template <typename T>
    void sparse_vector_matrix_mul_with_init_host(
        const thrust::device_vector<T>& x,
        int start_x,
        thrust::device_vector<T>& result,
        int start_result,
        int sigma, int e, int t) {
        std::cout << "DEPRECATED, USE V2 INSTEAD" << std::endl;

        BlockMatrix mat;
        initialize_block_matrix_v2(mat, sigma, e, t);

        int threadsPerBlock = sigma * e;
        if (threadsPerBlock > 1024) {
            throw std::runtime_error("Block can have at most 1024 threads");
        }

        sparse_vector_matrix_mul << <t, threadsPerBlock >> > (
            thrust::raw_pointer_cast(x.data()) + start_x,
            thrust::raw_pointer_cast(mat.data.data()),
            thrust::raw_pointer_cast(mat.blockOffsets.data()),
            thrust::raw_pointer_cast(mat.rowIndices.data()),
            thrust::raw_pointer_cast(mat.colIndices.data()),
            thrust::raw_pointer_cast(result.data()) + start_result,
            sigma, e, t
        );

        cudaDeviceSynchronize();

        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            throw std::runtime_error(cudaGetErrorString(err));
        }
    }

    template <typename T>
    void sparse_vector_matrix_mul_with_init_host_v2(
        const thrust::device_vector<T>& x,
        int start_x,
        thrust::device_vector<T>& result,
        int start_result,
        int sigma, int e, int t) {
        BlockMatrix mat;
        initialize_block_matrix_v2(mat, sigma, e, t);

        int threadsPerBlock = 256;
        int numBlocks = (mat.sigma * mat.e * mat.t + threadsPerBlock - 1) / threadsPerBlock;

        sparse_vector_matrix_mul_v2 << <numBlocks, threadsPerBlock >> > (
            thrust::raw_pointer_cast(x.data()) + start_x,
            thrust::raw_pointer_cast(mat.data.data()),
            thrust::raw_pointer_cast(mat.blockOffsets.data()),
            thrust::raw_pointer_cast(mat.rowIndices.data()),
            thrust::raw_pointer_cast(mat.colIndices.data()),
            thrust::raw_pointer_cast(result.data()) + start_result,
            sigma, e, t
            );

        cudaDeviceSynchronize();

        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            throw std::runtime_error(cudaGetErrorString(err));
        }
    }

    template <typename T>
    void sparse_vector_matrix_mul_with_init_host_v3(
        const thrust::device_vector<T>& x,
        int start_x,
        thrust::device_vector<T>& result,
        int start_result,
        thrust::device_vector<uint8_t> &mat,
        MulHelper& mulHelper) {

        initialize_random_block_matrix(
            mat,
            mulHelper.sigma, mulHelper.e, mulHelper.t);

        int threadsPerBlock = 256;
        int numBlocks = (mulHelper.sigma * mulHelper.e * mulHelper.t + threadsPerBlock - 1) / threadsPerBlock;

        sparse_vector_matrix_mul_v2 << <numBlocks, threadsPerBlock >> > (
            thrust::raw_pointer_cast(x.data()) + start_x,
            thrust::raw_pointer_cast(mat.data()),
            thrust::raw_pointer_cast(mulHelper.blockOffsets.data()),
            thrust::raw_pointer_cast(mulHelper.rowIndices.data()),
            thrust::raw_pointer_cast(mulHelper.colIndices.data()),
            thrust::raw_pointer_cast(result.data()) + start_result,
            mulHelper.sigma, mulHelper.e, mulHelper.t
            );

        cudaDeviceSynchronize();

        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            throw std::runtime_error(cudaGetErrorString(err));
        }
    }


    template <typename T>
    void sparse_vector_matrix_mul_with_init_host_v4(
        const thrust::device_vector<T>& x,
        int start_x,
        thrust::device_vector<T>& result,
        int start_result,
        thrust::device_vector<uint8_t>& mat,
        MulHelperV2& mulHelper) {
        
        initialize_random_block_matrix(
            mat,
            mulHelper.sigma, mulHelper.e, mulHelper.t);

        int threadsPerBlock = 256;
        int numBlocks = (mulHelper.block_num_cols * mulHelper.t + threadsPerBlock - 1) / threadsPerBlock;
        
        sparse_vector_matrix_mul_v3 << <numBlocks, threadsPerBlock >> > (
            thrust::raw_pointer_cast(x.data()) + start_x,
            thrust::raw_pointer_cast(mat.data()),
            thrust::raw_pointer_cast(mulHelper.blockOffsets.data()),
            thrust::raw_pointer_cast(mulHelper.rowIndices.data()),
            thrust::raw_pointer_cast(mulHelper.colIndices.data()),
            thrust::raw_pointer_cast(result.data()) + start_result,
            mulHelper.sigma, mulHelper.t,
            mulHelper.block_num_rows, mulHelper.block_num_cols
            );

        cudaDeviceSynchronize();

        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            throw std::runtime_error(cudaGetErrorString(err));
        }
    }

    template <typename T>
    void sparse_vector_matrix_mul_with_init_host_v5(
        thrust::device_ptr<T> x,
        thrust::device_ptr<T> result,
        MulHelperV3& mulHelper) {

        unsigned int seed = 12345;

        int threadsPerBlock = 256;
        int numBlocks = (mulHelper.block_num_cols * mulHelper.t + threadsPerBlock - 1) / threadsPerBlock;

        sparse_vector_matrix_mul_v4 << <numBlocks, threadsPerBlock >> > (
            thrust::raw_pointer_cast(x),
            thrust::raw_pointer_cast(mulHelper.rowIndices.data()),
            thrust::raw_pointer_cast(mulHelper.colIndices.data()),
            thrust::raw_pointer_cast(result),
            mulHelper.t,
            mulHelper.block_num_rows, 
            mulHelper.block_num_cols,
            seed
            );

        cudaDeviceSynchronize();

        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            throw std::runtime_error(cudaGetErrorString(err));
        }
    }

    template <typename T>
    void gpu_shuffle(thrust::device_vector<T>& data) {
        thrust::default_random_engine rnggpu(static_cast<unsigned int>(time(0)));
        thrust::shuffle(data.begin(), data.end(), rnggpu);
    }

    template <typename T>
    void code_cuda(
        const thrust::device_vector<T>& x,
        const BlockMatrix& G,
        const BlockMatrix& H,
        thrust::device_vector<T>& result) {
        thrust::device_vector<T> intermediate_result(result.size());

         // Step 1: xG Multiplication
         sparse_vector_matrix_mul_host_v2<T>(x, G, intermediate_result);

         // Step 2: Shuffle
         gpu_shuffle<T>(intermediate_result);

         // Step 3: xH Multiplication
         sparse_vector_matrix_mul_host_v2<T>(intermediate_result, H, result);
    }

    template <typename T>
    void recursive_code_cuda(
        const thrust::device_vector<T>& x, // does not change across recursion, we index into it
        int start_x, // index to the part of x i am recursing on
        thrust::device_vector<T>& result,
        int start_result, // index to the part of result i am recursing on
        std::vector<int> &sigma, // one for each recursive depth (will be roughly 2sqrt(k) each time, set such that t stays the same???)
        int k,
        int n,
        int e,
        int currRecursiveDepth,
        int baseRecursiveDepth) {

        int t = k / sigma[currRecursiveDepth];

        // Check arguments passed ok
        if (sigma[currRecursiveDepth] * t != k)
            throw std::runtime_error(
                "sigma needs to be set such that t divides k "
                "at each recursive step"
            );
        if (k * e != n) throw std::runtime_error("invalid arguments");
        if (currRecursiveDepth > baseRecursiveDepth) throw std::runtime_error("invalid arguments");
        if (sigma.size() != (baseRecursiveDepth + 1)) throw std::runtime_error("invalid arguments");

        thrust::device_vector<T> intermediate_result (n);

        // Base case
        if (currRecursiveDepth == baseRecursiveDepth) {
            // Step1: xG Multiplication
            sparse_vector_matrix_mul_with_init_host_v2<T>(x, start_x,
                                                          intermediate_result, 0,
                                                          sigma[currRecursiveDepth], e, t);
            // Step 2: Shuffle
            gpu_shuffle<T>(intermediate_result);
            // Step 3: (xGpi)H Multiplication
            // Note: different inputs from step 1, as can be reached when recursing on xG or (xGpi)H
            sparse_vector_matrix_mul_with_init_host_v2<T>(intermediate_result, 0,
                                                          result, start_result,
                                                          sigma[currRecursiveDepth], 1, e * t);

            return;
        }

        // Step 1: Recurse (on the xG Multiplication)
        // iterate over the t Gi's
        for (int i = 0; i < t; ++i) {
            // call recursive_code_cuda on each, with currRecursiveDepth+1
            recursive_code_cuda<T>(
                x,
                start_x + sigma[currRecursiveDepth] * i, // start x
                intermediate_result,
                sigma[currRecursiveDepth] * e * i, // start result
                sigma, // one for each recursive depth (will be roughly 2sqrt(k) each time)
                sigma[currRecursiveDepth], // k
                e * sigma[currRecursiveDepth],  // n
                e, // expanding factor
                currRecursiveDepth + 1,
                baseRecursiveDepth
            );
        }
        
        // Top level Shuffle
        gpu_shuffle<T>(intermediate_result);

        // Step 3: Recurse (on the (xGpi)H Multiplication)
        // iterate over the e * t Hi's
        for (int i = 0; i < e * t; ++i) {
            // call recursive_code_cuda on each, with currRecursiveDepth+1
            recursive_code_cuda<T>(
                intermediate_result,
                sigma[currRecursiveDepth] * i, // start index in intermediate_result
                result,
                start_result + sigma[currRecursiveDepth] * i, // start index in result
                sigma,
                sigma[currRecursiveDepth], // k
                sigma[currRecursiveDepth], // n
                1, // expanding factor e (always 1 here)
                currRecursiveDepth + 1,
                baseRecursiveDepth
            );
        }
    }

    // Thrust's implementation of feistel bijection (slightly refactored)
    // operating on 64-bit keys
    // Transformed into functions
    
    // Define a struct to hold the Feistel parameters
    struct FeistelParams {
        std::uint64_t left_side_bits;
        std::uint64_t left_side_mask;
        std::uint64_t right_side_bits;
        std::uint64_t right_side_mask;
        std::uint32_t num_rounds;
    };

    // Find the nearest power of two
    __host__ __device__ std::uint64_t get_cipher_bits(std::uint64_t m) {
        if (m <= 16) return 4;
        std::uint64_t i = 0;
        m--;
        while (m != 0) {
            i++;
            m >>= 1;
        }
        return i;
    }

    // Function to set Feistel parameters and return them as a struct
    __host__ __device__ FeistelParams initialize_feistel_params(std::uint64_t m, std::uint32_t num_rounds) {
        std::uint64_t total_bits = get_cipher_bits(m);

        FeistelParams params;
        // Half bits rounded down
        params.left_side_bits = total_bits / 2;
        params.left_side_mask = (1ull << params.left_side_bits) - 1;
        // Half the bits rounded up
        params.right_side_bits = total_bits - params.left_side_bits;
        params.right_side_mask = (1ull << params.right_side_bits) - 1;

        // Set the number of rounds
        params.num_rounds = num_rounds;

        return params;
    }

    // Perform 64 bit multiplication and save result in two 32 bit int
    __host__ __device__ void mulhilo(std::uint64_t a, std::uint64_t b, std::uint32_t& hi, std::uint32_t& lo)
    {
        std::uint64_t product = a * b;
        hi = static_cast<std::uint32_t>(product >> 32);
        lo = static_cast<std::uint32_t>(product);
    }

    __host__ __device__ std::uint64_t feistel_bijection(
        const std::uint64_t val, // index to permute
        std::uint32_t* key,
        std::uint64_t left_side_bits,
        std::uint64_t left_side_mask,
        std::uint64_t right_side_bits,
        std::uint64_t right_side_mask,    
        std::uint32_t num_rounds
        ) {
        std::uint32_t state[2] = { static_cast<std::uint32_t>(val >> right_side_bits), static_cast<std::uint32_t>(val & right_side_mask) };
        for (std::uint32_t i = 0; i < num_rounds; i++)
        {
            std::uint32_t hi, lo;
            constexpr std::uint64_t M0 = UINT64_C(0xD2B74407B1CE6E93);
            mulhilo(M0, state[0], hi, lo);
            lo = (lo << (right_side_bits - left_side_bits)) | state[1] >> left_side_bits;
            state[0] = ((hi ^ key[i]) ^ state[1]) & left_side_mask;
            state[1] = lo & right_side_mask;
        }
        // Combine the left and right sides together to get result
        return static_cast<std::uint64_t>(state[0] << right_side_bits) | static_cast<std::uint64_t>(state[1]);
    }

    // Feistel cipher-based bijection for pseudorandom permutation
    /*__device__ uint64_t feistel_bijection(uint64_t idx, uint64_t n, uint32_t* keys, int num_rounds, uint64_t block_id) {
        uint32_t left = static_cast<uint32_t>(idx >> 32);
        uint32_t right = static_cast<uint32_t>(idx & 0xFFFFFFFF);

        for (int i = 0; i < num_rounds; ++i) {
            uint32_t temp = right;
            // block_id to add block-specific randomness
            //right = (left ^ (keys[i] + (block_id * 0xDEADBEEF) + (right * 0x5DEECE66DLL % n))) % n;
            // replacing modulo with & -> ONLY WORKS WHEN N A POWER OF 2
            right = (left ^ (keys[i] + (block_id * 0xDEADBEEF) + (right * 0x5DEECE66DLL & (n - 1)))) & (n - 1);

            left = temp;
        }

        return ((static_cast<uint64_t>(left) << 32) | right) % n;
    }*/


    // CUDA kernel for block-wise shuffle of T type data
    template<typename T>
    __global__ void shuffle_blocks_feistel_kernel(
        T* data, // Pointer to the vector to be shuffled
        T* result, // Pointer to the result
        uint64_t n, // Total number of elements in the input vector
        uint64_t block_size, // Size of each block to shuffle independently
        uint32_t* keys, // Array of random keys used for the Feistel bijection to generate pseudorandom permutations
        uint32_t num_rounds, // Number of Feistel rounds for generating pseudorandom indices
        uint64_t left_side_bits,
        uint64_t left_side_mask,
        uint64_t right_side_bits,
        uint64_t right_side_mask
        ) { 
        uint64_t tid = threadIdx.x + blockIdx.x * blockDim.x; // Compute global thread ID
        uint64_t block_id = tid / block_size;  // Identify the block (the chunk of the array i am permuting)
        
        uint64_t block_start = block_id * block_size; // Calculates the starting index of the block 
                                                      // the thread is operating on
        // uint64_t block_end = min(block_start + block_size, n); // Calculates the ending index of the block
       

        // Print thread information for debugging
        //printf("Thread %llu: block_start=%llu, block_end=%llu, block_id=%llu\\n", 
        //    tid, block_start, block_end, block_id);

        //printf("Thread %llu: feistel 0=%llu, feistel 1=%llu, feistel 2=%llu, feistel 3=%llu\\n", tid,
        //    bijection(0, keys + keys_start), bijection(1, keys + keys_start),
        //    bijection(2, keys + keys_start), bijection(3, keys + keys_start));

        // Note tid can be >= n
        if (tid < n && block_start < n) {
                uint64_t keys_start = block_id * num_rounds;
                // Maps the local block index (i - block_start) to a pseudorandom index within the block
                uint64_t index_to_permute = tid - block_start;
                //printf("index to permute: %llu\\n", index_to_permute);
                uint64_t permuted_idx = feistel_bijection(
                    index_to_permute, 
                    keys + keys_start,
                    left_side_bits,
                    left_side_mask,
                    right_side_bits,
                    right_side_mask,
                    num_rounds)
                    + block_start;
                //printf("block start: %llu\\n", block_start);
                // printf("permuted index: %llu", permuted_idx);
                // gather
                result[tid] = data[permuted_idx];
                //if (tid < permuted_idx) { // Ensures that each pair is swapped only once, avoiding redundant swaps
                //    uint64_t temp = data[tid];
                //    data[tid] = data[permuted_idx];
                //    data[permuted_idx] = temp;
                //}
        }
    }

    // Wrapper function to shuffle a thrust::device_vector containing T type data
    template<typename T>
    void shuffle_blocks_feistel(
        thrust::device_vector<T>& data, // The vector of T type (e.g. uint64_t) elements to shuffle
        uint64_t block_size) { // Specifies the size of each block that will be independently shuffled
        uint64_t n = data.size();
        thrust::device_vector<T> result(n);
        // block size must evenly divide the total number of elements
        if (block_size == 0 || n % block_size != 0) {
            throw std::invalid_argument("Block size must be a positive divisor of the input size.");
        }
        // ensure n is a power of 2
        if ((n & (n - 1)) != 0) {
            throw std::invalid_argument("n should be a power of 2");
        }

        uint32_t num_rounds = 24; // The number of Feistel rounds to use in the pseudorandom permutation
                                   // same as in the thrust implementation
        const int num_blocks = n / block_size;
        const int num_keys = num_rounds * num_blocks; // for each round and each block, unique feistel keys
        thrust::host_vector<uint32_t> h_keys (num_keys);
        // NOTE need to generate fresh randomness for each block (look at feistel_bijection)
        // so that each block is shuffled differently
        // thrust::default_random_engine rng; // default seed (SAME each time)
        thrust::default_random_engine rng(static_cast<unsigned int>(time(0)));

        for (int i = 0; i < num_keys; ++i) {
            h_keys[i] = rng(); // A random key is generated for each round/block using thrust::default_random_engine
        }

        thrust::device_vector<uint32_t> d_keys = h_keys; // Copy keys to device

        FeistelParams feistel_params = initialize_feistel_params(block_size, num_rounds);

        // Launch kernel
        int threads_per_block = 256; //block_size; // Sets the number of threads in each block (exactly 8 warps)
        int blocks_per_grid = (n + threads_per_block - 1) / threads_per_block; 
                                                                 // (n + block_size - 1) / block_size;
                                                                 // Determines the total number of blocks 
                                                                 // needed to cover all n elements
        shuffle_blocks_feistel_kernel << <blocks_per_grid, threads_per_block >> > (
            thrust::raw_pointer_cast(data.data()), thrust::raw_pointer_cast(result.data()), n, block_size,
            thrust::raw_pointer_cast(d_keys.data()), num_rounds, 
            feistel_params.left_side_bits, feistel_params.left_side_mask,
            feistel_params.right_side_bits, feistel_params.right_side_mask);

        cudaDeviceSynchronize();

        thrust::copy(result.begin(), result.end(), data.begin());
    }


    // Wrapper function to shuffle a thrust::device_vector containing T type data
    template<typename T>
    void shuffle_blocks_feistel_v2(
        thrust::device_ptr<T> data, // The vector of T type (e.g. uint64_t) elements to shuffle
        uint64_t block_size,
        uint64_t n) { // Specifies the size of each block that will be independently shuffled
        thrust::device_vector<T> result(n);
        // block size must evenly divide the total number of elements
        if (block_size == 0 || n % block_size != 0) {
            throw std::invalid_argument("Block size must be a positive divisor of the input size.");
        }
        // ensure n is a power of 2
        if ((n & (n - 1)) != 0) {
            throw std::invalid_argument("n should be a power of 2");
        }

        uint32_t num_rounds = 24; // The number of Feistel rounds to use in the pseudorandom permutation
        // same as in the thrust implementation
        const int num_blocks = n / block_size;
        const int num_keys = num_rounds * num_blocks; // for each round and each block, unique feistel keys
        thrust::host_vector<uint32_t> h_keys(num_keys);
        // NOTE need to generate fresh randomness for each block (look at feistel_bijection)
        // so that each block is shuffled differently
        // thrust::default_random_engine rng; // default seed (SAME each time)
        thrust::default_random_engine rng(static_cast<unsigned int>(time(0)));

        for (int i = 0; i < num_keys; ++i) {
            h_keys[i] = rng(); // A random key is generated for each round/block using thrust::default_random_engine
        }

        thrust::device_vector<uint32_t> d_keys = h_keys; // Copy keys to device

        FeistelParams feistel_params = initialize_feistel_params(block_size, num_rounds);

        // Launch kernel
        int threads_per_block = 256; //block_size; // Sets the number of threads in each block (exactly 8 warps)
        int blocks_per_grid = (n + threads_per_block - 1) / threads_per_block;
        // (n + block_size - 1) / block_size;
        // Determines the total number of blocks 
        // needed to cover all n elements
        shuffle_blocks_feistel_kernel << <blocks_per_grid, threads_per_block >> > (
            thrust::raw_pointer_cast(data), thrust::raw_pointer_cast(result.data()), n, block_size,
            thrust::raw_pointer_cast(d_keys.data()), num_rounds,
            feistel_params.left_side_bits, feistel_params.left_side_mask,
            feistel_params.right_side_bits, feistel_params.right_side_mask);

        cudaDeviceSynchronize();

        thrust::copy(result.begin(), result.end(), data);
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
        std::vector<uint8_t> h_vector = { 1, 1, 1,
                                                   0, 0, 1,
                                                            1, 0, 1 }; // Binary vector of size k

        // --- Host Block Matrices (G1, G2, ..., Gt) ---
        // std::vector<std::vector<uint8_t>> h_blocks(t, std::vector<uint8_t>(sigma * (sigma * e), 1));
        std::vector<uint8_t> h_blocks = { 1,0,1,1,1,0,
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
        // when just binary
        //std::vector<uint8_t> h_expected_result = { 0,0,0,0,1,1,
        //                                                       1,1,1,0,0,0,
        //                                                                   1,1,0,1,1,0 };
        std::vector<uint8_t> h_expected_result = { 2,2,2,2,1,1,
                                                               1,1,1,0,0,0,
                                                                           1,1,0,1,1,2 };

        // --- Transfer Data to GPU ---
        thrust::device_vector<uint8_t> d_vector = h_vector; // Vector x on GPU

        // --- Final Result Vector on GPU ---
        thrust::device_vector<uint8_t> d_result(n, 0);
        thrust::device_vector<uint8_t> d_result2(n, 0);

        sparse_vector_matrix_mul_host<uint8_t>(d_vector, d_blocks, d_result);
        sparse_vector_matrix_mul_host_v2<uint8_t>(d_vector, d_blocks, d_result2);

        // Copy results back to host
        thrust::host_vector<uint8_t> h_result_gpu = d_result;
        thrust::host_vector<uint8_t> h_result2_gpu = d_result2;

        // Verify correctness
        for (size_t i = 0; i < n; i++) {
            // std::cout << "expected at index " << i << ": " << static_cast<int>(h_expected_result[i]) << std::endl;
            // std::cout << "computed at index " << i << ": " << static_cast<int>(h_result_gpu[i]) << std::endl;
            if (h_result_gpu[i] != h_expected_result[i] || h_result2_gpu[i] != h_expected_result[i])
                throw std::runtime_error("Computed result not as expected");
        }
        std::cout << std::endl;
    }


    void benchmark_code_cuda() {

        // Set up pseudorandom generator for generating x
        std::mt19937_64 rngcpu(std::random_device{}()); // 64-bit random number generator
        // Uniform distribution over [0, UINT64_MAX]
        std::uniform_int_distribution<uint64_t> dist(0, std::numeric_limits<uint64_t>::max());

        constexpr int k = 1 << 20; // 2^20
        constexpr int n = 1 << 21; // 2^21
        constexpr int sigma = 512;  // Block size (2 * sqrt(k))

        //
        // Initialize x, G, and empty xG, and move them from host to device
        //
        // --- Host Input Vector x ---
        std::vector<uint64_t> h_x(k); // Field vector of size k
        for (auto& val : h_x) {
            val = dist(rngcpu); // Generate a uniform uint64_t value and assign to the vector
            // std::cout << val << std::endl; // Uncomment to debug and print values
        }

        // --- Transfer Data to GPU ---
        thrust::device_vector<uint64_t> d_x = h_x; // Vector x on GPU
        // --- Final result vector on GPU ---

        thrust::device_vector<uint64_t> d_xG(n, 0);

        BlockMatrix G, H;
        //initialize_block_matrix(G, sigma, k, n, dist, rngcpu);
        //initialize_block_matrix(H, sigma, k, n, dist, rngcpu);
        initialize_block_matrix_v2(G, sigma, n/k, k/sigma); // sigma, e, t
        initialize_block_matrix_v2(H, sigma, 1, n/sigma); // sigma, e, t
        
        auto start = std::chrono::high_resolution_clock::now();
        code_cuda<uint64_t>(d_x, G, H, d_xG);
        auto stop = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = stop - start;

        // Step 4: Print the elapsed time
        std::cout << "Time to compute plain multiply-shuffle-multiply with "
            << " k: " << k
            << " n: " << n
            << " sigma: " << sigma
            << " is " << elapsed.count() << " ms" << std::endl;
        std::cout << "NOTE The number above does NOT include the cost to initialize the matrices G, H" << std::endl;
        std::cout << "NOTE this approach will run out of memory for sigma>512, "
                     "G, H: each t * sigma * sigma * e elements too much for gpu memory" << std::endl;
        std::cout << "TODO Generate each of the t blocks on the fly" << std::endl;      
    }


    void benchmark_recursive_code_cuda() {

        // Set up pseudorandom generator for generating x
        std::mt19937_64 rngcpu(std::random_device{}()); // 64-bit random number generator
        // Uniform distribution over [0, UINT64_MAX]
        std::uniform_int_distribution<uint64_t> dist(0, std::numeric_limits<uint64_t>::max());

        constexpr int k = 1 << 20; // 2^20
        constexpr int n = 1 << 21; // 2^21
        std::vector<int> sigmas = { 2048, 128 };  // Block size ~ (2 * sqrt(k))
        int baseRecursiveDepth = sigmas.size() - 1; // starts with 0

        int e = n / k;
        if (k * e != n) throw std::runtime_error("invalid k, n");
        if (k % sigmas[0] != 0) throw std::runtime_error("invalid sigmas[0]");
        for (int i = 0; i < sigmas.size() - 1; ++i) {
            if (sigmas[i] % sigmas[i + 1] != 0) throw std::runtime_error("invalid sigmas[i]");
        }

        //
        // Initialize x and empty xG, and move them from host to device
        //
        // --- Host Input Vector x ---
        std::vector<uint64_t> h_x(k); // Binary vector of size k
        for (auto& val : h_x) {
            val = dist(rngcpu); // Generate 0 or 1 and assign to the vector
            // std::cout << static_cast<int>(val);
        }

        // --- Transfer Data to GPU ---
        thrust::device_vector<uint64_t> d_x = h_x; // Vector x on GPU
        // --- Final result vector on GPU ---

        thrust::device_vector<uint64_t> d_result(n);

        auto start = std::chrono::high_resolution_clock::now();

        recursive_code_cuda<uint64_t>(
            d_x, // does not change across recursion, we index into it
            0, // index to the part of x i am recursing on
            d_result,
            0, // index to the result index i am recursing on
            sigmas, // one for each recursive depth (will be roughly 2sqrt(k) each time, set such that t stays the same???)
            k,
            n,
            e,
            0, // current recursive depth
            baseRecursiveDepth); // total recursive depth

        auto stop = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = stop - start;

        // Print the elapsed time
        std::cout << "Time to compute recursive multiply-shuffle-multiply (plain recursion, not unrolled) with "
            << " k: " << k
            << " n: " << n
            << " sigmas: ";
        for (const auto s : sigmas) std::cout << s << " ";
            std::cout << "is " << elapsed.count() << " ms" << std::endl;
        std::cout << "NOTE The number above DOES include the cost to initialize the matrices G, H" << std::endl;
        std::cout << "NOTE The plain recursive function above is NOT carefully debugged" << std::endl;      
    }

    void benchmark_permutations() {
        std::cout << "BENCHMARKING DIFFERENT PERMUTATIONS:" << std::endl;

        int n = 1 << 21;

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

        // Create a device_vector with some data
        thrust::device_vector<uint64_t> d_vec2(n);
        // Fill the vector with sequential values (0, 1, 2, ..., n-1)
        thrust::transform(thrust::make_counting_iterator(0),
            thrust::make_counting_iterator(n),
            d_vec2.begin(),
            sequence_functor());

        std::cout << "Benchmarking our feistel shuffle for different block size:" << std::endl;
        std::vector<uint64_t> block_size = {
            uint64_t(n),
            uint64_t(n) / 16,
            uint64_t(n) / 128,
            uint64_t(n) / 2048,
            uint64_t(n) / 16384
        };

        for (auto& b : block_size) {
            // different size block
            start_device_chrono = std::chrono::high_resolution_clock::now();
            shuffle_blocks_feistel<uint64_t>(d_vec2, b); // 1 block
            stop_device_chrono = std::chrono::high_resolution_clock::now();
            elapsed_device_chrono = stop_device_chrono - start_device_chrono;
            std::cout 
                << "Time to block-wise Feistel shuffle (our function) a thrust::device_vector (GPU) using chrono "
                << "with block of size " << b << " is " << elapsed_device_chrono.count() << " ms" << std::endl;
        }

        //
        // modified thrust shuffle
        //

        thrust::device_vector<uint64_t> d_vec3(n);
        // Fill the vector with sequential values (0, 1, 2, ..., n-1)
        thrust::transform(thrust::make_counting_iterator(0),
            thrust::make_counting_iterator(n),
            d_vec3.begin(),
            sequence_functor());

        start_device_chrono = std::chrono::high_resolution_clock::now();

        thrust::default_random_engine rng2;
        auto seed2 = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        rng2.seed(static_cast<unsigned int>(seed2)); // Seed based on current time

        shuffle_chunks(thrust::cuda::par, d_vec3.begin(), d_vec3.end(), block_size[0], rng2);

        stop_device_chrono = std::chrono::high_resolution_clock::now();

        elapsed_device_chrono = stop_device_chrono - start_device_chrono;

        // Step 5: Print the elapsed time
        std::cout << "Time for modified block-wise thrust shuffle (sequential) for a thrust::device_vector (GPU)"
                     " with block of size " << block_size[0] << " is "
                     "using chrono: "
                     << elapsed_device_chrono.count() << " ms" << std::endl;

        std::cout << std::endl;
    }

    // Recursive function to build the sequence
    std::vector<int> buildSequence(int depth) {
        if (depth == 1) {
            return { 0 }; // Base case: For depth 1, the sequence is [0]
        }

        // Recursively build the sequence for the previous depth
        std::vector<int> prevSequence = buildSequence(depth - 1);

        // Construct the new sequence for the current depth
        std::vector<int> newSequence;

        // Left subtree: S(d-1) + depth
        for (int val : prevSequence) {
            newSequence.push_back(val + 1);
        }

        // Middle element: 0
        newSequence.push_back(0);

        // Right subtree: S(d-1) + depth
        for (int val : prevSequence) {
            newSequence.push_back(val + 1);
        }

        return newSequence;
    }

    template <typename T>
    void iterative_code_cuda(
        const thrust::device_vector<T>& x,
        thrust::device_vector<T>& result,
        std::vector<int>& sigma,
        int k,
        int e) {

        int depth = sigma.size() - 1; // remember sigma includes n at sigma[0]
        int num_iters = pow(2, depth) - 1;
        std::vector<int> perm_blocksize_idx;
        if (depth == 2) {
            perm_blocksize_idx = {1, 0, 1};
        }
        else if (depth == 3) {
            perm_blocksize_idx = { 2, 1, 2, 0, 2, 1, 2 };
        }
        else {
            throw std::runtime_error("you can use the commented out function below but expensive "
                                     "(do not uncomment for efficiency)");
            // works for any depth, but it is a recursive function
            //perm_blocksize_idx = buildSequence(depth);
        }
        
        // We implement 2 cuda kernels that we keep invoking
        // The current function is run on the host and invokes the kernels
        // Iterate and keep doing one after the other these 2 operations:
        // 1. Multiply a vector x = x1,...,xt by a bunch of base size blocks G=G1,...,Gt, where t=k/sigma[depth]
        // 2. Shuffle: split the vector resulting from multiplication in 1 into k/sigma[curr_depth-1] 
        //             same-size pieces and shuffle each piece (in 1 kernel)
        // Each iteration invokes 2 followed by 1

        int n = k * e;
        int mul_sigma = sigma[depth];
        int mul_t = n / mul_sigma; // except first iteration (where it is k/mul_sigma)
        int initial_t = k / mul_sigma;

        MulHelper mul_helper_expand;
        initialize_mul_helper(mul_helper_expand, mul_sigma, e, initial_t);

        MulHelper mul_helper_rest;
        initialize_mul_helper(mul_helper_rest, mul_sigma, 1, mul_t);

        // Each iteration (but the first one) will use one vector as input and the other as result:
        std::vector<thrust::device_vector<T>> results(2, thrust::device_vector<T>(n));

        // Initialize block matrix (but do not fill it with randomness - that will be done each time it is used)
        thrust::device_vector<uint8_t> mat (initial_t * mul_sigma * (mul_sigma * e));
       // mat.resize(initial_t * mul_sigma * (mul_sigma * e)); // note this is constant for 1st and later iters

        // First iteration separate because:
        // 1. it uses x as input
        // 2. the first multiplication is the only EXPANDING one, all others are the same
        sparse_vector_matrix_mul_with_init_host_v3<T>(
            x,
            0,
            results[0],
            0,
            mat,
            mul_helper_expand);

        shuffle_blocks_feistel<T>(results[0], e * sigma[depth - 1]);

        // Multiply
        sparse_vector_matrix_mul_with_init_host_v3<T>(
            results[0], // iter % 2
            0,
            results[1],
            0,
            mat,
            mul_helper_rest);

        // Remaining iterations
        for (size_t iter = 1; iter < num_iters; ++iter) {

            // Shuffle
            shuffle_blocks_feistel<T>(results[iter & 1], sigma[perm_blocksize_idx[iter]]);

            // Multiply
            sparse_vector_matrix_mul_with_init_host_v3<T>(
                results[iter & 1], // iter % 2
                0,
                results[(iter + 1) & 1], // (iter+1) % 2
                0,
                mat,
                mul_helper_rest);
        }

        // TODO copy the final results[i] into the result device vector
    }

    void benchmark_iterative_code_cuda(int depth) {

        // Set up pseudorandom generator for generating x
        std::mt19937_64 rngcpu(std::random_device{}()); // 64-bit random number generator
        // Uniform distribution over [0, UINT64_MAX]
        std::uniform_int_distribution<uint64_t> dist(0, std::numeric_limits<uint64_t>::max());

        constexpr int k = 1 << 20; // 2^20
        constexpr int n = 1 << 21; // 2^21
        std::vector<int> sigmas;
        if (depth == 2) {
            sigmas = { n, 2048, 128 }; // ~2sqrt(n)
        }
        else if (depth == 3) {
           sigmas = { n, 2048, 128, 32 }; // ~2sqrt(n)
        }
        else {
            throw std::runtime_error("need to define sigma vector to run for depth > 3");
        }

        int e = n / k;

        if (k * e != n) throw std::runtime_error("invalid k, n");

        if (e <= 1) throw std::runtime_error("needs to be expanding");

        std::vector<uint64_t> h_x(k);
        for (auto& val : h_x) {
            val = dist(rngcpu);
        }
        thrust::device_vector<uint64_t> d_x = h_x;

        thrust::device_vector<uint64_t> d_result(n);

        auto start = std::chrono::high_resolution_clock::now();

        iterative_code_cuda<uint64_t>(
            d_x,
            d_result,
            sigmas,
            k,
            e
        );

        auto stop = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = stop - start;

        std::cout << "Time to compute optimized iterative CUDA implementation (unrolled recursion) with "
            << " k: " << k
            << " n: " << n
            << " depth: " << depth
            << " sigmas: ";
        for (const auto s : sigmas) std::cout << s << " ";
        std::cout << "is " << elapsed.count() << " ms" << std::endl;
        std::cout << "NOTE The number above DOES include the cost to initialize the matrices G, H" << std::endl;
    }


    template <typename T>
    thrust::device_vector<T> iterative_pcg_code_cuda(
        const thrust::device_vector<T>& x,
        std::vector<int>& sigma,
        int k,
        int e) {

        int depth = sigma.size() - 1; // remember sigma includes n at sigma[0]
        int num_iters = pow(2, depth) - 1;
        int iter_half = num_iters / 2;

        std::vector<int> perm_blocksize_idx; // size of permutation block at a given iteration 
                                             // i.e. index into the sigmas vector that has the size
        // NOTE we can just use the first half (i.e. before 0) as the second half is identical
        if (depth == 2) {
            perm_blocksize_idx = { 1 }; // full: { 1, 0, 1 };
        }
        else if (depth == 3) {
            perm_blocksize_idx = {2, 1, 2}; // full: { 2, 1, 2, 0, 2, 1, 2 };
        }
        else {
            throw std::runtime_error("you can use the commented out function below but expensive "
                "(do not uncomment for efficiency)");
            // works for any depth, but it is a recursive function
            // NOTE you can just use the first half as second half is same of the output vector
            //perm_blocksize_idx = buildSequence(depth);
        }

        // We implement 2 cuda kernels that we keep invoking
        // The current function is run on the host and invokes the kernels
        // Iterate and keep doing one after the other these 2 operations:
        // 1. Multiply a vector x = x1,...,xt by a bunch of base size blocks G=G1,...,Gt, 
        //                      where t=k/sigma[depth] or t=n/sigma[depth])
        // 2. Shuffle: split the vector resulting from multiplication in 1 into
        //             same-size pieces of some size and shuffle each piece (in 1 kernel)
        // Each iteration invokes 2 followed by 1

        int n = k * e;
        int mul_sigma = sigma[depth]; // all multiplications are done with sigma[depth]
        int first_t = n / mul_sigma; // in the first half (in the second half it is k/mul_sigma)
        int last_t = k / mul_sigma; // starting with compression and onto second half
        
        MulHelperV2 mul_helper_firsthalf;
        initialize_mul_helper_expandorequal(mul_helper_firsthalf, mul_sigma, 1, first_t); // e=1 means non-expanding

        MulHelperV2 mul_helper_compress;
        initialize_mul_helper_compress(mul_helper_compress, mul_sigma, e, last_t);

        MulHelperV2 mul_helper_secondhalf;
        initialize_mul_helper_expandorequal(mul_helper_secondhalf, mul_sigma, 1, last_t); // e=1
        
        // Each iteration (except first) will use one vector as input and the other as result:
        std::vector<thrust::device_vector<T>> results_firsthalf(2, thrust::device_vector<T>(n));
        std::vector<thrust::device_vector<T>> results_secondhalf(2, thrust::device_vector<T>(k)); // after compressing

        // Initialize block matrix (but do not fill it with randomness - that will be done each time it is used)
        // note the size of mat is constant for all iters in first half (non-compressing) + compressing step
        thrust::device_vector<uint8_t> mat_firsthalf(first_t * mul_sigma * mul_sigma); // also can be used for compressing
                                                                                       // as size equals last_t * e * sigma * sigma
        thrust::device_vector<uint8_t> mat_secondhalf(last_t * mul_sigma * mul_sigma);
        
         // First multiplication separate because it uses x as input
        sparse_vector_matrix_mul_with_init_host_v4<T>(
            x,
            0,
            results_firsthalf[0],
            0,
            mat_firsthalf,
            mul_helper_firsthalf);

        //
        // Do the first 1/2 iterations (on n-size vectors)
        //        
        for (size_t iter = 0; iter < iter_half; ++iter) {

            // Shuffle
            shuffle_blocks_feistel<T>(results_firsthalf[iter & 1], sigma[perm_blocksize_idx[iter]]);

            // Multiply
            sparse_vector_matrix_mul_with_init_host_v4<T>(
                results_firsthalf[iter & 1], // iter % 2
                0,
                results_firsthalf[(iter + 1) & 1], // (iter+1) % 2
                0,
                mat_firsthalf,
                mul_helper_firsthalf);
        }

        //
        // Do the middle iteration (shuffle and compress)
        //
        
        // Shuffle (full thing of size n)
        shuffle_blocks_feistel<T>(results_firsthalf[iter_half & 1], sigma[0]);

        // Multiply (compress to size n->k)
        sparse_vector_matrix_mul_with_init_host_v4<T>(
            results_firsthalf[iter_half & 1], // iter % 2
            0,
            results_secondhalf[0], // (iter+1) % 2
            0,
            mat_firsthalf,
            mul_helper_compress);

        //
        // Do the remaining second half iterations (on k-size vectors)
        //
        for (size_t iter = 0; iter < iter_half; ++iter) {
            // Shuffle
            shuffle_blocks_feistel<T>(results_secondhalf[iter & 1], sigma[perm_blocksize_idx[iter]]);

            // Multiply
            sparse_vector_matrix_mul_with_init_host_v4<T>(
                results_secondhalf[iter & 1], // iter % 2
                0,
                results_secondhalf[(iter + 1) & 1], // (iter+1) % 2
                0,
                mat_secondhalf,
                mul_helper_secondhalf);
        }
        
        return results_secondhalf[iter_half & 1];
    }


    template <typename T>
    thrust::device_ptr<T> iterative_pcg_code_cuda_v2(
        thrust::device_vector<T>& x,
        std::vector<int>& sigma,
        std::vector<int> &perm_blocksize_idx,
        int k,
        int e) {

        int depth = sigma.size() - 1; // remember sigma includes n at sigma[0]
        int num_iters = pow(2, depth) - 1;
        int iter_half = num_iters / 2;
        
        // We implement 2 cuda kernels that we keep invoking
        // The current function is run on the host and invokes the kernels
        // Iterate and keep doing one after the other these 2 operations:
        // 1. Multiply a vector x = x1,...,xt by a bunch of base size blocks G=G1,...,Gt, 
        //                      where t=k/sigma[depth] or t=n/sigma[depth])
        // 2. Shuffle: split the vector resulting from multiplication in 1 into
        //             same-size pieces of some size and shuffle each piece (in 1 kernel)
        // Each iteration invokes 2 followed by 1

        int n = k * e;
        int mul_sigma = sigma[depth]; // all multiplications are done with sigma[depth]
        int first_t = n / mul_sigma; // in the first half (in the second half it is k/mul_sigma)
        int last_t = k / mul_sigma; // starting with compression and onto second half
        
        MulHelperV3 mul_helper_firsthalf;
        initialize_mul_helper_expandorequal_v2(mul_helper_firsthalf, mul_sigma, 1, first_t); // e=1 means non-expanding

        MulHelperV3 mul_helper_compress;
        initialize_mul_helper_compress_v2(mul_helper_compress, mul_sigma, e, last_t);

        MulHelperV3 mul_helper_secondhalf;
        initialize_mul_helper_expandorequal_v2(mul_helper_secondhalf, mul_sigma, 1, last_t); // e=1
        
        // Each iteration (except first) will use one vector as input and the other as result:
        thrust::device_vector<T> results(2 * n); // in first half: one is 0...n and the other n...2n
                                                 // in second half: one is 0...k and the other n...(n+k)
                                                 // so in second half we just do not use the redundant elements
        
        // First multiplication separate because it uses x as input
        sparse_vector_matrix_mul_with_init_host_v5<T>(
            x.data(),
            results.data(),
            mul_helper_firsthalf);

        //
        // Do the first 1/2 iterations (on n-size vectors)
        //        
        for (size_t iter = 0; iter < iter_half; ++iter) {

            // Shuffle
            shuffle_blocks_feistel_v2<T>(results.data() + (iter & 1) * n, sigma[perm_blocksize_idx[iter]], n);

            // Multiply
            sparse_vector_matrix_mul_with_init_host_v5<T>(
                results.data() + (iter & 1) * n, // iter % 2
                results.data() + ((~iter) & 1) * n, // (iter+1) % 2
                mul_helper_firsthalf);
        }

        //
        // Do the middle iteration (shuffle and compress)
        //

        // Shuffle (full thing of size n)
        shuffle_blocks_feistel_v2<T>(results.data() + (iter_half & 1) * n, sigma[0], n);

        // Multiply (compress to size n->k)
        sparse_vector_matrix_mul_with_init_host_v5<T>(
            results.data() + (iter_half & 1) * n, // first half (n size), iter % 2
            results.data() + ((~iter_half) & 1) * n, // second half (k size), (iter+1) % 2
            mul_helper_compress);

        //
        // Do the remaining second half iterations (on k-size vectors)
        //
        for (size_t iter = 0; iter < iter_half; ++iter) {
            // Shuffle
            shuffle_blocks_feistel_v2<T>(
                results.data() + (((iter_half ^ iter) + 1) & 1) * n,
                sigma[perm_blocksize_idx[iter]], k);

            // Multiply
            sparse_vector_matrix_mul_with_init_host_v5<T>(
                results.data() + (((iter_half ^ iter) + 1) & 1) * n, // iter % 2
                results.data() + ((iter_half ^ iter) & 1) * n, // (iter+1) % 2
                mul_helper_secondhalf);
        }
        
        //iter_half+iter_half-1+2
        // = 2 * iter_half + 1
        // 2 * iter_half + 1 == num_iters        
        return results.data() + (num_iters & 1) * n;
    }


    void benchmark_iterative_pcg_code_cuda(int depth) {

        std::cout << "Computing G[Delta e]..." << std::endl;

        // Set up pseudorandom generator for generating x
        std::mt19937_64 rngcpu(std::random_device{}()); // 64-bit random number generator
        // Uniform distribution over [0, UINT64_MAX]
        std::uniform_int_distribution<uint64_t> dist(0, std::numeric_limits<uint64_t>::max());

        constexpr int k = 1 << 20; // 2^20
        constexpr int n = 1 << 21; // 2^21

        std::vector<int> sigmas;
        if (depth == 2) {
            sigmas = { n, 2048, 128 }; // ~2sqrt(n)
        }
        else if (depth == 3) {
            sigmas = { n, 2048, 128, 32 }; // ~2sqrt(n)
        }
        else {
            throw std::runtime_error("need to define sigma vector to run for depth > 3");
        }

        std::vector<int> perm_blocksize_idx; // size of permutation block at a given iteration 
        // i.e. index into the sigmas vector that has the size
        // NOTE we can just use the first half (i.e. before 0) as the second half is identical
        if (depth == 2) {
            perm_blocksize_idx = { 1 }; // full: { 1, 0, 1 };
        }
        else if (depth == 3) {
            perm_blocksize_idx = { 2, 1, 2 }; // full: { 2, 1, 2, 0, 2, 1, 2 };
        }
        else {
            throw std::runtime_error("you can use the commented out function below but expensive "
                "(do not uncomment for efficiency)");
            // works for any depth, but it is a recursive function
            // NOTE you can just use the first half as second half is same of the output vector
            //perm_blocksize_idx = buildSequence(depth);
        }

        int e = n / k;

        if (k * e != n) throw std::runtime_error("invalid k, n");

        if (e <= 1) throw std::runtime_error("needs to be expanding");

        std::vector<uint64_t> h_x(n); // h_x is the [Delta * e]
        for (auto& val : h_x) {
            val = dist(rngcpu);
        }
        thrust::device_vector<uint64_t> d_x = h_x; // move the [Delta e] on the device

        auto start = std::chrono::high_resolution_clock::now();

        thrust::device_ptr<uint64_t> d_result = iterative_pcg_code_cuda_v2<uint64_t>(
            d_x,
            sigmas,
            perm_blocksize_idx,
            k,
            e
        );

        auto stop = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = stop - start;

        std::cout << "Time to compute G[Delta e] iterative CUDA implementation (unrolled recursion) with "
            << " k: " << k
            << " n: " << n
            << " depth: " << depth
            << " sigmas: ";
        for (const auto s : sigmas) std::cout << s << " ";
        std::cout << "is " << elapsed.count() << " ms" << std::endl;
        std::cout << "NOTE The number above DOES include the cost to initialize the matrices G, H" << std::endl;

        // if (d_result.size() != k) throw std::runtime_error("dimensions of output are incorrect");
    }

    void test_feistel_shuffle() {
        int n = 128;
        int block_size = 16;
        thrust::device_vector<uint64_t> data(n);
        thrust::sequence(data.begin(), data.end(), 0);

        //std::cout << "Before feistel shuffle:\n";
        thrust::host_vector<uint64_t> h_data = data;
        //for (size_t i = 0; i < h_data.size(); ++i) {
        //    std::cout << static_cast<int>(h_data[i]) << " ";
        //}
        //std::cout << "\n";

        shuffle_blocks_feistel<uint64_t>(data, block_size);

        std::vector<int> verify_bijection(n, 1);
        //std::cout << "After feistel shuffle:\n";
        h_data = data;
        for (size_t i = 0; i < h_data.size(); ++i) {
            //std::cout << static_cast<int>(h_data[i]) << " ";
            verify_bijection[h_data[i]]--;
        }
        //std::cout << "\n";

        for (const auto& vb:  verify_bijection) {
            if (vb != 0) throw std::runtime_error("Not a perfect bijection");
        }        
    }

    void test_modified_thrust_shuffle() {
        int n = 128;
        int block_size = 16;

        thrust::device_vector<uint64_t> data(n);
        thrust::sequence(data.begin(), data.end(), 0);

        //std::cout << "Before shuffle:\n";
        thrust::host_vector<uint64_t> h_data = data;
        //for (size_t i = 0; i < h_data.size(); ++i) {
        //    std::cout << static_cast<int>(h_data[i]) << " ";
        //}
        //std::cout << "\n";

        thrust::default_random_engine rng;
        auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        rng.seed(static_cast<unsigned int>(seed)); // Seed based on current time

        shuffle_chunks(thrust::cuda::par, data.begin(), data.end(), block_size, rng);

        std::vector<int> verify_bijection(n, 1);
        //std::cout << "After shuffle:\n";
        h_data = data;
        for (size_t i = 0; i < h_data.size(); ++i) {
            //std::cout << static_cast<int>(h_data[i]) << " ";
            verify_bijection[h_data[i]]--;
        }
        //std::cout << "\n";

        for (const auto& vb : verify_bijection) {
            if (vb != 0) throw std::runtime_error("Not a perfect bijection");
        }
    }

    void parallelSD() {

        // Is cuda included properly into cmake?
        test_cuda_compiled();

        //
        // BENCHMARKS
        //

        // Benchmark different permutations
        benchmark_permutations();

        std::cout << "BENCHMARKING OUR CODES:" << std::endl;

        // benchmark code cuda (non recursive) with fixed sigma
        // plain multiply/permute/multiply
        benchmark_code_cuda();

        // benchmark recursive code cuda (with blocks generated on the fly in the base case)
        // recursive approach (and implemented recursively)
        benchmark_recursive_code_cuda();

        // like the recursive approach above, but much more in parallel (reduces #kernel launches and fills gpu)
        // recursive but implemented iteratively
        // this is the approach we want to use
        benchmark_iterative_code_cuda(2); // parameter depth
        benchmark_iterative_code_cuda(3);

        // The code above computes xG
        // For PCG, we want to compute G\Delta\e
        benchmark_iterative_pcg_code_cuda(2);
        benchmark_iterative_pcg_code_cuda(3);

        //
        // DIFFERENT TESTS
        //

        // test block multiply with thrust and cuda
        test_thrust_block_multiply();
        test_cuda_block_multiply();

        // Shuffle, split vector into equal sized blocks and shuffle each
        // Do NOT use this one (just done for comparison)
        test_modified_thrust_shuffle();

        // Shuffle, split vector into equal sized blocks and shuffle each
        // Use this shuffle
        test_feistel_shuffle();
    }

} // namespace osuCrypto