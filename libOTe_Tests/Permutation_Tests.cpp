#include "Permutation_Tests.h"
#include "libOTe/Tools/BlkAccCode/Permutation.h"
#include "cryptoTools/Common/TestCollection.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/BitVector.h"
#include <set>
#include <random>
#include <iomanip>

using namespace osuCrypto;

namespace tests_libOTe
{

    void Permutation_bijection_test(const CLP& cmd)
    {
        // Test various sizes for both permutation types
        std::vector<u64> sizes = { 16, 64, 256, 1024, 4096 };
        
        for (auto size : sizes)
        {
            // Test Feistel2KPerm (power of 2 sizes only)
            Timer timer;
            auto seed = block(123456, 789012);
            
            timer.setTimePoint("start");
            Feistel2KPerm perm2k(size, seed);
            timer.setTimePoint("init2k");
            
            // Check bijection property (one-to-one mapping)
            std::set<u32> outputs;
            for (u32 i = 0; i < size; ++i)
            {
                u32 p = perm2k.feistelBijection(i);
                if (outputs.count(p) > 0)
                {
                    throw std::runtime_error("Feistel2KPerm failed bijection test: duplicate output found");
                }
                outputs.insert(p);
                
                // Ensure all outputs are within range
                if (p >= size)
                {
                    throw std::runtime_error("Feistel2KPerm failed range test: output exceeds domain");
                }
            }
            timer.setTimePoint("bijection2k");
            
            // Make sure all values in the domain are covered
            if (outputs.size() != size)
            {
                throw std::runtime_error("Feistel2KPerm failed coverage test: not all outputs covered");
            }
            
            //std::cout << "Feistel2KPerm size " << size << " passed bijection test" << std::endl;
            //std::cout << "  Init time: " << std::setw(8) << timer["init2k"] - timer["start"] << " ms" << std::endl;
            //std::cout << "  Check time: " << std::setw(8) << timer["bijection2k"] - timer["init2k"] << " ms" << std::endl;
        }
        
        // Test non-power-of-2 sizes for FeistelPerm
        std::vector<u64> nonPow2Sizes = { 10, 100, 1000, 3000, 4500 };
        
        for (auto size : nonPow2Sizes)
        {
            Timer timer;
            auto seed = block(123456, 789012);
            
            timer.setTimePoint("start");
            FeistelPerm perm(size, seed);
            timer.setTimePoint("init");
            
            // Check bijection property using iterator interface
            std::set<u32> outputs;
            auto iter = perm.begin();
            for (u64 i = 0; i < size; ++i)
            {
                u32 p = *iter;
                if (outputs.count(p) > 0)
                {
                    throw std::runtime_error("FeistelPerm failed bijection test: duplicate output found");
                }
                outputs.insert(p);
                
                // Ensure all outputs are within range
                if (p >= size)
                {
                    throw std::runtime_error("FeistelPerm failed range test: output exceeds domain");
                }
                
                ++iter;
            }
            timer.setTimePoint("bijection");
            
            // Make sure all values in the domain are covered
            if (outputs.size() != size)
            {
                throw std::runtime_error("FeistelPerm failed coverage test: not all outputs covered");
            }
            
            //std::cout << "FeistelPerm size " << size << " passed bijection test" << std::endl;
            //std::cout << "  Init time: " << std::setw(8) << timer["init"] - timer["start"] << " ms" << std::endl;
            //std::cout << "  Check time: " << std::setw(8) << timer["bijection"] - timer["init"] << " ms" << std::endl;
        }
    }

    void Permutation_data_test(const CLP& cmd)
    {
        // Test permuting actual data
        std::vector<u64> sizes = { 64, 1024, 4096 };
        
        for (auto size : sizes)
        {
            // Create test data
            std::vector<u32> data(size);
            for (u64 i = 0; i < size; ++i)
            {
                data[i] = static_cast<u32>(i);
            }
            
            std::vector<u32> output(size);
            
            // Test Feistel2KPerm
            {
                Feistel2KPerm perm2k(size);
                
                // Permute the data using dualEncode
                perm2k.dualEncode(span<const u32>(data), span<u32>(output));
                
                // Verify that the permutation contains all the original elements
                std::set<u32> uniqueValues;
                for (u64 i = 0; i < size; ++i)
                {
                    uniqueValues.insert(output[i]);
                }
                
                if (uniqueValues.size() != size)
                {
                    throw std::runtime_error("Feistel2KPerm data permutation failed: not all elements preserved");
                }
                
                //std::cout << "Feistel2KPerm size " << size << " passed data permutation test" << std::endl;
            }
            
            // Reset output for next test
            std::fill(output.begin(), output.end(), 0);
            
            // Test Feistel2KPerm iterator interface
            {
                Feistel2KPerm perm2k(size);
                
                // Use iterator interface to permute data
                auto iter = perm2k.begin(output.data());
                for (u64 i = 0; i < size; ++i)
                {
                    *iter = data[i];
                    ++iter;
                }
                
                // Verify permutation
                std::set<u32> uniqueValues;
                for (u64 i = 0; i < size; ++i)
                {
                    uniqueValues.insert(output[i]);
                }
                
                if (uniqueValues.size() != size)
                {
                    throw std::runtime_error("Feistel2KPerm iterator interface failed: not all elements preserved");
                }
                
                //std::cout << "Feistel2KPerm size " << size << " passed iterator interface test" << std::endl;
            }
        }
        
        // Test non-power-of-2 sizes with FeistelPerm
        std::vector<u64> nonPow2Sizes = { 100, 1000, 3000 };
        
        for (auto size : nonPow2Sizes)
        {
            // Create test data
            std::vector<u32> data(size);
            for (u64 i = 0; i < size; ++i)
            {
                data[i] = static_cast<u32>(i);
            }
            
            std::vector<u32> output(size);
            
            // Test FeistelPerm
            {
                FeistelPerm perm(size);
                
                // Permute the data using dualEncode
                perm.dualEncode(span<const u32>(data), span<u32>(output));
                
                // Verify that the permutation contains all the original elements
                std::set<u32> uniqueValues;
                for (u64 i = 0; i < size; ++i)
                {
                   if( uniqueValues.insert(output[i]).second == false )
                   {
                       throw std::runtime_error("FeistelPerm data permutation failed: duplicate element found");
				   }
                }
                
                if (uniqueValues.size() != size)
                {
                    throw std::runtime_error("FeistelPerm data permutation failed: not all elements preserved");
                }
                
                //std::cout << "FeistelPerm size " << size << " passed data permutation test" << std::endl;
            }
            
            // Reset output for next test
            std::fill(output.begin(), output.end(), 0);
            
            // Test FeistelPerm iterator interface
            {
                FeistelPerm perm(size);
                
                // Use iterator interface to permute data
                auto iter = perm.begin(output.data());
                for (u64 i = 0; i < size; ++i)
                {
                    *iter = data[i];
                    ++iter;
                }
                
                // Verify permutation
                std::set<u32> uniqueValues;
                for (u64 i = 0; i < size; ++i)
                {
                    uniqueValues.insert(output[i]);
                }
                
                if (uniqueValues.size() != size)
                {
                    throw std::runtime_error("FeistelPerm iterator interface failed: not all elements preserved");
                }
                
                //std::cout << "FeistelPerm size " << size << " passed iterator interface test" << std::endl;
            }
        }
    }

    void Permutation_chunk_test(const CLP& cmd)
    {
        // Test chunk functionality
        std::vector<u64> sizes = { 64, 1024, 4096 };
        
        for (auto size : sizes)
        {
            // Create test data
            std::vector<u32> data(size);
            for (u64 i = 0; i < size; ++i)
            {
                data[i] = static_cast<u32>(i);
            }
            
            std::vector<u32> output(size);
            
            // Test Feistel2KPerm chunk
            {
                Feistel2KPerm perm2k(size);
                
                // Use chunk interface to permute data
                auto iter = perm2k.begin(output.data());
                u64 processed = 0;
                
                while (processed < size)
                {
                    u64 remaining = size - processed;
                    if (remaining >= Feistel2KPerm::chunkSize)
                    {
                        perm2k.chunk(iter, data.data() + processed);
                        processed += Feistel2KPerm::chunkSize;
                    }
                    else
                    {
                        // Process remaining elements one by one
                        for (u64 i = 0; i < remaining; ++i)
                        {
                            *iter = data[processed + i];
                            ++iter;
                        }
                        processed += remaining;
                    }
                }
                
                // Verify permutation
                std::set<u32> uniqueValues;
                for (u64 i = 0; i < size; ++i)
                {
                    uniqueValues.insert(output[i]);
                }
                
                if (uniqueValues.size() != size)
                {
                    throw std::runtime_error("Feistel2KPerm chunk interface failed: not all elements preserved");
                }
                
                //std::cout << "Feistel2KPerm size " << size << " passed chunk interface test" << std::endl;
            }
        }
        
        // Test non-power-of-2 sizes with FeistelPerm
        std::vector<u64> nonPow2Sizes = { 100, 1000, 3000 };
        
        for (auto size : nonPow2Sizes)
        {
            // Create test data
            std::vector<u32> data(size);
            for (u64 i = 0; i < size; ++i)
            {
                data[i] = static_cast<u32>(i);
            }
            
            std::vector<u32> output(size);
            
            // Test FeistelPerm chunk
            {
                FeistelPerm perm(size);
                
                // Use chunk interface to permute data
                auto iter = perm.begin(output.data());
                u64 processed = 0;
                
                while (processed < size)
                {
                    u64 remaining = size - processed;
                    if (remaining >= FeistelPerm::chunkSize)
                    {
                        perm.chunk(iter, data.data() + processed);
                        processed += FeistelPerm::chunkSize;
                    }
                    else
                    {
                        // Process remaining elements one by one
                        for (u64 i = 0; i < remaining; ++i)
                        {
                            *iter = data[processed + i];
                            ++iter;
                        }
                        processed += remaining;
                    }
                }
                
                // Verify permutation
                std::set<u32> uniqueValues;
                for (u64 i = 0; i < size; ++i)
                {
                    uniqueValues.insert(output[i]);
                }
                
                if (uniqueValues.size() != size)
                {
                    throw std::runtime_error("FeistelPerm chunk interface failed: not all elements preserved");
                }
                
                //std::cout << "FeistelPerm size " << size << " passed chunk interface test" << std::endl;
            }
        }
    }

    void Permutation_performance_test(const CLP& cmd)
    {
        // Performance comparison for power-of-2 sizes
        std::vector<u64> sizes = { 1024, 4096, 16384, 65536 };
        
        std::cout << "\n=== Performance Comparison ===" << std::endl;
        std::cout << "Size      | Feistel2KPerm | FeistelPerm   | Ratio" << std::endl;
        std::cout << "----------|---------------|---------------|-------" << std::endl;
        
        for (auto size : sizes)
        {
            // Create test data
            std::vector<u32> data(size);
            for (u64 i = 0; i < size; ++i)
            {
                data[i] = static_cast<u32>(i);
            }
            
            std::vector<u32> output1(size), output2(size);
            
            // Measure Feistel2KPerm performance
            Timer timer;
            timer.setTimePoint("start");
            
            Feistel2KPerm perm2k(size);
            perm2k.dualEncode(span<const u32>(data), span<u32>(output1));
            
            timer.setTimePoint("feistel2k");
            
            // Measure FeistelPerm performance
            FeistelPerm perm(size);
            perm.dualEncode(span<const u32>(data), span<u32>(output2));
            
            timer.setTimePoint("feistel");
            
            // Calculate timings
            double time2k = std::chrono::duration_cast<std::chrono::microseconds>(timer["feistel2k"] - timer["start"]).count();
            double timePerm = std::chrono::duration_cast<std::chrono::microseconds>(timer["feistel"] - timer["feistel2k"]).count();
            double ratio = timePerm / time2k;
            
            std::cout << std::setw(10) << size << " | " 
                      << std::setw(13) << std::fixed << std::setprecision(3) << time2k << " ms | " 
                      << std::setw(13) << std::fixed << std::setprecision(3) << timePerm << " ms | " 
                      << std::setw(5) << std::fixed << std::setprecision(2) << ratio << "x" << std::endl;
        }
        
        // Performance comparison for non-power-of-2 sizes
        std::vector<u64> nonPow2Sizes = { 1000, 4000, 16000, 60000 };
        
        std::cout << "\n=== Non-Power-of-2 Performance ===" << std::endl;
        std::cout << "Size      | FeistelPerm" << std::endl;
        std::cout << "----------|-------------" << std::endl;
        
        for (auto size : nonPow2Sizes)
        {
            // Create test data
            std::vector<u32> data(size);
            for (u64 i = 0; i < size; ++i)
            {
                data[i] = static_cast<u32>(i);
            }
            
            std::vector<u32> output(size);
            
            // Measure FeistelPerm performance
            Timer timer;
            timer.setTimePoint("start");
            
            FeistelPerm perm(size);
            perm.dualEncode(span<const u32>(data), span<u32>(output));
            
            timer.setTimePoint("feistel");
            
            // Calculate timing
            double timePerm = std::chrono::duration_cast<std::chrono::microseconds>(timer["feistel"] - timer["start"]).count();
            
            std::cout << std::setw(10) << size << " | " 
                      << std::setw(11) << std::fixed << std::setprecision(3) << timePerm << " ms" << std::endl;
        }
    }
}