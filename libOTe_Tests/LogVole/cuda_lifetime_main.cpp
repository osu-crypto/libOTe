#include "libOTe/Vole/LogVole/cuda/LogVoleGpuMemory.h"
#include <cuda_runtime_api.h>
#include <array>
#include <future>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <thread>

using namespace osuCrypto::LogVole::gpu;

namespace
{
    struct Cancelled {};
    void require(bool condition, const char* message)
    {
        if (!condition) throw std::runtime_error(message);
    }
    void check(cudaError_t error)
    {
        if (error != cudaSuccess) throw std::runtime_error(cudaGetErrorString(error));
    }
    void fill(OwnedGpuBuffer& buffer, unsigned char value)
    {
        check(cudaMemsetAsync(buffer.data(), value, buffer.size(),
            static_cast<cudaStream_t>(buffer.stream()->raw())));
    }
    void verify(OwnedGpuBuffer& buffer, unsigned char value)
    {
        std::array<unsigned char, 4099> host{};
        require(buffer.size() == host.size(), "incorrect buffer size");
        check(cudaMemcpyAsync(host.data(), buffer.data(), host.size(), cudaMemcpyDeviceToHost,
            static_cast<cudaStream_t>(buffer.stream()->raw())));
        buffer.stream()->synchronize();
        for (auto byte : host) require(byte == value, "CUDA lifetime data mismatch");
    }
}

int main()
{
    try
    {
        for (unsigned round = 0; round != 3; ++round)
        {
            auto memory = std::make_shared<GpuMemoryPool>(0);
            auto first = std::make_shared<OwnedGpuStream>(memory);
            auto second = std::make_shared<OwnedGpuStream>(memory);
            OwnedGpuBuffer buffer(first, 4099);
            fill(buffer, 17 + round);
            // No producer synchronization before the exclusive handoff.
            buffer.handoff(second);
            verify(buffer, 17 + round);

            // An idle trim must not release a live allocation. Exercise reuse
            // on both the original and a different stream, including last use
            // still queued when the old buffer goes out of scope.
            for (unsigned i = 0; i != 8; ++i)
            {
                OwnedGpuBuffer temporary(i & 1 ? first : second, 4099);
                fill(temporary, i);
                if (i == 3) memory->trim();
            }
            verify(buffer, 17 + round);
            memory->trim();
            verify(buffer, 17 + round);

            // Both memory and stream are retained by the exported buffer.
            std::weak_ptr<GpuMemoryPool> weakMemory = memory;
            std::weak_ptr<OwnedGpuStream> weakStream = second;
            first.reset();
            second.reset();
            memory.reset();
            require(!weakMemory.expired() && !weakStream.expired(), "owner released too early");
            verify(buffer, 17 + round);
            buffer.reset();
            require(weakStream.expired() && weakMemory.expired(), "allocation ownership cycle");
        }

        // A worker can exit with an exported allocation. Destruction belongs
        // to the receiving scope, with no CUDA calls from TLS detach callbacks.
        std::packaged_task<OwnedGpuBuffer()> task([] {
            auto memory = std::make_shared<GpuMemoryPool>(0);
            auto stream = std::make_shared<OwnedGpuStream>(memory);
            OwnedGpuBuffer result(stream, 4099);
            fill(result, 91);
            return result;
        });
        auto result = task.get_future();
        std::thread worker(std::move(task));
        worker.join();
        auto exported = result.get();
        verify(exported, 91);
        exported.reset();

        // Independent workers share only the allocation domain. They retain
        // separate streams and scratch, including concurrent pool bookkeeping.
        auto sharedMemory = std::make_shared<GpuMemoryPool>(0);
        std::array<std::packaged_task<void()>, 2> tasks;
        std::array<std::future<void>, 2> completions;
        std::array<std::thread, 2> workers;
        for (unsigned i = 0; i != workers.size(); ++i)
        {
            tasks[i] = std::packaged_task<void()>([sharedMemory, i] {
                auto stream = std::make_shared<OwnedGpuStream>(sharedMemory);
                for (unsigned j = 0; j != 4; ++j)
                {
                    OwnedGpuBuffer buffer(stream, 4099);
                    fill(buffer, 10 + i * 4 + j);
                    verify(buffer, 10 + i * 4 + j);
                }
            });
            completions[i] = tasks[i].get_future();
            workers[i] = std::thread(std::move(tasks[i]));
        }
        for (auto& thread : workers) thread.join();
        for (auto& completion : completions) completion.get();
        sharedMemory->trim();

        // Rejection and exception unwinding must leave the original allocation
        // usable and release every owner, including outstanding stream work.
        auto memory = std::make_shared<GpuMemoryPool>(0);
        auto stream = std::make_shared<OwnedGpuStream>(memory);
        auto otherMemory = std::make_shared<GpuMemoryPool>(0);
        auto otherStream = std::make_shared<OwnedGpuStream>(otherMemory);
        OwnedGpuBuffer original(stream, 4099);
        fill(original, 63);
        bool rejected = false;
        try { original.handoff(otherStream); }
        catch (const std::invalid_argument&) { rejected = true; }
        require(rejected, "cross-domain handoff accepted");
        verify(original, 63);
        OwnedGpuBuffer moved(std::move(original));
        require(!original.data() && original.size() == 0 && !original.stream(), "invalid moved-from buffer");
        verify(moved, 63);
        rejected = false;
        try { OwnedGpuBuffer oversized(stream, std::numeric_limits<std::size_t>::max()); }
        catch (const std::length_error&) { rejected = true; }
        require(rejected, "oversized allocation accepted");
        try
        {
            OwnedGpuBuffer abandoned(stream, 4099);
            fill(abandoned, 127);
            throw Cancelled{};
        }
        catch (const Cancelled&) {}
        memory->trim();
        verify(moved, 63);
        std::cout << "CUDA owned lifetime checks passed\n";
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
