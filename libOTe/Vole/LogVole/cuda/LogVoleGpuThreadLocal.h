#pragma once

#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#include <atomic>
#include <memory>

namespace osuCrypto::LogVole::gpu
{
    namespace thread_storage_detail
    {
        // CUDA cannot safely be called from Windows thread-detach callbacks.
        // TLS retires its entire group; a live thread drains retired GPU owners.
        struct ThreadResourceNode
        {
            ThreadResourceNode* next = nullptr;
            void (*destroy)(ThreadResourceNode*) noexcept = nullptr;
        };
        void registerThreadResource(ThreadResourceNode* node);
    }

    // One allocation/registration on first use per thread, with a direct typed
    // reference thereafter. No locks, virtual calls or reference counting in
    // accesses. Destruction dispatch is confined to cold resource collection.
    template<typename T>
    class GpuThreadLocal
    {
        struct Owner : thread_storage_detail::ThreadResourceNode
        {
            T value{};
            Owner()
            {
                destroy = [](thread_storage_detail::ThreadResourceNode* node) noexcept {
                    delete static_cast<Owner*>(node);
                };
            }
        };
        Owner* mOwner;
    public:
        GpuThreadLocal()
        {
            gpuCollectThreadResources();
            auto owner = std::make_unique<Owner>();
            thread_storage_detail::registerThreadResource(owner.get());
            mOwner = owner.release();
        }
        ~GpuThreadLocal() = default;
        GpuThreadLocal(const GpuThreadLocal&) = delete;
        GpuThreadLocal& operator=(const GpuThreadLocal&) = delete;
        T& get() noexcept { return mOwner->value; }
    };
}
