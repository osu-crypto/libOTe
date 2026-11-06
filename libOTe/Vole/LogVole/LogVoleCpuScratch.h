#pragma once

#include <memory>
#include <mutex>
#include <vector>

namespace osuCrypto::LogVole
{
    struct RnsPoly;

    namespace detail
    {
        class CpuRowScratch;
        // State-owned CPU workspace. Copies of a protocol state may share this
        // owner: overlapping calls lease separate slots, while completed calls
        // leave capacity available to any worker. No thread history is retained.
        class ShrinkExpandScratch
        {
            struct Slot;
            std::mutex mMutex;
            std::vector<std::unique_ptr<Slot>> mSlots;
            void release(Slot& slot) noexcept;

        public:
            class Lease
            {
                friend class ShrinkExpandScratch;
                std::shared_ptr<ShrinkExpandScratch> mOwner;
                Slot* mSlot;
                Lease(std::shared_ptr<ShrinkExpandScratch> owner, Slot& slot) noexcept;

            public:
                ~Lease();
                Lease(Lease&& other) noexcept;
                Lease(const Lease&) = delete;
                Lease& operator=(const Lease&) = delete;
                Lease& operator=(Lease&&) = delete;

                // Exclusive storage, valid until this lease is released. The
                // lease retains its owner; no mutex is held during computation.
                std::vector<RnsPoly>& ct2() const;
                CpuRowScratch& cpuRows() const;
            };

            ShrinkExpandScratch();
            ~ShrinkExpandScratch();
            ShrinkExpandScratch(const ShrinkExpandScratch&) = delete;
            ShrinkExpandScratch& operator=(const ShrinkExpandScratch&) = delete;

            static Lease acquire(std::shared_ptr<ShrinkExpandScratch> owner);
        };
    }
}
