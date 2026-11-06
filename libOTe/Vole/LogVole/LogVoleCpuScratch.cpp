#include "libOTe/Vole/LogVole/LogVoleCpuScratch.h"
#include "libOTe/Vole/LogVole/LogVoleTypes.h"
#include "libOTe/Vole/LogVole/LogVoleLhe.h"

#include <stdexcept>
#include <utility>

namespace osuCrypto::LogVole::detail
{
    struct ShrinkExpandScratch::Slot
    {
        std::vector<RnsPoly> mCt2;
        LheDecScratch mLheDec;
        bool mInUse = false;
    };

    ShrinkExpandScratch::ShrinkExpandScratch() = default;
    ShrinkExpandScratch::~ShrinkExpandScratch() = default;

    ShrinkExpandScratch::Lease::Lease(
        std::shared_ptr<ShrinkExpandScratch> owner, Slot& slot) noexcept
        : mOwner(std::move(owner)), mSlot(&slot) {}

    ShrinkExpandScratch::Lease::Lease(Lease&& other) noexcept
        : mOwner(std::move(other.mOwner)), mSlot(std::exchange(other.mSlot, nullptr)) {}

    ShrinkExpandScratch::Lease::~Lease()
    {
        if (mSlot) mOwner->release(*mSlot);
    }

    std::vector<RnsPoly>& ShrinkExpandScratch::Lease::ct2() const
    {
        return mSlot->mCt2;
    }

    LheDecScratch& ShrinkExpandScratch::Lease::lheDec() const
    {
        return mSlot->mLheDec;
    }

    ShrinkExpandScratch::Lease ShrinkExpandScratch::acquire(
        std::shared_ptr<ShrinkExpandScratch> owner)
    {
        if (!owner) throw std::invalid_argument("Missing shrink/expand scratch owner");
        auto& pool = *owner;
        std::lock_guard lock(pool.mMutex);
        for (auto& slot : pool.mSlots)
        {
            if (!slot->mInUse)
            {
                slot->mInUse = true;
                return Lease(std::move(owner), *slot);
            }
        }
        auto slot = std::make_unique<Slot>();
        slot->mInUse = true;
        pool.mSlots.push_back(std::move(slot));
        return Lease(std::move(owner), *pool.mSlots.back());
    }

    void ShrinkExpandScratch::release(Slot& slot) noexcept
    {
        std::lock_guard lock(mMutex);
        slot.mInUse = false;
    }
}
