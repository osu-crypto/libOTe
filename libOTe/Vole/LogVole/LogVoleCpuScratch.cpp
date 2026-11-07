#include "libOTe/Vole/LogVole/LogVoleCpuScratch.h"
#include "libOTe/Vole/LogVole/LogVoleTypes.h"
#include "libOTe/Vole/LogVole/LogVoleCpuRows.h"
#include "libOTe/Vole/LogVole/LogVoleCpuExecutor.h"

#include <stdexcept>
#include <utility>

namespace osuCrypto::LogVole::detail
{
    struct CpuRowScratch::Impl
    {
        CpuBenchmarkContext* mBenchmark;
        std::vector<Local> mLocals;
        // Destroy/join the executor before releasing its borrowed numerical storage.
        std::unique_ptr<CpuExecutor> mExecutor;
        Impl(std::size_t workers, std::size_t words, CpuBenchmarkContext* benchmark)
            : mBenchmark(benchmark), mLocals(workers)
        {
            if (words) for (auto& local : mLocals) local.mProduct.mCoeffs.resize(words);
            if (workers > 1) mExecutor = std::make_unique<CpuExecutor>(workers, benchmark);
        }
    };

    CpuRowScratch::CpuRowScratch() noexcept = default;
    CpuRowScratch::~CpuRowScratch() = default;

    std::span<CpuRowScratch::Local> CpuRowScratch::prepare(
        std::size_t workers, std::size_t words, CpuBenchmarkContext* benchmark, std::size_t terms)
    {
        if (!workers) throw std::invalid_argument("CPU rows require a partition");
        if (!mImpl || mImpl->mLocals.size() < workers || mImpl->mBenchmark != benchmark)
            mImpl = std::make_unique<Impl>(workers, words, benchmark);
        for (auto& local : std::span(mImpl->mLocals).first(workers))
        {
            if (words) local.mProduct.mCoeffs.resize(words);
            local.mCiphertexts.reserve(terms);
            local.mNodes.reserve(terms);
            local.mOk = true;
        }
        return std::span(mImpl->mLocals).first(workers);
    }

    CpuExecutor* CpuRowScratch::executor() noexcept
    {
        return mImpl ? mImpl->mExecutor.get() : nullptr;
    }

    std::size_t CpuRowScratch::setupWorkers(std::size_t tasks, u32 allowance,
        const CpuBenchmarkContext* benchmark)
    {
        const auto hardware = allowance == 1 ? std::size_t{1} :
            std::max<std::size_t>(1, std::thread::hardware_concurrency());
        auto capacity = hardware;
        if (benchmark)
            capacity = std::max<std::size_t>(1, benchmark->mWorkerLimit
                ? std::min(benchmark->mWorkerLimit, benchmark->mCpus.size()) : benchmark->mCpus.size());
        return std::min({tasks, capacity, allowance ? std::size_t(allowance) : hardware});
    }

    struct ShrinkExpandScratch::Slot
    {
        std::vector<RnsPoly> mCt2;
        CpuRowScratch mCpuRows;
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

    CpuRowScratch& ShrinkExpandScratch::Lease::cpuRows() const
    {
        return mSlot->mCpuRows;
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
