#pragma once

#include "libOTe/Vole/LogVole/LogVoleTypes.h"
#include "libOTe/Vole/LogVole/LogVoleCpuBenchmark.h"
#include <span>

namespace osuCrypto::LogVole
{
    namespace detail
    {
        class CpuExecutor;

        // Exclusive operation scratch. Empty until a CPU row phase needs it;
        // the VOLE scratch lease keeps it alive through the synchronous join.
        class CpuRowScratch
        {
            struct Impl;
            std::unique_ptr<Impl> mImpl;
        public:
            struct Local
            {
                RnsPoly mProduct;
                std::vector<const RnsPoly*> mCiphertexts, mNodes;
                bool mOk = true;
            };
            CpuRowScratch() noexcept;
            ~CpuRowScratch();
            CpuRowScratch(const CpuRowScratch&) = delete;
            CpuRowScratch& operator=(const CpuRowScratch&) = delete;
            std::span<Local> prepare(std::size_t workers, std::size_t words,
                CpuBenchmarkContext* benchmark, std::size_t terms = 0);
            CpuExecutor* executor() noexcept;
        };
    }

}
