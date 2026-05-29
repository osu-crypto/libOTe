#pragma once

#include <cstdint>
#include <vector>
#include "logvole/comm/types.hpp"
#include "logvole/ring_ops.hpp"
#include "logvole/ring_types.hpp"

namespace logvole
{
    struct ring_ntt_context;

    enum class seedlabel_mode
    {
        leaf = 0, // w <= tau * rho
        internal = 1 // w > tau * rho
    };

    seedlabel_mode eval_seedlabel_mode(std::uint32_t w, std::uint32_t alpha, std::uint32_t tau, std::uint32_t rho);
} // namespace logvole
