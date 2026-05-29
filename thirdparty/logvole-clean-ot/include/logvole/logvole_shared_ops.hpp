#pragma once

#include <cstdint>
#include <vector>
#include "logvole/comm/types.hpp"
#include "logvole/ring_ops.hpp"
#include "logvole/ring_types.hpp"

namespace logvole
{
    struct ring_ntt_context;

    enum class logvole_mode
    {
        root = 0, // w <= alpha * tau_hi * rho
        internal = 1 // w > alpha * tau_hi * rho
    };

    logvole_mode eval_logvole_mode(std::uint32_t w, std::uint32_t alpha, std::uint32_t tau, std::uint32_t rho);
} // namespace logvole
