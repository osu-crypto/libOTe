#include "logvole/seedlabel_shared_ops.hpp"

namespace logvole
{
    seedlabel_mode eval_seedlabel_mode(std::uint32_t w, std::uint32_t alpha, std::uint32_t tau, std::uint32_t rho)
    {
        (void)alpha;
        if (w <= tau * rho)
        {
            return seedlabel_mode::leaf;
        }
        return seedlabel_mode::internal;
    }
} // namespace logvole
