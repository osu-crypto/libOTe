#include "logvole/logvole_shared_ops.hpp"

namespace logvole
{
    logvole_mode eval_logvole_mode(std::uint32_t w, std::uint32_t alpha, std::uint32_t tau, std::uint32_t rho)
    {
        if (w <= alpha * tau * rho)
        {
            return logvole_mode::root;
        }
        return logvole_mode::internal;
    }
} // namespace logvole
