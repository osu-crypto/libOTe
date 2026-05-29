#pragma once

#include "logvole/seedlabel_backend.hpp"

namespace logvole
{
    // LogVOLE reuses the SeedLabel backend implementation; protocol-side logic applies
    // truncation-specific parameterization and high-digit decomposition.
    using logvole_backend = seedlabel_backend;
    using logvole_seal_backend = seedlabel_seal_backend;
} // namespace logvole
