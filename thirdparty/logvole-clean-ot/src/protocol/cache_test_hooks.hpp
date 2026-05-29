#pragma once

namespace logvole
{
    void clear_lhe_public_a_cache_for_testing();
    void clear_shrinkexpand_runtime_caches_for_testing();

    inline void clear_protocol_runtime_caches_for_testing()
    {
        clear_lhe_public_a_cache_for_testing();
        clear_shrinkexpand_runtime_caches_for_testing();
    }

} // namespace logvole
