#pragma once

namespace loglabel
{
    // Standard noise and security parameters used across the protocol
    struct shrinkexpand_noise_params
    {
        // Standard deviation of the secret key distribution
        static constexpr double std_s = 3.19;

        // Statistical security parameter for noise flooding
        static constexpr double lambda = 128.0;
    };

} // namespace loglabel
