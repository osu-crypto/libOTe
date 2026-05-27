#pragma once

#include "loglabel/ring_types.hpp"

#include <vector>

namespace loglabel
{
    using keyderive_params = ring_params;

    struct keyderive_sender_input
    {
        keyderive_params params{};
        std::vector<ring_rns_poly> sk1{};
        std::vector<ring_rns_poly> sk2{};
    };

    struct keyderive_receiver_input
    {
        keyderive_params params{};
        std::vector<ring_rns_poly> d{};
    };

    struct keyderive_sender_output
    {
        std::vector<ring_rns_poly> k{};
    };

    struct keyderive_receiver_output
    {
        std::vector<ring_rns_poly> m{};
    };

} // namespace loglabel
