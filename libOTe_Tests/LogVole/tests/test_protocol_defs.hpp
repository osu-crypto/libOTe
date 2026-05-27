#pragma once

#include "loglabel/comm/protocol_engine.hpp"

#include <cstdint>

namespace loglabel::comm::test_defs
{
    struct ping_msg
    {
        std::uint64_t nonce = 0;
    };

    struct pong_msg
    {
        std::uint32_t ok = 0;
    };

    struct wrong_ping_msg
    {
        std::uint64_t nonce = 0;
    };

    struct ping_pong_spec
    {
        using script = round_script<
            round_pair<round_send<ping_msg, role_t::sender>, round_recv<ping_msg, role_t::receiver>>,
            round_pair<round_send<pong_msg, role_t::receiver>, round_recv<pong_msg, role_t::sender>>>;
    };

    struct one_round_ping_spec
    {
        using script = round_script<
            round_pair<round_send<ping_msg, role_t::sender>, round_recv<ping_msg, role_t::receiver>>>;
    };

    struct one_round_wrong_ping_spec
    {
        using script = round_script<
            round_pair<round_send<wrong_ping_msg, role_t::sender>, round_recv<wrong_ping_msg, role_t::receiver>>>;
    };

} // namespace loglabel::comm::test_defs

LOGLABEL_DEFINE_TRIVIAL_MESSAGE_TRAITS(loglabel::comm::test_defs::ping_msg, 0x2001u);
LOGLABEL_DEFINE_TRIVIAL_MESSAGE_TRAITS(loglabel::comm::test_defs::pong_msg, 0x2002u);
LOGLABEL_DEFINE_TRIVIAL_MESSAGE_TRAITS(loglabel::comm::test_defs::wrong_ping_msg, 0x2003u);
