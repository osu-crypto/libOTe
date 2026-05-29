#pragma once

#include "logvole/comm/channel.hpp"

namespace logvole::comm
{
    protocol_result<any_channel> make_in_memory_channel_impl(const channel_config &config);
    protocol_result<any_channel> make_uds_channel_impl(const channel_config &config);
    protocol_result<any_channel> make_tcp_channel_impl(const channel_config &config);
}

