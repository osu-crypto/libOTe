#pragma once

#include "logvole/comm/types.hpp"

#include <cstddef>
#include <tuple>
#include <type_traits>

namespace logvole::comm
{
    template <class Msg, role_t From>
    struct round_send
    {
        using message_type = Msg;
        static constexpr role_t from = From;
    };

    template <class Msg, role_t To>
    struct round_recv
    {
        using message_type = Msg;
        static constexpr role_t to = To;
    };

    template <class SendStep, class RecvStep>
    struct round_pair
    {
        using send_step = SendStep;
        using recv_step = RecvStep;
        using message_type = typename send_step::message_type;

        static_assert(std::is_same<typename send_step::message_type, typename recv_step::message_type>::value,
                      "round_pair requires identical message types for send and recv");

        static_assert(send_step::from == opposite_role(recv_step::to),
                      "round_pair requires complementary send and recv roles");
    };

    template <class... Pairs>
    struct round_script
    {
        using tuple_type = std::tuple<Pairs...>;
        static constexpr std::size_t round_count = sizeof...(Pairs);

        template <std::size_t RoundIndex>
        using round_type = typename std::tuple_element<RoundIndex, tuple_type>::type;
    };

    template <class Script>
    struct round_script_traits;

    template <class... Pairs>
    struct round_script_traits<round_script<Pairs...>>
    {
        using tuple_type = std::tuple<Pairs...>;
        static constexpr std::size_t round_count = sizeof...(Pairs);

        template <std::size_t RoundIndex>
        using round_type = typename std::tuple_element<RoundIndex, tuple_type>::type;
    };

    template <class Pair, role_t Role>
    struct role_round_action
    {
        static constexpr bool is_send = Pair::send_step::from == Role;
        static constexpr bool is_recv = Pair::recv_step::to == Role;
        using message_type = typename Pair::message_type;

        static_assert(is_send ^ is_recv,
                      "exactly one role-side action must be active for each round");
    };

} // namespace logvole::comm
