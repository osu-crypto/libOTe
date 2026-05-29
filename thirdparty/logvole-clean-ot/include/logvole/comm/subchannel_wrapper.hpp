#pragma once

#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <unordered_map>
#include "logvole/comm/channel.hpp"

namespace logvole::comm
{
    namespace detail
    {
        struct subchannel_demux_state
        {
            std::mutex mutex;
            std::condition_variable cv;
            bool recv_in_progress = false;
            std::unordered_map<std::uint64_t, std::deque<byte_buffer>> pending_frames_by_session{};
        };

        inline std::shared_ptr<subchannel_demux_state> get_subchannel_demux_state(channel_interface *parent)
        {
            static std::mutex map_mutex;
            static std::unordered_map<channel_interface *, std::weak_ptr<subchannel_demux_state>> map;

            std::lock_guard<std::mutex> lock(map_mutex);
            for (auto it = map.begin(); it != map.end();)
            {
                if (it->second.expired())
                {
                    it = map.erase(it);
                }
                else
                {
                    ++it;
                }
            }

            auto &slot = map[parent];
            auto state = slot.lock();
            if (!state)
            {
                state = std::make_shared<subchannel_demux_state>();
                slot = state;
            }
            return state;
        }

        inline bool pop_pending_frame_locked(
            subchannel_demux_state &state, std::uint64_t session_id, byte_buffer &out_frame)
        {
            auto it = state.pending_frames_by_session.find(session_id);
            if (it == state.pending_frames_by_session.end() || it->second.empty())
            {
                return false;
            }

            out_frame = std::move(it->second.front());
            it->second.pop_front();
            if (it->second.empty())
            {
                state.pending_frames_by_session.erase(it);
            }
            return true;
        }

        inline bool has_pending_frame_locked(const subchannel_demux_state &state, std::uint64_t session_id)
        {
            auto it = state.pending_frames_by_session.find(session_id);
            return it != state.pending_frames_by_session.end() && !it->second.empty();
        }
    } // namespace detail

    class subchannel_wrapper : public channel_interface
    {
    public:
        subchannel_wrapper(channel_interface *parent, std::uint64_t sub_session_id)
            : channel_interface(parent->config()), parent_(parent), transport_parent_(parent),
              demux_state_(detail::get_subchannel_demux_state(parent))
        {
            // Recursive protocol layers can create subchannels from subchannels.
            // Always demux against the transport-root parent so outer wrappers do not trap inner-session frames.
            if (auto *parent_subchannel = dynamic_cast<subchannel_wrapper *>(parent_))
            {
                transport_parent_ = parent_subchannel->transport_parent_;
                demux_state_ = parent_subchannel->demux_state_;
            }

            config_.session_id = sub_session_id;
        }

        protocol_result<void> send_frame(byte_buffer frame) override
        {
            return transport_parent_->send_frame(std::move(frame));
        }

        protocol_result<byte_buffer> recv_frame() override
        {
            if (!transport_parent_)
            {
                return protocol_result<byte_buffer>::failure(protocol_errc::config_error, "missing parent channel");
            }
            if (!demux_state_)
            {
                return protocol_result<byte_buffer>::failure(
                    protocol_errc::config_error, "missing subchannel demux state");
            }

            const std::uint64_t target_session_id = config_.session_id;
            const auto timeout = config_.recv_timeout;
            const bool finite_timeout = timeout.count() > 0;
            const auto deadline = std::chrono::steady_clock::now() + timeout;

            while (true)
            {
                {
                    std::unique_lock<std::mutex> lock(demux_state_->mutex);
                    byte_buffer pending_frame;
                    if (detail::pop_pending_frame_locked(*demux_state_, target_session_id, pending_frame))
                    {
                        return protocol_result<byte_buffer>::success(std::move(pending_frame));
                    }

                    if (demux_state_->recv_in_progress)
                    {
                        if (!finite_timeout)
                        {
                            return protocol_result<byte_buffer>::failure(
                                protocol_errc::timeout, "subchannel receive timeout");
                        }

                        const bool woke = demux_state_->cv.wait_until(lock, deadline, [&]() {
                            return !demux_state_->recv_in_progress ||
                                   detail::has_pending_frame_locked(*demux_state_, target_session_id);
                        });
                        if (!woke)
                        {
                            return protocol_result<byte_buffer>::failure(
                                protocol_errc::timeout, "subchannel receive timeout");
                        }

                        // Re-check queues/reader ownership at top of loop.
                        continue;
                    }

                    demux_state_->recv_in_progress = true;
                }

                auto frame_result = transport_parent_->recv_frame();
                if (!frame_result)
                {
                    {
                        std::lock_guard<std::mutex> lock(demux_state_->mutex);
                        demux_state_->recv_in_progress = false;
                    }
                    demux_state_->cv.notify_all();
                    return frame_result;
                }

                auto frame = std::move(frame_result.value());
                auto parsed = deserialize_frame(frame);
                if (!parsed)
                {
                    {
                        std::lock_guard<std::mutex> lock(demux_state_->mutex);
                        demux_state_->recv_in_progress = false;
                    }
                    demux_state_->cv.notify_all();
                    return protocol_result<byte_buffer>::failure(parsed.error(), parsed.message());
                }

                const std::uint64_t frame_session_id = parsed.value().first.session_id;
                {
                    std::lock_guard<std::mutex> lock(demux_state_->mutex);
                    if (frame_session_id == target_session_id)
                    {
                        demux_state_->recv_in_progress = false;
                        demux_state_->cv.notify_all();
                        return protocol_result<byte_buffer>::success(std::move(frame));
                    }

                    demux_state_->pending_frames_by_session[frame_session_id].push_back(std::move(frame));
                    demux_state_->recv_in_progress = false;
                }
                demux_state_->cv.notify_all();
            }
        }

    private:
        channel_interface *parent_;
        channel_interface *transport_parent_;
        std::shared_ptr<detail::subchannel_demux_state> demux_state_{};
    };

} // namespace logvole::comm
