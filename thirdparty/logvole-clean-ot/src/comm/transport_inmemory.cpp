#include "channel_impl_factory.hpp"

#include <chrono>
#include <memory>
#include <utility>

namespace logvole::comm
{
    namespace
    {
        class in_memory_channel_impl : public channel_interface
        {
        public:
            in_memory_channel_impl(channel_config config, std::shared_ptr<in_memory_link> link)
                : channel_interface(std::move(config)), link_(std::move(link))
            {}

            protocol_result<void> send_frame(byte_buffer frame) override
            {
                if (!link_)
                {
                    return protocol_result<void>::failure(protocol_errc::config_error, "missing in-memory link");
                }

                auto &queue = send_queue();
                {
                    std::lock_guard<std::mutex> lock(queue.mutex);
                    queue.frames.emplace_back(std::move(frame));
                }
                queue.cv.notify_one();
                return protocol_result<void>::success();
            }

            protocol_result<byte_buffer> recv_frame() override
            {
                if (!link_)
                {
                    return protocol_result<byte_buffer>::failure(protocol_errc::config_error, "missing in-memory link");
                }

                auto &queue = recv_queue();
                std::unique_lock<std::mutex> lock(queue.mutex);

                if (config_.recv_timeout.count() <= 0)
                {
                    if (queue.frames.empty())
                    {
                        return protocol_result<byte_buffer>::failure(protocol_errc::timeout, "in-memory receive timeout");
                    }
                }
                else
                {
                    const bool ready = queue.cv.wait_for(lock, config_.recv_timeout, [&queue] { return !queue.frames.empty(); });
                    if (!ready)
                    {
                        return protocol_result<byte_buffer>::failure(protocol_errc::timeout, "in-memory receive timeout");
                    }
                }

                byte_buffer frame = std::move(queue.frames.front());
                queue.frames.pop_front();
                return protocol_result<byte_buffer>::success(std::move(frame));
            }

        private:
            in_memory_link::queue_state &send_queue()
            {
                return config_.role == role_t::sender ? link_->s2r : link_->r2s;
            }

            in_memory_link::queue_state &recv_queue()
            {
                return config_.role == role_t::sender ? link_->r2s : link_->s2r;
            }

            std::shared_ptr<in_memory_link> link_;
        };
    } // namespace

    protocol_result<any_channel> make_in_memory_channel_impl(const channel_config &config)
    {
        if (config.kind != transport_kind::in_memory)
        {
            return protocol_result<any_channel>::failure(protocol_errc::config_error, "in-memory factory received wrong kind");
        }

        if (!config.in_memory.link)
        {
            return protocol_result<any_channel>::failure(protocol_errc::config_error, "in-memory transport requires link");
        }

        auto impl = std::make_unique<in_memory_channel_impl>(config, config.in_memory.link);
        return protocol_result<any_channel>::success(any_channel(std::move(impl)));
    }

} // namespace logvole::comm
