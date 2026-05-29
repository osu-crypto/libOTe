#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include "logvole/comm/types.hpp"

namespace logvole
{
    namespace detail
    {
        inline std::size_t hardware_worker_slots()
        {
            const std::size_t hw = static_cast<std::size_t>(std::thread::hardware_concurrency());
            return hw == 0u ? 1u : hw;
        }

        inline std::atomic<std::size_t> global_parallel_worker_slots_in_use{ 0u };
        inline thread_local std::size_t thread_local_parallel_worker_cap = 0u;

        class parallel_worker_cap_scope
        {
        public:
            explicit parallel_worker_cap_scope(std::size_t worker_cap)
                : previous_cap_(thread_local_parallel_worker_cap)
            {
                if (worker_cap == 0u)
                {
                    return;
                }

                if (previous_cap_ == 0u)
                {
                    thread_local_parallel_worker_cap = worker_cap;
                }
                else
                {
                    thread_local_parallel_worker_cap = std::min(previous_cap_, worker_cap);
                }
            }

            parallel_worker_cap_scope(const parallel_worker_cap_scope &) = delete;
            parallel_worker_cap_scope &operator=(const parallel_worker_cap_scope &) = delete;

            ~parallel_worker_cap_scope()
            {
                thread_local_parallel_worker_cap = previous_cap_;
            }

        private:
            std::size_t previous_cap_ = 0u;
        };

        class parallel_worker_slot_guard
        {
        public:
            explicit parallel_worker_slot_guard(std::size_t requested_workers)
            {
                granted_workers_ = 1u;
                if (requested_workers <= 1u)
                {
                    return;
                }

                const std::size_t max_slots = hardware_worker_slots();
                while (true)
                {
                    std::size_t used = global_parallel_worker_slots_in_use.load(std::memory_order_acquire);
                    if (used >= max_slots)
                    {
                        // Fallback to caller-only execution when all slots are occupied.
                        return;
                    }

                    const std::size_t available = max_slots - used;
                    const std::size_t grant = std::min(requested_workers, available);
                    if (global_parallel_worker_slots_in_use.compare_exchange_weak(
                            used, used + grant, std::memory_order_acq_rel, std::memory_order_acquire))
                    {
                        granted_workers_ = grant;
                        reserved_workers_ = grant;
                        return;
                    }
                }
            }

            parallel_worker_slot_guard(const parallel_worker_slot_guard &) = delete;
            parallel_worker_slot_guard &operator=(const parallel_worker_slot_guard &) = delete;

            ~parallel_worker_slot_guard()
            {
                if (reserved_workers_ != 0u)
                {
                    global_parallel_worker_slots_in_use.fetch_sub(reserved_workers_, std::memory_order_release);
                }
            }

            std::size_t granted_workers() const
            {
                return granted_workers_;
            }

        private:
            std::size_t granted_workers_ = 1u;
            std::size_t reserved_workers_ = 0u;
        };

        inline std::size_t resolve_worker_count(std::uint32_t requested_workers, std::size_t task_count)
        {
            if (task_count <= 1u)
            {
                return 1u;
            }

            std::size_t workers = static_cast<std::size_t>(requested_workers);
            if (requested_workers == 0u)
            {
                workers = static_cast<std::size_t>(std::thread::hardware_concurrency());
            }

            if (workers == 0u)
            {
                workers = 1u;
            }

            if (thread_local_parallel_worker_cap != 0u)
            {
                workers = std::min(workers, thread_local_parallel_worker_cap);
            }

            return std::min(workers, task_count);
        }

        template <typename TaskFn>
        comm::protocol_result<void> run_parallel_tasks(
            std::size_t task_count, std::uint32_t requested_workers, TaskFn &&task_fn)
        {
            if (task_count == 0u)
            {
                return comm::protocol_result<void>::success();
            }

            const std::size_t worker_count_requested = resolve_worker_count(requested_workers, task_count);
            parallel_worker_slot_guard worker_slot_guard(worker_count_requested);
            const std::size_t worker_count = std::min(worker_count_requested, worker_slot_guard.granted_workers());
            if (worker_count <= 1u)
            {
                for (std::size_t task_idx = 0u; task_idx < task_count; ++task_idx)
                {
                    auto task_result = task_fn(task_idx);
                    if (!task_result)
                    {
                        return task_result;
                    }
                }
                return comm::protocol_result<void>::success();
            }

            std::atomic<std::size_t> next_task_idx{ 0u };
            std::atomic<bool> failed{ false };
            std::mutex failure_mutex{};
            comm::protocol_errc failure_code = comm::protocol_errc::flow_violation;
            std::string failure_message = "parallel task failed";
            const std::size_t batch_size = (task_count >= (worker_count * 8u)) ? 4u : 1u;

            auto worker = [&]() {
                while (!failed.load(std::memory_order_acquire))
                {
                    const std::size_t batch_start = next_task_idx.fetch_add(batch_size, std::memory_order_relaxed);
                    if (batch_start >= task_count)
                    {
                        break;
                    }

                    const std::size_t batch_end = std::min(batch_start + batch_size, task_count);
                    for (std::size_t task_idx = batch_start; task_idx < batch_end; ++task_idx)
                    {
                        if (failed.load(std::memory_order_acquire))
                        {
                            break;
                        }

                        auto task_result = task_fn(task_idx);
                        if (!task_result)
                        {
                            bool expected = false;
                            if (failed.compare_exchange_strong(
                                    expected, true, std::memory_order_acq_rel, std::memory_order_acquire))
                            {
                                std::lock_guard<std::mutex> lock(failure_mutex);
                                failure_code = task_result.error();
                                failure_message = task_result.message();
                            }
                            break;
                        }
                    }
                }
            };

            std::vector<std::thread> workers;
            workers.reserve(worker_count - 1u);
            for (std::size_t i = 1u; i < worker_count; ++i)
            {
                workers.emplace_back(worker);
            }

            // Use the calling thread as one worker to reduce thread create/join overhead.
            worker();

            for (auto &thread : workers)
            {
                thread.join();
            }

            if (failed.load(std::memory_order_acquire))
            {
                return comm::protocol_result<void>::failure(failure_code, failure_message);
            }

            return comm::protocol_result<void>::success();
        }
    } // namespace detail
} // namespace logvole
