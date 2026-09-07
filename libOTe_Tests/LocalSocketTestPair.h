#pragma once

#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/thread_pool.h"
#include "macoro/when_all.h"
#include "macoro/sync_wait.h"

namespace tests_libOTe
{
    // Queue local protocol continuations instead of recursively resuming the
    // peer on the same native stack. All work still runs on the calling thread,
    // including fixtures that share a PRNG. The executor outlives both sockets.
    class LocalSocketTestPair
    {
        macoro::thread_pool mExecutor;
        std::array<coproto::LocalAsyncSocket, 2> mSockets =
            coproto::LocalAsyncSocket::makePair();

    public:
        LocalSocketTestPair()
        {
            for (auto& socket : mSockets)
                socket.setExecutor(mExecutor);
        }

        LocalSocketTestPair(const LocalSocketTestPair&) = delete;
        LocalSocketTestPair& operator=(const LocalSocketTestPair&) = delete;

        coproto::LocalAsyncSocket& operator[](std::size_t i) { return mSockets[i]; }

        template<typename... Tasks>
        auto run(Tasks&&... tasks)
        {
            auto result = macoro::when_all_ready(std::forward<Tasks>(tasks)...)
                | macoro::make_eager();
            mExecutor.run();
            return macoro::sync_wait(std::move(result));
        }
    };
}
