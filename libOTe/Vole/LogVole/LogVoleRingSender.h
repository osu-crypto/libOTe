#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole/LogVoleCore.h"
#include "libOTe/Vole/LogVole/LogVoleShrinkExpand.h"

namespace osuCrypto::LogVole
{
    class LogVoleRingSender
    {
        task<> onlineStart(
            macoro::thread_pool& executor, std::span<LheDecryptBuffer> buffers,
            SenderState& state, const SenderOnlineOptions& options,
            SenderOnlineOutput& output, PRNG& prng, Socket& sock, ProtocolCacheScope cacheScope);

    public:
        task<> offline(
            const ShrinkExpandSenderOfflineInput& input,
            ShrinkExpandSenderState& state,
            PRNG& prng,
            Socket& sock);

        task<> offline(
            const SenderOfflineInput& input,
            SenderState& state,
            PRNG& prng,
            Socket& sock, RootWirePinOverlapEvidence& rootWirePin);

        task<> keyDerive(
            const KeyDeriveSenderInput& input,
            KeyDeriveSenderOutput& output,
            Socket& sock, LogVoleEncodingOptions encoding = {}, bool useGpu = false, HostStepProfiler* profile = nullptr);

        // Borrow the executor and exclusive buffers until completion. Recursive
        // levels reuse the same ring-sized products; buffers bound CPU workers.
        // A started operation must finish before its resources are reused.
        task<> online(
            macoro::thread_pool& executor, std::span<LheDecryptBuffer> buffers,
            SenderState& state, const SenderOnlineOptions& options,
            SenderOnlineOutput& output, PRNG& prng, Socket& sock);

        // CPU resources are caller-owned and must outlive completion.
        // The existing GPU path does not use the executor or buffers.
        task<> expand(
            macoro::thread_pool& executor, std::span<LheDecryptBuffer> buffers,
            const ShrinkExpandSenderState& state,
            const ShrinkExpandExpandSenderInput& input,
            ShrinkExpandSenderExpandOutput& output,
            Socket& sock);
    };
}
