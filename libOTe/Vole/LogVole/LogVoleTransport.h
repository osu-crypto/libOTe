#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole/LogVoleCore.h"
#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"

#include <array>
#include <chrono>
#include <limits>
#include <stdexcept>
#include <utility>

namespace osuCrypto::LogVole::detail
{
    // Shared framing and recursion helpers for the two protocol roles.
    inline constexpr u64 kFrameHeaderSize = sizeof(u64);

    inline void writeU64(std::array<u8, kFrameHeaderSize>& out, u64 value)
    {
        for (u64 i = 0; i < kFrameHeaderSize; ++i)
        {
            out[i] = static_cast<u8>((value >> (8u * i)) & 0xFFu);
        }
    }

    inline u64 readU64(const std::array<u8, kFrameHeaderSize>& in)
    {
        u64 value = 0;
        for (u64 i = 0; i < kFrameHeaderSize; ++i)
        {
            value |= static_cast<u64>(in[i]) << (8u * i);
        }
        return value;
    }

    inline task<> sendFrame(Socket& sock, const Buffer& payload)
    {
        std::array<u8, kFrameHeaderSize> header{};
        writeU64(header, static_cast<u64>(payload.size()));

        co_await sock.send(coproto::copy(header));
        if (!payload.empty())
        {
            co_await sock.send(coproto::copy(payload));
        }
    }

    // Retain the single-use payload in the coroutine frame until coproto takes it.
    inline task<> sendOwnedFrame(Socket& sock, Buffer payload)
    {
        std::array<u8, kFrameHeaderSize> header{};
        writeU64(header, static_cast<u64>(payload.size()));

        co_await sock.send(coproto::copy(header));
        if (!payload.empty())
        {
            co_await sock.send(std::move(payload));
        }
    }

    template<ProtocolCacheRole Role>
    inline task<Buffer> recvFrame(Socket& sock, u64 maxPayloadSize)
    {
        std::array<u8, kFrameHeaderSize> header{};
        const auto waitStart = std::chrono::steady_clock::now();
        co_await sock.recv(header);
        (Role == ProtocolCacheRole::Sender ? globalTimingStats.mSenderWaitUs
            : globalTimingStats.mReceiverWaitUs).fetch_add(
            static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(
                                 std::chrono::steady_clock::now() - waitStart)
                                 .count()),
            std::memory_order_relaxed);

        const auto size = readU64(header);
        if (size > maxPayloadSize ||
            size > static_cast<u64>(std::numeric_limits<std::size_t>::max()))
        {
            throw std::length_error("LogVole frame is too large");
        }

        Buffer payload(static_cast<std::size_t>(size));
        adviseGpuSetupWireBuffer(payload);
        if (!payload.empty())
        {
            if constexpr (Role == ProtocolCacheRole::Receiver)
            {
                HostStep phase("transport receiver: receive frame payload");
                co_await sock.recv(payload);
            }
            else
            {
                co_await sock.recv(payload);
            }
        }

        co_return payload;
    }

    inline u64 frameBytes(const Buffer& payload)
    {
        return kFrameHeaderSize + static_cast<u64>(payload.size());
    }

    inline u64 requirePayloadSize(bool valid, u64 size)
    {
        if (!valid)
            throw std::length_error("LogVole could not derive a frame size bound");
        return size;
    }

    inline bool computeTauHi(const Params& params, u32& out)
    {
        if (params.mShrinkExpand.mTau < 2)
        {
            return false;
        }
        out = params.mShrinkExpand.mTau - 1;
        return true;
    }

    inline bool recursiveMode(const Params& params, RecursiveMode& out)
    {
        u32 tauHi = 0;
        if (!computeTauHi(params, tauHi))
        {
            return false;
        }

        const u32 rho = static_cast<u32>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
        out = evalRecursiveMode(params.mW, params.mShrinkExpand.mAlpha, tauHi, rho);
        return true;
    }

    inline bool childParams(const Params& params, Params& out)
    {
        u32 tauHi = 0;
        if (!computeTauHi(params, tauHi))
        {
            return false;
        }

        const u32 rho = static_cast<u32>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
        const u32 muHi = params.mShrinkExpand.mAlpha * tauHi * rho;
        if (rho == 0 || muHi == 0)
        {
            return false;
        }

        const u32 wDoublePrime = (params.mW + muHi - 1u) / muHi;
        if (wDoublePrime == 0)
        {
            return false;
        }

        out = params;
        out.mW = wDoublePrime * tauHi * rho;
        out.mGamma = tauHi;
        return true;
    }
}
