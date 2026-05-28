#include "libOTe/Vole/LogVole/LogVoleEncoding.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace osuCrypto
{
    namespace
    {
        void logVoleAppendU8(LogVoleBuffer& buffer, u8 value)
        {
            buffer.push_back(value);
        }

        void logVoleAppendU16(LogVoleBuffer& buffer, u16 value)
        {
            buffer.push_back(static_cast<u8>(value & 0xFFu));
            buffer.push_back(static_cast<u8>((value >> 8u) & 0xFFu));
        }

        void logVoleAppendU32(LogVoleBuffer& buffer, u32 value)
        {
            for (u64 i = 0; i < sizeof(u32); ++i)
            {
                buffer.push_back(static_cast<u8>((value >> (8u * i)) & 0xFFu));
            }
        }

        void logVoleAppendU64(LogVoleBuffer& buffer, u64 value)
        {
            for (u64 i = 0; i < sizeof(u64); ++i)
            {
                buffer.push_back(static_cast<u8>((value >> (8u * i)) & 0xFFu));
            }
        }

        bool logVoleReadU8(std::span<const u8> payload, u64& offset, u8& value)
        {
            if (offset + sizeof(u8) > payload.size())
                return false;

            value = payload[offset];
            offset += sizeof(u8);
            return true;
        }

        bool logVoleReadU16(std::span<const u8> payload, u64& offset, u16& value)
        {
            if (offset + sizeof(u16) > payload.size())
                return false;

            value = static_cast<u16>(payload[offset]) |
                static_cast<u16>(static_cast<u16>(payload[offset + 1]) << 8u);
            offset += sizeof(u16);
            return true;
        }

        bool logVoleReadU32(std::span<const u8> payload, u64& offset, u32& value)
        {
            if (offset + sizeof(u32) > payload.size())
                return false;

            value = 0;
            for (u64 i = 0; i < sizeof(u32); ++i)
            {
                value |= static_cast<u32>(payload[offset + i]) << (8u * i);
            }
            offset += sizeof(u32);
            return true;
        }

        bool logVoleReadU64(std::span<const u8> payload, u64& offset, u64& value)
        {
            if (offset + sizeof(u64) > payload.size())
                return false;

            value = 0;
            for (u64 i = 0; i < sizeof(u64); ++i)
            {
                value |= static_cast<u64>(payload[offset + i]) << (8u * i);
            }
            offset += sizeof(u64);
            return true;
        }

        template<typename T>
        u32 logVoleCheckedVectorSize(const std::vector<T>& values)
        {
            if (values.size() > std::numeric_limits<u32>::max())
                throw std::length_error("LogVole vector is too large to encode");

            return static_cast<u32>(values.size());
        }

        void logVoleAppendU16Vector(LogVoleBuffer& buffer, const std::vector<u16>& values)
        {
            logVoleAppendU32(buffer, logVoleCheckedVectorSize(values));
            for (auto value : values)
            {
                logVoleAppendU16(buffer, value);
            }
        }

        void logVoleAppendU64Vector(LogVoleBuffer& buffer, const std::vector<u64>& values)
        {
            logVoleAppendU32(buffer, logVoleCheckedVectorSize(values));
            for (auto value : values)
            {
                logVoleAppendU64(buffer, value);
            }
        }

        bool logVoleReadU16Vector(std::span<const u8> payload, u64& offset, std::vector<u16>& values)
        {
            u32 count = 0;
            if (!logVoleReadU32(payload, offset, count))
                return false;

            if (static_cast<u64>(count) > (payload.size() - offset) / sizeof(u16))
                return false;

            values.clear();
            values.reserve(count);
            for (u32 i = 0; i < count; ++i)
            {
                u16 value = 0;
                if (!logVoleReadU16(payload, offset, value))
                    return false;
                values.push_back(value);
            }

            return true;
        }

        bool logVoleReadU64Vector(std::span<const u8> payload, u64& offset, std::vector<u64>& values)
        {
            u32 count = 0;
            if (!logVoleReadU32(payload, offset, count))
                return false;

            if (static_cast<u64>(count) > (payload.size() - offset) / sizeof(u64))
                return false;

            values.clear();
            values.reserve(count);
            for (u32 i = 0; i < count; ++i)
            {
                u64 value = 0;
                if (!logVoleReadU64(payload, offset, value))
                    return false;
                values.push_back(value);
            }

            return true;
        }

        LogVoleBuffer logVoleEncodeKeyDerive(
            u32 polyModulusDegree,
            u32 coeffModulusCount,
            u32 tau,
            const std::vector<u64>& coeffs)
        {
            LogVoleBuffer out;
            out.reserve(4 * sizeof(u32) + coeffs.size() * sizeof(u64));

            logVoleAppendU32(out, polyModulusDegree);
            logVoleAppendU32(out, coeffModulusCount);
            logVoleAppendU32(out, tau);
            logVoleAppendU64Vector(out, coeffs);
            return out;
        }

        bool logVoleDecodeKeyDerive(
            std::span<const u8> payload,
            u32& polyModulusDegree,
            u32& coeffModulusCount,
            u32& tau,
            std::vector<u64>& coeffs)
        {
            u64 offset = 0;
            if (!logVoleReadU32(payload, offset, polyModulusDegree) ||
                !logVoleReadU32(payload, offset, coeffModulusCount) ||
                !logVoleReadU32(payload, offset, tau) ||
                !logVoleReadU64Vector(payload, offset, coeffs))
            {
                return false;
            }

            return offset == payload.size();
        }
    }

    LogVoleBuffer logVoleEncode(const LogVoleKeyDeriveRequest& message)
    {
        return logVoleEncodeKeyDerive(
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mDCoeffs);
    }

    LogVoleBuffer logVoleEncode(const LogVoleKeyDeriveResponse& message)
    {
        return logVoleEncodeKeyDerive(
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mMNttCoeffs);
    }

    LogVoleBuffer logVoleEncode(const LogVoleShrinkExpandOfflineMessage& message)
    {
        LogVoleBuffer out;

        logVoleAppendU32(out, message.mPolyModulusDegree);
        logVoleAppendU16Vector(out, message.mCoeffModulusBits);

        logVoleAppendU32(out, message.mPlaintextModulusBits);
        logVoleAppendU32(out, message.mAlpha);
        logVoleAppendU32(out, message.mMu);
        logVoleAppendU32(out, message.mTau);
        logVoleAppendU32(out, message.mGadgetLogBase);
        logVoleAppendU8(out, message.mMode);
        logVoleAppendU64(out, message.mMetadataFingerprint);

        logVoleAppendU32(out, message.mCt1Rows);
        logVoleAppendU32(out, message.mCt1Cols);
        logVoleAppendU64Vector(out, message.mCt1Coeffs);

        logVoleAppendU32(out, message.mLacctWidthPadded);
        logVoleAppendU32(out, message.mLacctLevels);
        logVoleAppendU32(out, message.mLacctCtRows);
        logVoleAppendU32(out, message.mLacctCtCols);
        logVoleAppendU64Vector(out, message.mLacctCtCoeffs);

        return out;
    }

    bool logVoleDecode(std::span<const u8> payload, LogVoleKeyDeriveRequest& message)
    {
        return logVoleDecodeKeyDerive(
            payload,
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mDCoeffs);
    }

    bool logVoleDecode(std::span<const u8> payload, LogVoleKeyDeriveResponse& message)
    {
        return logVoleDecodeKeyDerive(
            payload,
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mMNttCoeffs);
    }

    bool logVoleDecode(std::span<const u8> payload, LogVoleShrinkExpandOfflineMessage& message)
    {
        u64 offset = 0;

        if (!logVoleReadU32(payload, offset, message.mPolyModulusDegree) ||
            !logVoleReadU16Vector(payload, offset, message.mCoeffModulusBits) ||
            !logVoleReadU32(payload, offset, message.mPlaintextModulusBits) ||
            !logVoleReadU32(payload, offset, message.mAlpha) ||
            !logVoleReadU32(payload, offset, message.mMu) ||
            !logVoleReadU32(payload, offset, message.mTau) ||
            !logVoleReadU32(payload, offset, message.mGadgetLogBase) ||
            !logVoleReadU8(payload, offset, message.mMode) ||
            !logVoleReadU64(payload, offset, message.mMetadataFingerprint) ||
            !logVoleReadU32(payload, offset, message.mCt1Rows) ||
            !logVoleReadU32(payload, offset, message.mCt1Cols) ||
            !logVoleReadU64Vector(payload, offset, message.mCt1Coeffs) ||
            !logVoleReadU32(payload, offset, message.mLacctWidthPadded) ||
            !logVoleReadU32(payload, offset, message.mLacctLevels) ||
            !logVoleReadU32(payload, offset, message.mLacctCtRows) ||
            !logVoleReadU32(payload, offset, message.mLacctCtCols) ||
            !logVoleReadU64Vector(payload, offset, message.mLacctCtCoeffs))
        {
            return false;
        }

        return offset == payload.size();
    }
}
