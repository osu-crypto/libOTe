#include "libOTe/Vole/LogVole/LogVoleEncoding.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace osuCrypto::LogVole
{
    namespace
    {
        void appendU8(Buffer& buffer, u8 value)
        {
            buffer.push_back(value);
        }

        void appendU16(Buffer& buffer, u16 value)
        {
            buffer.push_back(static_cast<u8>(value & 0xFFu));
            buffer.push_back(static_cast<u8>((value >> 8u) & 0xFFu));
        }

        void appendU32(Buffer& buffer, u32 value)
        {
            for (u64 i = 0; i < sizeof(u32); ++i)
            {
                buffer.push_back(static_cast<u8>((value >> (8u * i)) & 0xFFu));
            }
        }

        void appendU64(Buffer& buffer, u64 value)
        {
            for (u64 i = 0; i < sizeof(u64); ++i)
            {
                buffer.push_back(static_cast<u8>((value >> (8u * i)) & 0xFFu));
            }
        }

        bool readU8(std::span<const u8> payload, u64& offset, u8& value)
        {
            if (offset + sizeof(u8) > payload.size())
                return false;

            value = payload[offset];
            offset += sizeof(u8);
            return true;
        }

        bool readU16(std::span<const u8> payload, u64& offset, u16& value)
        {
            if (offset + sizeof(u16) > payload.size())
                return false;

            value = static_cast<u16>(payload[offset]) |
                static_cast<u16>(static_cast<u16>(payload[offset + 1]) << 8u);
            offset += sizeof(u16);
            return true;
        }

        bool readU32(std::span<const u8> payload, u64& offset, u32& value)
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

        bool readU64(std::span<const u8> payload, u64& offset, u64& value)
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
        u32 checkedVectorSize(const std::vector<T>& values)
        {
            if (values.size() > std::numeric_limits<u32>::max())
                throw std::length_error("LogVole vector is too large to encode");

            return static_cast<u32>(values.size());
        }

        void appendU16Vector(Buffer& buffer, const std::vector<u16>& values)
        {
            appendU32(buffer, checkedVectorSize(values));
            for (auto value : values)
            {
                appendU16(buffer, value);
            }
        }

        void appendU64Vector(Buffer& buffer, const std::vector<u64>& values)
        {
            appendU32(buffer, checkedVectorSize(values));
            for (auto value : values)
            {
                appendU64(buffer, value);
            }
        }

        bool readU16Vector(std::span<const u8> payload, u64& offset, std::vector<u16>& values)
        {
            u32 count = 0;
            if (!readU32(payload, offset, count))
                return false;

            if (static_cast<u64>(count) > (payload.size() - offset) / sizeof(u16))
                return false;

            values.clear();
            values.reserve(count);
            for (u32 i = 0; i < count; ++i)
            {
                u16 value = 0;
                if (!readU16(payload, offset, value))
                    return false;
                values.push_back(value);
            }

            return true;
        }

        bool readU64Vector(std::span<const u8> payload, u64& offset, std::vector<u64>& values)
        {
            u32 count = 0;
            if (!readU32(payload, offset, count))
                return false;

            if (static_cast<u64>(count) > (payload.size() - offset) / sizeof(u64))
                return false;

            values.clear();
            values.reserve(count);
            for (u32 i = 0; i < count; ++i)
            {
                u64 value = 0;
                if (!readU64(payload, offset, value))
                    return false;
                values.push_back(value);
            }

            return true;
        }

        Buffer encodeKeyDerive(
            u32 polyModulusDegree,
            u32 coeffModulusCount,
            u32 tau,
            const std::vector<u64>& coeffs)
        {
            Buffer out;
            out.reserve(4 * sizeof(u32) + coeffs.size() * sizeof(u64));

            appendU32(out, polyModulusDegree);
            appendU32(out, coeffModulusCount);
            appendU32(out, tau);
            appendU64Vector(out, coeffs);
            return out;
        }

        bool decodeKeyDerive(
            std::span<const u8> payload,
            u32& polyModulusDegree,
            u32& coeffModulusCount,
            u32& tau,
            std::vector<u64>& coeffs)
        {
            u64 offset = 0;
            if (!readU32(payload, offset, polyModulusDegree) ||
                !readU32(payload, offset, coeffModulusCount) ||
                !readU32(payload, offset, tau) ||
                !readU64Vector(payload, offset, coeffs))
            {
                return false;
            }

            return offset == payload.size();
        }
    }

    Buffer encode(const KeyDeriveRequest& message)
    {
        return encodeKeyDerive(
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mDCoeffs);
    }

    Buffer encode(const KeyDeriveResponse& message)
    {
        return encodeKeyDerive(
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mMNttCoeffs);
    }

    Buffer encode(const ShrinkExpandOfflineMessage& message)
    {
        Buffer out;

        appendU32(out, message.mPolyModulusDegree);
        appendU16Vector(out, message.mCoeffModulusBits);

        appendU32(out, message.mPlaintextModulusBits);
        appendU32(out, message.mAlpha);
        appendU32(out, message.mMu);
        appendU32(out, message.mTau);
        appendU32(out, message.mGadgetLogBase);
        appendU8(out, message.mMode);
        appendU64(out, message.mMetadataFingerprint);

        appendU32(out, message.mCt1Rows);
        appendU32(out, message.mCt1Cols);
        appendU64Vector(out, message.mCt1Coeffs);

        appendU32(out, message.mLacctWidthPadded);
        appendU32(out, message.mLacctLevels);
        appendU32(out, message.mLacctCtRows);
        appendU32(out, message.mLacctCtCols);
        appendU64Vector(out, message.mLacctCtCoeffs);

        return out;
    }

    Buffer encode(const PolyMessage& message)
    {
        Buffer out;
        out.reserve(3 * sizeof(u32) + message.mCoeffs.size() * sizeof(u64));

        appendU32(out, message.mPolyModulusDegree);
        appendU32(out, message.mCoeffModulusCount);
        appendU64Vector(out, message.mCoeffs);
        return out;
    }

    bool decode(std::span<const u8> payload, KeyDeriveRequest& message)
    {
        return decodeKeyDerive(
            payload,
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mDCoeffs);
    }

    bool decode(std::span<const u8> payload, KeyDeriveResponse& message)
    {
        return decodeKeyDerive(
            payload,
            message.mPolyModulusDegree,
            message.mCoeffModulusCount,
            message.mTau,
            message.mMNttCoeffs);
    }

    bool decode(std::span<const u8> payload, ShrinkExpandOfflineMessage& message)
    {
        u64 offset = 0;

        if (!readU32(payload, offset, message.mPolyModulusDegree) ||
            !readU16Vector(payload, offset, message.mCoeffModulusBits) ||
            !readU32(payload, offset, message.mPlaintextModulusBits) ||
            !readU32(payload, offset, message.mAlpha) ||
            !readU32(payload, offset, message.mMu) ||
            !readU32(payload, offset, message.mTau) ||
            !readU32(payload, offset, message.mGadgetLogBase) ||
            !readU8(payload, offset, message.mMode) ||
            !readU64(payload, offset, message.mMetadataFingerprint) ||
            !readU32(payload, offset, message.mCt1Rows) ||
            !readU32(payload, offset, message.mCt1Cols) ||
            !readU64Vector(payload, offset, message.mCt1Coeffs) ||
            !readU32(payload, offset, message.mLacctWidthPadded) ||
            !readU32(payload, offset, message.mLacctLevels) ||
            !readU32(payload, offset, message.mLacctCtRows) ||
            !readU32(payload, offset, message.mLacctCtCols) ||
            !readU64Vector(payload, offset, message.mLacctCtCoeffs))
        {
            return false;
        }

        return offset == payload.size();
    }

    bool decode(std::span<const u8> payload, PolyMessage& message)
    {
        u64 offset = 0;
        if (!readU32(payload, offset, message.mPolyModulusDegree) ||
            !readU32(payload, offset, message.mCoeffModulusCount) ||
            !readU64Vector(payload, offset, message.mCoeffs))
        {
            return false;
        }

        return offset == payload.size();
    }
}
