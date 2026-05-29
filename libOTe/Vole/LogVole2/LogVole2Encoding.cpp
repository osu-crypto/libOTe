#include "libOTe/Vole/LogVole2/LogVole2Encoding.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace osuCrypto::LogVole2
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
            for (u32 i = 0; i < sizeof(u32); ++i)
            {
                buffer.push_back(static_cast<u8>((value >> (8u * i)) & 0xFFu));
            }
        }

        void appendU64(Buffer& buffer, u64 value)
        {
            for (u32 i = 0; i < sizeof(u64); ++i)
            {
                buffer.push_back(static_cast<u8>((value >> (8u * i)) & 0xFFu));
            }
        }

        void appendI64(Buffer& buffer, i64 value)
        {
            appendU64(buffer, static_cast<u64>(value));
        }

        bool readU8(std::span<const u8> payload, u64& offset, u8& value)
        {
            if (offset + sizeof(u8) > payload.size())
            {
                return false;
            }

            value = payload[offset];
            offset += sizeof(u8);
            return true;
        }

        bool readU16(std::span<const u8> payload, u64& offset, u16& value)
        {
            if (offset + sizeof(u16) > payload.size())
            {
                return false;
            }

            value = static_cast<u16>(payload[offset]) |
                    static_cast<u16>(static_cast<u16>(payload[offset + 1]) << 8u);
            offset += sizeof(u16);
            return true;
        }

        bool readU32(std::span<const u8> payload, u64& offset, u32& value)
        {
            if (offset + sizeof(u32) > payload.size())
            {
                return false;
            }

            value = 0;
            for (u32 i = 0; i < sizeof(u32); ++i)
            {
                value |= static_cast<u32>(payload[offset + i]) << (8u * i);
            }
            offset += sizeof(u32);
            return true;
        }

        bool readU64(std::span<const u8> payload, u64& offset, u64& value)
        {
            if (offset + sizeof(u64) > payload.size())
            {
                return false;
            }

            value = 0;
            for (u32 i = 0; i < sizeof(u64); ++i)
            {
                value |= static_cast<u64>(payload[offset + i]) << (8u * i);
            }
            offset += sizeof(u64);
            return true;
        }

        bool readI64(std::span<const u8> payload, u64& offset, i64& value)
        {
            u64 unsignedValue = 0;
            if (!readU64(payload, offset, unsignedValue))
            {
                return false;
            }
            value = static_cast<i64>(unsignedValue);
            return true;
        }

        template<typename T>
        u32 checkedVectorSize(const std::vector<T>& values)
        {
            if (values.size() > std::numeric_limits<u32>::max())
            {
                throw std::length_error("LogVole2 vector is too large to encode");
            }
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
            if (!readU32(payload, offset, count) ||
                static_cast<u64>(count) > (payload.size() - offset) / sizeof(u16))
            {
                return false;
            }

            values.clear();
            values.reserve(count);
            for (u32 i = 0; i < count; ++i)
            {
                u16 value = 0;
                if (!readU16(payload, offset, value))
                {
                    return false;
                }
                values.push_back(value);
            }
            return true;
        }

        bool readU64Vector(std::span<const u8> payload, u64& offset, std::vector<u64>& values)
        {
            u32 count = 0;
            if (!readU32(payload, offset, count) ||
                static_cast<u64>(count) > (payload.size() - offset) / sizeof(u64))
            {
                return false;
            }

            values.clear();
            values.reserve(count);
            for (u32 i = 0; i < count; ++i)
            {
                u64 value = 0;
                if (!readU64(payload, offset, value))
                {
                    return false;
                }
                values.push_back(value);
            }
            return true;
        }

        void appendParams(Buffer& out, const ShrinkExpandParams& params)
        {
            appendU32(out, params.mRing.mPolyModulusDegree);

            std::vector<u16> coeffBits;
            coeffBits.reserve(params.mRing.mCoeffModulusBits.size());
            for (auto bits : params.mRing.mCoeffModulusBits)
            {
                coeffBits.push_back(static_cast<u16>(bits));
            }
            appendU16Vector(out, coeffBits);

            appendU32(out, params.mPlaintextModulusBits);
            appendU32(out, params.mAlpha);
            appendU32(out, params.mMu);
            appendU32(out, params.mGadgetLogBase);
            appendU32(out, params.mTau);
            appendU8(out, static_cast<u8>(params.mTruncateOneGadgetDigit ? 1 : 0));
            appendU8(out, static_cast<u8>(params.mLeafInputsAreGadget ? 1 : 0));
            appendU8(out, static_cast<u8>(params.mMode));
            appendU64(out, params.mSamplingSeeds.mNoiseRoot);
            appendU64(out, params.mSamplingSeeds.mCt2Root);
            appendI64(out, params.mNoiseBound);
        }

        bool readParams(std::span<const u8> payload, u64& offset, ShrinkExpandParams& params)
        {
            std::vector<u16> coeffBits;
            u8 truncate = 0;
            u8 leafInputsAreGadget = 0;
            u8 mode = 0;
            if (!readU32(payload, offset, params.mRing.mPolyModulusDegree) ||
                !readU16Vector(payload, offset, coeffBits) ||
                !readU32(payload, offset, params.mPlaintextModulusBits) ||
                !readU32(payload, offset, params.mAlpha) ||
                !readU32(payload, offset, params.mMu) ||
                !readU32(payload, offset, params.mGadgetLogBase) ||
                !readU32(payload, offset, params.mTau) ||
                !readU8(payload, offset, truncate) ||
                !readU8(payload, offset, leafInputsAreGadget) ||
                !readU8(payload, offset, mode) ||
                !readU64(payload, offset, params.mSamplingSeeds.mNoiseRoot) ||
                !readU64(payload, offset, params.mSamplingSeeds.mCt2Root) ||
                !readI64(payload, offset, params.mNoiseBound))
            {
                return false;
            }

            params.mRing.mCoeffModulusBits.clear();
            params.mRing.mCoeffModulusBits.reserve(coeffBits.size());
            for (auto bits : coeffBits)
            {
                params.mRing.mCoeffModulusBits.push_back(static_cast<int>(bits));
            }
            params.mTruncateOneGadgetDigit = truncate != 0;
            params.mLeafInputsAreGadget = leafInputsAreGadget != 0;
            params.mMode = static_cast<ShrinkExpandMode>(mode);
            return true;
        }
    }

    Buffer encode(const ShrinkExpandOfflineMessage& message)
    {
        Buffer out;
        appendParams(out, message.mParams);

        appendU32(out, message.mCt1.mRows);
        appendU32(out, message.mCt1.mCols);
        appendU64Vector(out, packRingTensor(message.mCt1));

        appendU32(out, message.mLacct.mWidthPadded);
        appendU32(out, message.mLacct.mLevels);
        appendU32(out, message.mLacct.mCt.mRows);
        appendU32(out, message.mLacct.mCt.mCols);
        appendU64Vector(out, packRingTensor(message.mLacct.mCt));
        return out;
    }

    Buffer encode(const PolyMessage& message)
    {
        Buffer out;
        appendU32(out, message.mPolyModulusDegree);
        appendU32(out, message.mCoeffModulusCount);
        appendU64Vector(out, message.mCoeffs);
        return out;
    }

    bool decode(std::span<const u8> payload, ShrinkExpandOfflineMessage& message)
    {
        u64 offset = 0;
        std::vector<u64> ct1Coeffs;
        std::vector<u64> lacctCoeffs;

        if (!readParams(payload, offset, message.mParams) ||
            !readU32(payload, offset, message.mCt1.mRows) ||
            !readU32(payload, offset, message.mCt1.mCols) ||
            !readU64Vector(payload, offset, ct1Coeffs) ||
            !readU32(payload, offset, message.mLacct.mWidthPadded) ||
            !readU32(payload, offset, message.mLacct.mLevels) ||
            !readU32(payload, offset, message.mLacct.mCt.mRows) ||
            !readU32(payload, offset, message.mLacct.mCt.mCols) ||
            !readU64Vector(payload, offset, lacctCoeffs) ||
            offset != payload.size())
        {
            return false;
        }

        const u32 coeffCount = static_cast<u32>(message.mParams.mRing.mCoeffModulusBits.size());
        if (!unpackRingTensor(
                message.mCt1.mRows,
                message.mCt1.mCols,
                message.mParams.mRing.mPolyModulusDegree,
                coeffCount,
                ct1Coeffs,
                message.mCt1) ||
            !unpackRingTensor(
                message.mLacct.mCt.mRows,
                message.mLacct.mCt.mCols,
                message.mParams.mRing.mPolyModulusDegree,
                coeffCount,
                lacctCoeffs,
                message.mLacct.mCt))
        {
            return false;
        }

        return true;
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

    PolyMessage makePolyMessage(const RingParams& params, const RnsPoly& poly)
    {
        PolyMessage message{};
        message.mPolyModulusDegree = params.mPolyModulusDegree;
        message.mCoeffModulusCount = static_cast<u32>(params.mCoeffModulusBits.size());
        message.mCoeffs = poly.mCoeffs;
        return message;
    }

    bool readPolyMessage(const RingParams& params, PolyMessage& message, RnsPoly& out)
    {
        if (message.mPolyModulusDegree != params.mPolyModulusDegree ||
            message.mCoeffModulusCount != params.mCoeffModulusBits.size() ||
            message.mCoeffs.size() != static_cast<std::size_t>(ringPolyCoeffCount(params)))
        {
            return false;
        }

        out.mCoeffs = std::move(message.mCoeffs);
        return true;
    }
}
