#include "libOTe/Vole/LogVole/LogVoleEncoding.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <utility>

namespace osuCrypto::LogVole
{
    namespace
    {
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

        template<typename Vec>
        u32 checkedVectorSize(const Vec& values)
        {
            if (values.size() > std::numeric_limits<u32>::max())
            {
                throw std::length_error("LogVole vector is too large to encode");
            }
            return static_cast<u32>(values.size());
        }

        template<typename Vec>
        std::size_t u64VectorByteSize(const Vec& values)
        {
            checkedVectorSize(values);
            return sizeof(u32) + values.size() * sizeof(u64);
        }

        std::size_t ringBatchCoeffCount(const std::vector<RnsPoly>& polys)
        {
            std::size_t total = 0;
            for (const auto& poly : polys)
            {
                if (poly.mCoeffs.size() > std::numeric_limits<u32>::max() - total)
                {
                    throw std::length_error("LogVole ring batch is too large to encode");
                }
                total += poly.mCoeffs.size();
            }
            return total;
        }

        std::size_t ringBatchByteSize(const std::vector<RnsPoly>& polys)
        {
            const auto coeffCount = ringBatchCoeffCount(polys);
            return sizeof(u32) + coeffCount * sizeof(u64);
        }

        std::size_t ringParamsByteSize(const RingParams& params)
        {
            return sizeof(u32) + sizeof(u32) + params.mCoeffModulusBits.size() * sizeof(u16);
        }

        std::size_t paramsByteSize(const ShrinkExpandParams& params)
        {
            return ringParamsByteSize(params.mRing) +
                   5u * sizeof(u32) +
                   3u * sizeof(u8) +
                   sizeof(i64);
        }

        struct BufferWriter
        {
            Buffer mBuffer;
            std::size_t mOffset = 0;

            explicit BufferWriter(std::size_t size)
                : mBuffer(size)
            {
            }

            void writeU8(u8 value)
            {
                mBuffer[mOffset++] = value;
            }

            void writeU16(u16 value)
            {
                mBuffer[mOffset++] = static_cast<u8>(value & 0xFFu);
                mBuffer[mOffset++] = static_cast<u8>((value >> 8u) & 0xFFu);
            }

            void writeU32(u32 value)
            {
                for (u32 i = 0; i < sizeof(u32); ++i)
                {
                    mBuffer[mOffset + i] = static_cast<u8>((value >> (8u * i)) & 0xFFu);
                }
                mOffset += sizeof(u32);
            }

            void writeU64(u64 value)
            {
                for (u32 i = 0; i < sizeof(u64); ++i)
                {
                    mBuffer[mOffset + i] = static_cast<u8>((value >> (8u * i)) & 0xFFu);
                }
                mOffset += sizeof(u64);
            }

            void writeI64(i64 value)
            {
                writeU64(static_cast<u64>(value));
            }

            void writeBytes(std::span<const u8> values)
            {
                std::copy(values.begin(), values.end(), mBuffer.begin() + static_cast<std::ptrdiff_t>(mOffset));
                mOffset += values.size();
            }

            template<typename Vec>
            void writeU64Vector(const Vec& values)
            {
                writeU32(checkedVectorSize(values));
                for (auto value : values)
                {
                    writeU64(static_cast<u64>(value));
                }
            }

            void writeRingBatch(const std::vector<RnsPoly>& polys)
            {
                writeU32(static_cast<u32>(ringBatchCoeffCount(polys)));
                for (const auto& poly : polys)
                {
                    for (auto coeff : poly.mCoeffs)
                    {
                        writeU64(coeff);
                    }
                }
            }

            void writeRingParams(const RingParams& params)
            {
                writeU32(params.mPolyModulusDegree);
                writeU32(checkedVectorSize(params.mCoeffModulusBits));
                for (auto bits : params.mCoeffModulusBits)
                {
                    writeU16(static_cast<u16>(bits));
                }
            }

            void writeParams(const ShrinkExpandParams& params)
            {
                writeRingParams(params.mRing);
                writeU32(params.mPlaintextModulusBits);
                writeU32(params.mAlpha);
                writeU32(params.mMu);
                writeU32(params.mGadgetLogBase);
                writeU32(params.mTau);
                writeU8(static_cast<u8>(params.mTruncateOneGadgetDigit ? 1 : 0));
                writeU8(static_cast<u8>(params.mLeafInputsAreGadget ? 1 : 0));
                writeU8(static_cast<u8>(params.mMode));
                writeI64(params.mNoiseBound);
            }

            Buffer finish()
            {
                if (mOffset != mBuffer.size())
                {
                    throw std::logic_error("LogVole encoding size mismatch");
            }
                return std::move(mBuffer);
            }
        };

        bool readU16Vector(std::span<const u8> payload, u64& offset, AlignedUnVec<u16>& values)
        {
            u32 count = 0;
            if (!readU32(payload, offset, count) ||
                static_cast<u64>(count) > (payload.size() - offset) / sizeof(u16))
            {
                return false;
            }

            values.resize(count);
            for (u32 i = 0; i < count; ++i)
            {
                u16 value = 0;
                if (!readU16(payload, offset, value))
                {
                    return false;
                }
                values[i] = value;
            }
            return true;
        }

        bool readU64Vector(std::span<const u8> payload, u64& offset, AlignedUnVec<u64>& values)
        {
            u32 count = 0;
            if (!readU32(payload, offset, count) ||
                static_cast<u64>(count) > (payload.size() - offset) / sizeof(u64))
            {
                return false;
            }

            values.resize(count);
            for (u32 i = 0; i < count; ++i)
            {
                u64 value = 0;
                if (!readU64(payload, offset, value))
                {
                    return false;
                }
                values[i] = value;
            }
            return true;
        }

        bool readRingParams(std::span<const u8> payload, u64& offset, RingParams& params)
        {
            AlignedUnVec<u16> coeffBits;
            if (!readU32(payload, offset, params.mPolyModulusDegree) ||
                !readU16Vector(payload, offset, coeffBits))
            {
                return false;
            }

            params.mCoeffModulusBits.resize(coeffBits.size());
            u64 idx = 0;
            for (auto bits : coeffBits)
            {
                params.mCoeffModulusBits[idx++] = static_cast<int>(bits);
            }
            return true;
        }

        template<typename Vec>
        Buffer encodeKeyDerive(
            u32 polyModulusDegree,
            u32 coeffModulusCount,
            u32 tau,
            const Vec& coeffs)
        {
            BufferWriter writer(3u * sizeof(u32) + u64VectorByteSize(coeffs));
            writer.writeU32(polyModulusDegree);
            writer.writeU32(coeffModulusCount);
            writer.writeU32(tau);
            writer.writeU64Vector(coeffs);
            return writer.finish();
        }

        bool decodeKeyDerive(
            std::span<const u8> payload,
            u32& polyModulusDegree,
            u32& coeffModulusCount,
            u32& tau,
            AlignedUnVec<u64>& coeffs)
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

        bool readShrinkExpandMode(u8 value, ShrinkExpandMode& mode)
        {
            switch (value)
            {
            case static_cast<u8>(ShrinkExpandMode::FullNoise):
                mode = ShrinkExpandMode::FullNoise;
                return true;
#ifdef LIBOTE_LOGVOLE_ENABLE_INSECURE_NOISELESS
            case static_cast<u8>(ShrinkExpandMode::Deterministic):
                mode = ShrinkExpandMode::Deterministic;
                return true;
#endif
            default:
                return false;
            }
        }

        bool readParams(std::span<const u8> payload, u64& offset, ShrinkExpandParams& params)
        {
            u8 truncate = 0;
            u8 leafInputsAreGadget = 0;
            u8 mode = 0;
            if (!readRingParams(payload, offset, params.mRing) ||
                !readU32(payload, offset, params.mPlaintextModulusBits) ||
                !readU32(payload, offset, params.mAlpha) ||
                !readU32(payload, offset, params.mMu) ||
                !readU32(payload, offset, params.mGadgetLogBase) ||
                !readU32(payload, offset, params.mTau) ||
                !readU8(payload, offset, truncate) ||
                !readU8(payload, offset, leafInputsAreGadget) ||
                !readU8(payload, offset, mode) ||
                !readI64(payload, offset, params.mNoiseBound))
            {
                return false;
            }

            params.mTruncateOneGadgetDigit = truncate != 0;
            params.mLeafInputsAreGadget = leafInputsAreGadget != 0;
            return readShrinkExpandMode(mode, params.mMode);
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
        BufferWriter writer(
            paramsByteSize(message.mParams) +
            2u * sizeof(u32) +
            ringBatchByteSize(message.mCt1.mPolys) +
            4u * sizeof(u32) +
            ringBatchByteSize(message.mLacct.mCt.mPolys));
        writer.writeParams(message.mParams);
        writer.writeU32(message.mCt1.mRows);
        writer.writeU32(message.mCt1.mCols);
        writer.writeRingBatch(message.mCt1.mPolys);
        writer.writeU32(message.mLacct.mWidthPadded);
        writer.writeU32(message.mLacct.mLevels);
        writer.writeU32(message.mLacct.mCt.mRows);
        writer.writeU32(message.mLacct.mCt.mCols);
        writer.writeRingBatch(message.mLacct.mCt.mPolys);
        return writer.finish();
    }

    Buffer encode(const PolyMessage& message)
    {
        BufferWriter writer(2u * sizeof(u32) + u64VectorByteSize(message.mCoeffs));
        writer.writeU32(message.mPolyModulusDegree);
        writer.writeU32(message.mCoeffModulusCount);
        writer.writeU64Vector(message.mCoeffs);
        return writer.finish();
    }

    Buffer encode(const SeedMessage& message)
    {
        BufferWriter writer(message.mSeed.size());
        writer.writeBytes(std::span<const u8>(message.mSeed.data(), message.mSeed.size()));
        return writer.finish();
    }

    Buffer encode(const RootOfflineMessage& message)
    {
        BufferWriter writer(
            ringParamsByteSize(message.mRing) +
            5u * sizeof(u32) +
            2u * sizeof(u32) +
            ringBatchByteSize(message.mCtR.mPolys) +
            4u * sizeof(u32) +
            ringBatchByteSize(message.mLacctLeft.mCt.mPolys) +
            2u * sizeof(u32) +
            ringBatchByteSize(message.mTopCt.mPolys) +
            sizeof(u32) +
            ringBatchByteSize(message.mPublicBStarNtt));
        writer.writeRingParams(message.mRing);
        writer.writeU32(message.mTauHi);
        writer.writeU32(message.mGadgetLogBase);
        writer.writeU32(message.mPlaintextModulusBits);
        writer.writeU32(message.mLeftWidth);
        writer.writeU32(message.mRandomizerWidth);
        writer.writeU32(message.mCtR.mRows);
        writer.writeU32(message.mCtR.mCols);
        writer.writeRingBatch(message.mCtR.mPolys);
        writer.writeU32(message.mLacctLeft.mWidthPadded);
        writer.writeU32(message.mLacctLeft.mLevels);
        writer.writeU32(message.mLacctLeft.mCt.mRows);
        writer.writeU32(message.mLacctLeft.mCt.mCols);
        writer.writeRingBatch(message.mLacctLeft.mCt.mPolys);
        writer.writeU32(message.mTopCt.mRows);
        writer.writeU32(message.mTopCt.mCols);
        writer.writeRingBatch(message.mTopCt.mPolys);
        writer.writeU32(checkedVectorSize(message.mPublicBStarNtt));
        writer.writeRingBatch(message.mPublicBStarNtt);
        return writer.finish();
    }

    Buffer encode(const RootDigestMessage& message)
    {
        BufferWriter writer(u64VectorByteSize(message.mDPrimeCoeffs));
        writer.writeU64Vector(message.mDPrimeCoeffs);
        return writer.finish();
    }

    Buffer encode(const RootResponseMessage& message)
    {
        BufferWriter writer(
            sizeof(u32) +
            message.mSeed.size() +
            u64VectorByteSize(message.mSkPrimeCoeffs));
        writer.writeU32(checkedVectorSize(message.mSeed));
        writer.writeBytes(std::span<const u8>(message.mSeed.data(), message.mSeed.size()));
        writer.writeU64Vector(message.mSkPrimeCoeffs);
        return writer.finish();
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
        AlignedUnVec<u64> ct1Coeffs;
        AlignedUnVec<u64> lacctCoeffs;

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

    bool decode(std::span<const u8> payload, SeedMessage& message)
    {
        if (payload.empty())
        {
            return false;
        }

        assignRange(message.mSeed, payload.begin(), payload.end());
        return true;
    }

    bool decode(std::span<const u8> payload, RootOfflineMessage& message)
    {
        u64 offset = 0;
        AlignedUnVec<u64> ctRCoeffs;
        AlignedUnVec<u64> lacctCoeffs;
        AlignedUnVec<u64> topCtCoeffs;
        AlignedUnVec<u64> publicBStarCoeffs;
        u32 publicBStarCount = 0;

        if (!readRingParams(payload, offset, message.mRing) ||
            !readU32(payload, offset, message.mTauHi) ||
            !readU32(payload, offset, message.mGadgetLogBase) ||
            !readU32(payload, offset, message.mPlaintextModulusBits) ||
            !readU32(payload, offset, message.mLeftWidth) ||
            !readU32(payload, offset, message.mRandomizerWidth) ||
            !readU32(payload, offset, message.mCtR.mRows) ||
            !readU32(payload, offset, message.mCtR.mCols) ||
            !readU64Vector(payload, offset, ctRCoeffs) ||
            !readU32(payload, offset, message.mLacctLeft.mWidthPadded) ||
            !readU32(payload, offset, message.mLacctLeft.mLevels) ||
            !readU32(payload, offset, message.mLacctLeft.mCt.mRows) ||
            !readU32(payload, offset, message.mLacctLeft.mCt.mCols) ||
            !readU64Vector(payload, offset, lacctCoeffs) ||
            !readU32(payload, offset, message.mTopCt.mRows) ||
            !readU32(payload, offset, message.mTopCt.mCols) ||
            !readU64Vector(payload, offset, topCtCoeffs) ||
            !readU32(payload, offset, publicBStarCount) ||
            !readU64Vector(payload, offset, publicBStarCoeffs) ||
            offset != payload.size())
        {
            return false;
        }

        const u32 coeffCount = static_cast<u32>(message.mRing.mCoeffModulusBits.size());
        if (!unpackRingTensor(
                message.mCtR.mRows,
                message.mCtR.mCols,
                message.mRing.mPolyModulusDegree,
                coeffCount,
                ctRCoeffs,
                message.mCtR) ||
            !unpackRingTensor(
                message.mLacctLeft.mCt.mRows,
                message.mLacctLeft.mCt.mCols,
                message.mRing.mPolyModulusDegree,
                coeffCount,
                lacctCoeffs,
                message.mLacctLeft.mCt) ||
            !unpackRingTensor(
                message.mTopCt.mRows,
                message.mTopCt.mCols,
                message.mRing.mPolyModulusDegree,
                coeffCount,
                topCtCoeffs,
                message.mTopCt) ||
            !unpackRingBatch(
                publicBStarCount,
                message.mRing.mPolyModulusDegree,
                coeffCount,
                publicBStarCoeffs,
                message.mPublicBStarNtt))
        {
            return false;
        }

        return true;
    }

    bool decode(std::span<const u8> payload, RootDigestMessage& message)
    {
        u64 offset = 0;
        if (!readU64Vector(payload, offset, message.mDPrimeCoeffs) ||
            offset != payload.size() ||
            message.mDPrimeCoeffs.empty())
        {
            return false;
        }
        return true;
    }

    bool decode(std::span<const u8> payload, RootResponseMessage& message)
    {
        u64 offset = 0;
        u32 seedSize = 0;
        if (!readU32(payload, offset, seedSize) ||
            offset + seedSize > payload.size())
        {
            return false;
        }

        assignRange(
            message.mSeed,
            payload.begin() + static_cast<std::ptrdiff_t>(offset),
            payload.begin() + static_cast<std::ptrdiff_t>(offset + seedSize));
        offset += seedSize;

        if (!readU64Vector(payload, offset, message.mSkPrimeCoeffs) ||
            offset != payload.size() ||
            message.mSeed.empty() ||
            message.mSkPrimeCoeffs.empty())
        {
            return false;
        }
        return true;
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
