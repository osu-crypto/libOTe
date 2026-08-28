#pragma once

#include "libOTe/config.h"
#if defined(ENABLE_REGULAR_DPF) && defined(ENABLE_CIRCUITS)

#include "libOTe/Triple/AnyField/AnyFieldCtx.h"
#include "libOTe/Dpf/RegularDpf.h"
#include "libOTe/Tools/Gmw/Gmw.h"
#include "libOTe/Vole/Noisy/NoisyVoleReceiver.h"
#include "libOTe/Vole/Noisy/NoisyVoleSender.h"
#include "cryptoTools/Circuit/BetaLibrary.h"
#include "cryptoTools/Common/Timer.h"
#include "coproto/Socket/Socket.h"
#include <algorithm>
#include <array>
#include <exception>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace osuCrypto
{
	// Semi-honest two-party PCG for OLE over a base field, following
	// Construction 1 of "Efficient Pseudorandom Correlation Generators for Any
	// Finite Field". Field-specific operations are supplied by a compile-time
	// context. The first context is AnyFieldF9Ctx, which generates two N-element
	// batches of F3 OLEs from QA-SD over F9. For each output index, the parties'
	// shares satisfy x_0 * x_1 = z_0 + z_1.
	//
	// This initial ordinary-DPF backend packs each transform coordinate into a
	// fixed-width binary field. It therefore requires a power-of-two coordinate
	// group. Base OTs and binary OLEs are one-shot and must be freshly installed
	// before every setup.
	template<AnyFieldContext Context>
	class AnyFieldOle : public TimerAdapter
	{
	public:
		using Ctx = Context;
		using Base = typename Ctx::Base;
		using Ext = typename Ctx::Ext;
		using DpfCoeffCtx = typename Ctx::DpfCoeffCtx;

		static constexpr u64 GroupCount = 4 * Ctx::extensionDegree;
		static_assert(Ctx::extensionDegree > 0,
			"AnyFieldOle requires a positive extension degree.");
		static_assert(Ctx::coordinateBits > 0 && Ctx::coordinateBits < 64,
			"AnyFieldOle requires a coordinate width between one and 63 bits.");
		static_assert(Ctx::coordinateSize == (u64{ 1 } << Ctx::coordinateBits),
			"The ordinary-DPF AnyFieldOle backend requires a power-of-two coordinate group.");

		struct BaseCorCount
		{
			u64 mSendOtCount = 0;
			u64 mRecvOtCount = 0;
			u64 mOleCount = 0;
		};

		AnyFieldOle() = default;
		AnyFieldOle(const AnyFieldOle&) = delete;
		AnyFieldOle& operator=(const AnyFieldOle&) = delete;
		AnyFieldOle(AnyFieldOle&& source) noexcept
		{
			*this = std::move(source);
		}

		AnyFieldOle& operator=(AnyFieldOle&& source) noexcept
		{
			if (this != &source)
			{
				clear();
				mTimer = std::exchange(source.mTimer, nullptr);
				mCtx = std::move(source.mCtx);
				mPartyIdx = std::exchange(source.mPartyIdx, 0);
				mDimensions = std::exchange(source.mDimensions, 0);
				mWeight = std::exchange(source.mWeight, 0);
				mN = std::exchange(source.mN, 0);
				mPublicSeed = std::exchange(source.mPublicSeed, block{});
				mPublicA = std::move(source.mPublicA);
				mPositionGmw = std::move(source.mPositionGmw);
				mCoordinateAdder = std::move(source.mCoordinateAdder);
				mSendOts = std::move(source.mSendOts);
				mRecvOts = std::move(source.mRecvOts);
				mRecvChoices = std::move(source.mRecvChoices);
				mBaseCorsAvailable = std::exchange(source.mBaseCorsAvailable, false);
				mSparsePositions = std::move(source.mSparsePositions);
				mSparseCoefficients = std::move(source.mSparseCoefficients);
				mDpfKeys = std::move(source.mDpfKeys);
				mHasSetup = std::exchange(source.mHasSetup, false);

				source.mPublicA.clear();
				source.mSendOts.clear();
				source.mRecvOts.clear();
				source.mRecvChoices.resize(0);
				source.mSparsePositions.clear();
				source.mSparseCoefficients.clear();
				for (auto& key : source.mDpfKeys)
					key = {};
			}
			return *this;
		}

		void init(
			u64 partyIdx,
			u64 dimensions,
			u64 weight,
			block publicSeed,
			Ctx ctx = {})
		{
			if (partyIdx > 1)
				throw std::invalid_argument("AnyFieldOle party index must be zero or one. " LOCATION);
			if (!dimensions)
				throw std::invalid_argument("AnyFieldOle requires at least one ring dimension. " LOCATION);
			if (!weight)
				throw std::invalid_argument("AnyFieldOle sparse weight must be positive. " LOCATION);
			if (Ctx::coordinateBits * dimensions >= 64)
				throw std::invalid_argument("AnyFieldOle binary DPF depth must be below 64. " LOCATION);
			if (weight > std::numeric_limits<u64>::max() / weight)
				throw std::length_error("AnyFieldOle point count overflows u64. " LOCATION);

			const auto pointsPerGroup = weight * weight;
			if (pointsPerGroup > std::numeric_limits<u64>::max() / GroupCount)
				throw std::length_error("AnyFieldOle total point count overflows u64. " LOCATION);
			const auto pointCount = GroupCount * pointsPerGroup;
			if (pointCount > std::numeric_limits<u64>::max() / dimensions)
				throw std::length_error("AnyFieldOle coordinate conversion count overflows u64. " LOCATION);
			const auto coordinateCount = pointCount * dimensions;
			if (coordinateCount > Gmw::MaxOleDimension)
				throw std::invalid_argument("AnyFieldOle coordinate conversion exceeds GMW capacity. " LOCATION);

			const auto domain = Ctx::domainSize(dimensions);
			if (weight > domain)
				throw std::invalid_argument("AnyFieldOle sparse weight exceeds its domain. " LOCATION);
			if (domain > std::numeric_limits<u64>::max() / Ctx::extensionDegree)
				throw std::length_error("AnyFieldOle output size overflows u64. " LOCATION);

			// Build the replacement state in temporaries so a rejected
			// reconfiguration leaves the current object unchanged.
			RegularDpf<Ext, DpfCoeffCtx> validator;
			validator.init(partyIdx, domain, pointsPerGroup, ctx.dpfCoeffCtx());

			BetaLibrary library;
			auto coordinateAdder = *library.int_int_add(
				Ctx::coordinateBits,
				Ctx::coordinateBits,
				Ctx::coordinateBits,
				BetaLibrary::Optimized::Depth);
			Gmw positionGmw;
			positionGmw.init(partyIdx, coordinateCount, coordinateAdder);

			std::vector<Ext> publicA(domain);
			PRNG publicPrng(publicSeed);
			auto coeffCtx = ctx.dpfCoeffCtx();
			for (auto& value : publicA)
				value = coeffCtx.sample(publicPrng);

			clear();
			mCtx = std::move(ctx);
			mPartyIdx = partyIdx;
			mDimensions = dimensions;
			mWeight = weight;
			mN = domain;
			mPublicSeed = publicSeed;
			mPublicA = std::move(publicA);
			mCoordinateAdder = std::move(coordinateAdder);
			mPositionGmw = std::move(positionGmw);
		}

		bool isInitialized() const { return mN != 0; }
		bool hasSetup() const { return mHasSetup; }

		u64 outputSize() const
		{
			if (!isInitialized())
				throw std::logic_error("AnyFieldOle::init must be called first. " LOCATION);
			return Ctx::extensionDegree * mN;
		}

		BaseCorCount baseCorCount() const
		{
			if (!isInitialized())
				throw std::logic_error("AnyFieldOle::init must be called first. " LOCATION);
			if (mHasSetup)
				return {};

			RegularDpf<Ext, DpfCoeffCtx> dpf;
			dpf.init(mPartyIdx, mN, pointsPerGroup(), mCtx.dpfCoeffCtx());
			const auto dpfOtCount = dpf.baseOtCount();
			if (dpfOtCount > std::numeric_limits<u64>::max() / GroupCount)
				throw std::length_error("AnyFieldOle DPF base-OT count overflows u64. " LOCATION);

			BaseCorCount result;
			result.mSendOtCount = GroupCount * dpfOtCount;
			result.mRecvOtCount = GroupCount * dpfOtCount;

			const auto tensorOtCount = rightCoefficientCount() *
				mCtx.dpfCoeffCtx().template bitSize<Ext>();
			if (mPartyIdx)
				result.mRecvOtCount += tensorOtCount;
			else
				result.mSendOtCount += tensorOtCount;

			result.mOleCount = mPositionGmw.oleCount();
			return result;
		}

		void setBaseCors(
			span<const std::array<block, 2>> sendOts,
			span<const block> recvOts,
			const BitVector& recvChoices,
			span<block> oleMult,
			span<block> oleAdd)
		{
			if (mHasSetup)
				throw std::logic_error("AnyFieldOle cannot replace correlations while a seed is pending expansion. " LOCATION);
			const auto count = baseCorCount();
			if (sendOts.size() != count.mSendOtCount ||
				recvOts.size() != count.mRecvOtCount ||
				recvChoices.size() != count.mRecvOtCount)
				throw std::invalid_argument("AnyFieldOle base-OT count mismatch. " LOCATION);
			if (oleMult.size() != divCeil(count.mOleCount, 128) ||
				oleAdd.size() != divCeil(count.mOleCount, 128))
				throw std::invalid_argument("AnyFieldOle binary-OLE count mismatch. " LOCATION);

			std::vector<std::array<block, 2>> newSendOts(sendOts.begin(), sendOts.end());
			std::vector<block> newRecvOts(recvOts.begin(), recvOts.end());
			BitVector newRecvChoices = recvChoices;
			Gmw newPositionGmw;
			newPositionGmw.init(
				mPartyIdx,
				GroupCount * pointsPerGroup() * mDimensions,
				mCoordinateAdder);
			newPositionGmw.setOle(oleMult, oleAdd);

			mSendOts = std::move(newSendOts);
			mRecvOts = std::move(newRecvOts);
			mRecvChoices = std::move(newRecvChoices);
			mPositionGmw = std::move(newPositionGmw);
			mBaseCorsAvailable = true;
		}

		bool hasBaseCors() const
		{
			if (!isInitialized() || mHasSetup || !mBaseCorsAvailable)
				return false;
			const auto count = baseCorCount();
			return mSendOts.size() == count.mSendOtCount &&
				mRecvOts.size() == count.mRecvOtCount &&
				mRecvChoices.size() == count.mRecvOtCount;
		}

		macoro::task<> setup(PRNG& prng, coproto::Socket& socket)
		{
			if (!isInitialized())
				throw std::logic_error("AnyFieldOle::init must be called first. " LOCATION);
			if (mHasSetup)
				throw std::logic_error("AnyFieldOle setup has already completed. " LOCATION);
			if (!hasBaseCors())
				throw std::logic_error("AnyFieldOle requires fresh base correlations. " LOCATION);

			// Correlations are one-shot. Mark them unavailable before the first
			// interaction so an exception cannot lead to accidental reuse.
			mBaseCorsAvailable = false;
			MACORO_TRY
			{
				const std::vector<block> localParams{
					mPublicSeed,
					block(mDimensions, mWeight),
					block(mN, mPartyIdx),
					block(Ctx::baseCharacteristic, Ctx::extensionDegree)
				};
				std::vector<block> peerParams(4);
				co_await socket.send(coproto::copy(localParams));
				co_await socket.recv(peerParams);
				if (peerParams[0] != mPublicSeed ||
					peerParams[1] != block(mDimensions, mWeight) ||
					peerParams[2] != block(mN, 1 ^ mPartyIdx) ||
					peerParams[3] != block(Ctx::baseCharacteristic, Ctx::extensionDegree))
					throw std::invalid_argument(
						"AnyFieldOle peers initialized incompatible parameters. " LOCATION);

				sampleSparseInputs(prng);

				std::vector<Ext> productShares(leftCoefficientCount() * rightCoefficientCount());
				co_await tensorCoefficients(productShares, prng, socket);

				std::vector<u64> pointShares;
				co_await makePointShares(pointShares, socket);

				const auto dpfOtCount = dpfBaseOtCount();
				mDpfKeys = {};
				for (u64 group = 0; group < GroupCount; ++group)
				{
					RegularDpf<Ext, DpfCoeffCtx> dpf;
					dpf.init(mPartyIdx, mN, pointsPerGroup(), mCtx.dpfCoeffCtx());
					const auto otOffset = group * dpfOtCount;
					dpf.setBaseOts(
						span<const std::array<block, 2>>(mSendOts).subspan(otOffset, dpfOtCount),
						span<const block>(mRecvOts).subspan(otOffset, dpfOtCount),
						mRecvChoices.subvec(otOffset, dpfOtCount));

					auto groupPoints = span<u64>(pointShares).subspan(
						group * pointsPerGroup(), pointsPerGroup());
					std::vector<Ext> groupValues(pointsPerGroup());
					fillGroupValues(group, productShares, groupValues);
					co_await dpf.keyGen(
						groupPoints,
						groupValues,
						prng,
						mDpfKeys[group],
						socket,
						mCtx.dpfCoeffCtx());
				}

				clearBaseCors();
				mHasSetup = true;
			}
			MACORO_CATCH(error)
			{
				clear();
				co_await socket.close();
				std::rethrow_exception(error);
			}
		}

		// Output is basis-major: entry j*mN+i is the i-th OLE extracted with
		// Tr(xi^(p^j) * x). Expansion consumes the PCG seed to prevent accidental
		// reuse of the same correlation.
		void expand(span<Base> x, span<Base> z)
		{
			if (!mHasSetup)
				throw std::logic_error("AnyFieldOle::setup must complete before expansion. " LOCATION);
			if (x.size() != outputSize() || z.size() != outputSize())
				throw std::invalid_argument("AnyFieldOle output span has the wrong size. " LOCATION);

			mHasSetup = false;
			try
			{
				std::fill(x.begin(), x.end(), Base::zero());
				std::fill(z.begin(), z.end(), Base::zero());

				std::array<Ext, Ctx::extensionDegree> traceBasis;
				std::array<std::array<Ext, Ctx::extensionDegree>, Ctx::extensionDegree>
					traceFactors;
				for (u64 basis = 0; basis < Ctx::extensionDegree; ++basis)
				{
					traceBasis[basis] = mCtx.traceBasis(basis);
					for (u64 power = 0; power < Ctx::extensionDegree; ++power)
						traceFactors[power][basis] = traceBasis[basis] *
							mCtx.frobenius(traceBasis[basis], power);
				}

				std::vector<Ext> sparseS(mN, Ext::zero());
				std::vector<Ext> sparseE(mN, Ext::zero());
				for (u64 i = 0; i < mWeight; ++i)
				{
					sparseS[mSparsePositions[i]] += mSparseCoefficients[i];
					sparseE[mSparsePositions[mWeight + i]] += mSparseCoefficients[mWeight + i];
				}
				mCtx.transform(sparseS, mDimensions);
				mCtx.transform(sparseE, mDimensions);

				for (u64 index = 0; index < mN; ++index)
				{
					const auto value = mPublicA[index] * sparseS[index] + sparseE[index];
					for (u64 basis = 0; basis < Ctx::extensionDegree; ++basis)
						x[basis * mN + index] = mCtx.trace(traceBasis[basis] * value);
				}

				std::vector<Ext> product(mN);
				for (u64 group = 0; group < GroupCount; ++group)
				{
					std::fill(product.begin(), product.end(), Ext::zero());
					RegularDpf<Ext, DpfCoeffCtx>::expand(
						mPartyIdx,
						mN,
						mDpfKeys[group],
						[&](u64, u64 leaf, Ext value, block) {
							product[leaf] += value;
						},
						mCtx.dpfCoeffCtx());
					mCtx.transform(product, mDimensions);

					const auto frobeniusPower = group / 4;
					const auto term = group % 4;
					for (u64 index = 0; index < mN; ++index)
					{
						const auto a = mPublicA[index];
						const auto aFrobenius = mCtx.frobenius(a, frobeniusPower);
						Ext scaled;
						switch (term)
						{
						case 0: scaled = a * aFrobenius * product[index]; break;
						case 1: scaled = aFrobenius * product[index]; break;
						case 2: scaled = a * product[index]; break;
						default: scaled = product[index]; break;
						}

						for (u64 basis = 0; basis < Ctx::extensionDegree; ++basis)
							z[basis * mN + index] += mCtx.trace(
								traceFactors[frobeniusPower][basis] * scaled);
					}
				}

				clearSetupState();
			}
			catch (...)
			{
				clearSetupState();
				throw;
			}
		}

		void clear()
		{
			clearBaseCors();
			clearSetupState();
			mPartyIdx = 0;
			mDimensions = 0;
			mWeight = 0;
			mN = 0;
			mPublicSeed = block{};
			mPublicA.clear();
			mPositionGmw.clear();
			mCoordinateAdder = {};
		}

	private:
		Ctx mCtx;
		u64 mPartyIdx = 0;
		u64 mDimensions = 0;
		u64 mWeight = 0;
		u64 mN = 0;
		block mPublicSeed{};
		std::vector<Ext> mPublicA;

		Gmw mPositionGmw;
		BetaCircuit mCoordinateAdder;
		std::vector<std::array<block, 2>> mSendOts;
		std::vector<block> mRecvOts;
		BitVector mRecvChoices;
		bool mBaseCorsAvailable = false;

		std::vector<u64> mSparsePositions;
		std::vector<Ext> mSparseCoefficients;
		std::array<RegularDpfKey, GroupCount> mDpfKeys;
		bool mHasSetup = false;

		u64 pointsPerGroup() const { return mWeight * mWeight; }
		u64 leftCoefficientCount() const { return 2 * mWeight; }
		u64 rightCoefficientCount() const { return 2 * Ctx::extensionDegree * mWeight; }

		u64 dpfBaseOtCount() const
		{
			RegularDpf<Ext, DpfCoeffCtx> dpf;
			dpf.init(mPartyIdx, mN, pointsPerGroup(), mCtx.dpfCoeffCtx());
			return dpf.baseOtCount();
		}

		void clearBaseCors()
		{
			mSendOts.clear();
			mRecvOts.clear();
			mRecvChoices.resize(0);
			mBaseCorsAvailable = false;
		}

		void clearSetupState()
		{
			mSparsePositions.clear();
			mSparseCoefficients.clear();
			for (auto& key : mDpfKeys)
				key = {};
			mHasSetup = false;
		}

		void sampleSparseInputs(PRNG& prng)
		{
			mSparsePositions.resize(leftCoefficientCount());
			mSparseCoefficients.resize(leftCoefficientCount());
			auto coeffCtx = mCtx.dpfCoeffCtx();
			for (u64 polynomial = 0; polynomial < 2; ++polynomial)
			{
				const auto offset = polynomial * mWeight;
				for (u64 i = 0; i < mWeight; ++i)
				{
					u64 position;
					bool duplicate;
					do
					{
						position = prng.get<u64>() & (mN - 1);
						duplicate = false;
						for (u64 j = 0; j < i; ++j)
							duplicate |= mSparsePositions[offset + j] == position;
					}
					while (duplicate);
					mSparsePositions[offset + i] = position;
					mSparseCoefficients[offset + i] = coeffCtx.sampleNonZero(prng);
				}
			}
		}

		macoro::task<> tensorCoefficients(
			span<Ext> productShares,
			PRNG& prng,
			coproto::Socket& socket)
		{
			if (productShares.size() != leftCoefficientCount() * rightCoefficientCount())
				throw std::invalid_argument("AnyFieldOle tensor output has the wrong size. " LOCATION);

			const auto dpfOts = GroupCount * dpfBaseOtCount();
			if (mPartyIdx)
			{
				std::vector<Ext> right(rightCoefficientCount());
				for (u64 polynomial = 0; polynomial < 2; ++polynomial)
					for (u64 power = 0; power < Ctx::extensionDegree; ++power)
						for (u64 i = 0; i < mWeight; ++i)
							right[(2 * polynomial + power) * mWeight + i] =
								mCtx.frobenius(mSparseCoefficients[polynomial * mWeight + i], power);

				auto tensorOts = span<block>(mRecvOts).subspan(dpfOts);
				BitVector choices = mRecvChoices.subvec(dpfOts, tensorOts.size());
				BitVector difference = choices;
				std::vector<std::vector<Ext>> vole(rightCoefficientCount(),
					std::vector<Ext>(leftCoefficientCount()));
				std::vector<coproto::Socket> sockets(rightCoefficientCount());
				std::vector<PRNG> prngs(rightCoefficientCount());
				std::vector<macoro::task<>> tasks(rightCoefficientCount());
				auto coeffCtx = mCtx.dpfCoeffCtx();
				const auto bitSize = coeffCtx.template bitSize<Ext>();
				for (u64 i = 0; i < rightCoefficientCount(); ++i)
				{
					auto bits = coeffCtx.binaryDecomposition(right[i]);
					for (u64 bit = 0; bit < bitSize; ++bit)
						difference[i * bitSize + bit] ^= bits[bit];
					sockets[i] = socket.fork();
					prngs[i] = prng.fork();
					tasks[i] = NoisyVoleSender<Ext, Ext, DpfCoeffCtx>::send(
						right[i], vole[i], prngs[i],
						tensorOts.subspan(i * bitSize, bitSize), sockets[i], coeffCtx);
				}
				co_await socket.send(std::move(difference));
				auto results = co_await macoro::when_all_ready(std::move(tasks));
				for (auto& result : results)
					result.result();
				for (u64 left = 0; left < leftCoefficientCount(); ++left)
					for (u64 rightIndex = 0; rightIndex < rightCoefficientCount(); ++rightIndex)
						productShares[left * rightCoefficientCount() + rightIndex] = -vole[rightIndex][left];
			}
			else
			{
				auto tensorOts = span<std::array<block, 2>>(mSendOts).subspan(dpfOts);
				std::vector<std::vector<Ext>> vole(rightCoefficientCount(),
					std::vector<Ext>(leftCoefficientCount()));
				std::vector<coproto::Socket> sockets(rightCoefficientCount());
				std::vector<PRNG> prngs(rightCoefficientCount());
				std::vector<macoro::task<>> tasks(rightCoefficientCount());
				auto coeffCtx = mCtx.dpfCoeffCtx();
				const auto bitSize = coeffCtx.template bitSize<Ext>();
				for (u64 i = 0; i < rightCoefficientCount(); ++i)
				{
					sockets[i] = socket.fork();
					prngs[i] = prng.fork();
					tasks[i] = NoisyVoleReceiver<Ext, Ext, DpfCoeffCtx>::receive(
						mSparseCoefficients, vole[i], prngs[i],
						tensorOts.subspan(i * bitSize, bitSize), sockets[i], coeffCtx);
				}
				BitVector difference(rightCoefficientCount() * bitSize);
				co_await socket.recv(difference);
				for (u64 i = 0; i < difference.size(); ++i)
					if (difference[i])
						std::swap(tensorOts[i][0], tensorOts[i][1]);
				auto results = co_await macoro::when_all_ready(std::move(tasks));
				for (auto& result : results)
					result.result();
				for (u64 left = 0; left < leftCoefficientCount(); ++left)
					for (u64 rightIndex = 0; rightIndex < rightCoefficientCount(); ++rightIndex)
						productShares[left * rightCoefficientCount() + rightIndex] = vole[rightIndex][left];
			}
		}

		macoro::task<> makePointShares(std::vector<u64>& pointShares, coproto::Socket& socket)
		{
			const auto coordinateCount = GroupCount * pointsPerGroup() * mDimensions;
			std::vector<u64> localCoordinates(coordinateCount);
			for (u64 group = 0; group < GroupCount; ++group)
			{
				const auto power = group / 4;
				const auto term = group % 4;
				for (u64 left = 0; left < mWeight; ++left)
				{
					const auto leftPosition = mSparsePositions[
						(term == 1 || term == 3 ? mWeight : 0) + left];
					for (u64 right = 0; right < mWeight; ++right)
					{
						const auto rightPosition = mSparsePositions[
							(term >= 2 ? mWeight : 0) + right];
						const auto point = (group * pointsPerGroup() + left * mWeight + right);
						for (u64 coordinate = 0; coordinate < mDimensions; ++coordinate)
						{
							const auto value = mPartyIdx ?
								mCtx.frobeniusCoordinate(
									mCtx.positionCoordinate(rightPosition, coordinate), power) :
								mCtx.positionCoordinate(leftPosition, coordinate);
							localCoordinates[point * mDimensions + coordinate] = value;
						}
					}
				}
			}

			MatrixView<const u64> input(localCoordinates.data(), coordinateCount, 1);
			mPositionGmw.setInput<const u64>(mPartyIdx, input);
			mPositionGmw.setZeroInput(1 ^ mPartyIdx);
			co_await mPositionGmw.run(socket);

			std::vector<u64> binaryCoordinates(coordinateCount);
			MatrixView<u64> output(binaryCoordinates.data(), coordinateCount, 1);
			mPositionGmw.getOutput<u64>(0, output);

			pointShares.assign(GroupCount * pointsPerGroup(), 0);
			for (u64 point = 0; point < pointShares.size(); ++point)
				for (u64 coordinate = 0; coordinate < mDimensions; ++coordinate)
					pointShares[point] |=
						(binaryCoordinates[point * mDimensions + coordinate] & (Ctx::coordinateSize - 1))
						<< (Ctx::coordinateBits * coordinate);
		}

		void fillGroupValues(u64 group, span<const Ext> productShares, span<Ext> values) const
		{
			const auto power = group / 4;
			const auto term = group % 4;
			const auto leftOffset = (term == 1 || term == 3) ? mWeight : 0;
			const auto rightOffset = (2 * (term >= 2) + power) * mWeight;
			for (u64 left = 0; left < mWeight; ++left)
				for (u64 right = 0; right < mWeight; ++right)
					values[left * mWeight + right] = productShares[
						(leftOffset + left) * rightCoefficientCount() + rightOffset + right];
		}
	};

	using AnyFieldF3Ole = AnyFieldOle<AnyFieldF9Ctx>;
}

#endif
