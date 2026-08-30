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
#include <type_traits>
#include <utility>
#include <vector>

namespace osuCrypto
{
	namespace anyField::detail
	{
		inline BitVector constantBits(u64 value, u64 size)
		{
			BitVector result(size);
			for (u64 bit = 0; bit < size; ++bit)
				result[bit] = (value >> bit) & 1;
			return result;
		}

		inline BetaBundle bundleSlice(const BetaBundle& bundle, u64 offset, u64 size)
		{
			if (offset > bundle.size() || size > bundle.size() - offset)
				throw std::out_of_range("AnyField position-circuit bundle slice is out of range. " LOCATION);
			BetaBundle result;
			result.insert(result.end(), bundle.begin() + offset, bundle.begin() + offset + size);
			return result;
		}

		inline BetaCircuit makePositionCircuit(
			u64 coordinateSize,
			u64 coordinateBits,
			u64 dimensions,
			u64 domainSize)
		{
			if (coordinateSize < 2 || !coordinateBits || coordinateBits >= 64 || !dimensions)
				throw std::invalid_argument("Invalid AnyField position-circuit parameters. " LOCATION);
			if (coordinateSize > (u64{ 1 } << coordinateBits) ||
				coordinateSize <= (u64{ 1 } << (coordinateBits - 1)))
				throw std::invalid_argument("AnyField coordinate width is not canonical. " LOCATION);
			if (coordinateBits * dimensions >= 64 || log2ceil(domainSize) >= 64)
				throw std::invalid_argument("AnyField position circuit exceeds the u64 interface. " LOCATION);
			u64 expectedDomain = 1;
			for (u64 i = 0; i < dimensions; ++i)
				expectedDomain *= coordinateSize;
			if (domainSize != expectedDomain)
				throw std::invalid_argument("AnyField position circuit has an inconsistent domain. " LOCATION);

			const auto inputBits = coordinateBits * dimensions;
			const auto outputBits = log2ceil(domainSize);
			BetaCircuit circuit;
			BetaBundle lhs(inputBits), rhs(inputBits), output(outputBits);
			circuit.addInputBundle(lhs);
			circuit.addInputBundle(rhs);
			circuit.addOutputBundle(output);

			const auto powerOfTwo = coordinateSize == (u64{ 1 } << coordinateBits);
			std::vector<BetaBundle> coordinates(dimensions);
			for (u64 coordinate = 0; coordinate < dimensions; ++coordinate)
			{
				auto lhsCoordinate = bundleSlice(
					lhs, coordinate * coordinateBits, coordinateBits);
				auto rhsCoordinate = bundleSlice(
					rhs, coordinate * coordinateBits, coordinateBits);

				if (powerOfTwo)
				{
					coordinates[coordinate] = bundleSlice(
						output, coordinate * coordinateBits, coordinateBits);
					BetaBundle temp(2 * coordinateBits);
					circuit.addTempWireBundle(temp);
					BetaLibrary::add_build(
						circuit, lhsCoordinate, rhsCoordinate, coordinates[coordinate], temp,
						BetaLibrary::IntType::Unsigned, BetaLibrary::Optimized::Depth);
				}
				else
				{
					BetaBundle sum(coordinateBits + 1);
					BetaBundle sumTemp(2 * sum.size());
					circuit.addTempWireBundle(sum);
					circuit.addTempWireBundle(sumTemp);
					BetaLibrary::add_build(
						circuit, lhsCoordinate, rhsCoordinate, sum, sumTemp,
						BetaLibrary::IntType::Unsigned, BetaLibrary::Optimized::Depth);

					BetaBundle modulus(sum.size());
					auto modulusBits = constantBits(coordinateSize, sum.size());
					circuit.addConstBundle(modulus, modulusBits);
					BetaBundle difference(sum.size() + 1);
					BetaBundle differenceTemp(2 * difference.size());
					circuit.addTempWireBundle(difference);
					circuit.addTempWireBundle(differenceTemp);
					BetaLibrary::subtract_build(
						circuit, sum, modulus, difference, differenceTemp,
						BetaLibrary::IntType::Unsigned, BetaLibrary::Optimized::Depth);

					coordinates[coordinate].resize(coordinateBits);
					circuit.addTempWireBundle(coordinates[coordinate]);
					BetaBundle differenceLow = bundleSlice(difference, 0, coordinateBits);
					BetaBundle sumLow = bundleSlice(sum, 0, coordinateBits);
					BetaBundle borrow = bundleSlice(difference, difference.size() - 1, 1);
					BetaBundle muxTemp(1);
					circuit.addTempWireBundle(muxTemp);
					BetaLibrary::multiplex_build(
						circuit, sumLow, differenceLow, borrow,
						coordinates[coordinate], muxTemp);
				}
			}

			if (!powerOfTwo)
			{
				if (dimensions == 1)
				{
					circuit.addCopy(
						bundleSlice(coordinates[0], 0, outputBits), output);
				}
				else
				{
					u64 partialDomain = coordinateSize;
					BetaBundle accumulator = coordinates.back();
					for (u64 processed = 1; processed < dimensions; ++processed)
					{
						const auto coordinate = dimensions - 1 - processed;
						if (partialDomain > std::numeric_limits<u64>::max() / coordinateSize)
							throw std::length_error("AnyField partial domain overflows u64. " LOCATION);
						partialDomain *= coordinateSize;
						const auto nextBits = log2ceil(partialDomain);
						BetaBundle radix(coordinateBits);
						auto radixBits = constantBits(coordinateSize, coordinateBits);
						circuit.addConstBundle(radix, radixBits);

						BetaBundle product(nextBits);
						circuit.addTempWireBundle(product);
						BetaLibrary::mult_build(
							circuit, accumulator, radix, product,
							BetaLibrary::Optimized::Depth, BetaLibrary::IntType::Unsigned);

						BetaBundle next = processed + 1 == dimensions ? output : BetaBundle(nextBits);
						if (processed + 1 != dimensions)
							circuit.addTempWireBundle(next);
						BetaBundle addTemp(2 * nextBits);
						circuit.addTempWireBundle(addTemp);
						BetaLibrary::add_build(
							circuit, product, coordinates[coordinate], next, addTemp,
							BetaLibrary::IntType::Unsigned, BetaLibrary::Optimized::Depth);
						accumulator = std::move(next);
					}
				}
			}

			return circuit;
		}
	}

	// Semi-honest two-party PCG for OLE over a base field, following
	// Construction 1 of "Efficient Pseudorandom Correlation Generators for Any
	// Finite Field". Field-specific operations are supplied by a compile-time
	// context. AnyFieldF9Ctx generates F3 OLEs from QA-SD over F9,
	// AnyFieldF4Ctx generates F2 OLEs from QA-SD over F4, and
	// AnyFieldGoldilocksCtx generates Goldilocks OLEs directly over the base
	// field. For each output index, the parties' shares satisfy
	// x_0 * x_1 = z_0 + z_1.
	//
	// Callers request a number of OLEs. The implementation fixes its 128-bit
	// QA-SD parameters, rounds small requests up to the minimum secure domain,
	// and returns exactly the requested prefix. Noise is generalized regular:
	// every sparse polynomial has a fixed number of points in each public coset,
	// allowing each product DPF to expand over a domain smaller by BlockCount.
	// Base OTs and binary OLEs are one-shot and must be freshly installed before
	// every setup. The public seed must be sampled honestly and uniformly,
	// independently of the parties' private inputs, and agreed by both parties; it
	// must not be adversarially selected or biased. The paper states QA-SD for a
	// uniformly random public group-algebra element, whereas this implementation
	// derives that element from PRNG(publicSeed). Thus this seeded instantiation
	// additionally uses the usual public-matrix/ideal-cipher heuristic. Reusing a
	// seed for independent setups also relies on the multi-instance form of the
	// QA-SD assumption.
	template<AnyFieldContext Context,
		typename Parameters = typename AnyFieldDefaultParams<Context>::type>
	class AnyFieldOle : public TimerAdapter
	{
	public:
		using Ctx = Context;
		using Params = Parameters;
		using Base = typename Ctx::Base;
		using Ext = typename Ctx::Ext;
		using DpfCoeffCtx = typename Ctx::DpfCoeffCtx;

		static constexpr u64 CompressionFactor = Params::compressionFactor;
		static constexpr u64 BlockDimensions = Params::blockDimensions;
		static constexpr u64 PointsPerBlock = Params::pointsPerBlock;
		static constexpr u64 BlockCount = [] {
			u64 result = 1;
			for (u64 i = 0; i < BlockDimensions; ++i)
				result *= Ctx::coordinateSize;
			return result;
		}();
		static constexpr u64 Weight = BlockCount * PointsPerBlock;
		static constexpr u64 GroupCount =
			CompressionFactor * CompressionFactor * Ctx::extensionDegree;
		static constexpr bool PacksPublicCoefficients =
			CompressionFactor * Ctx::fieldBits <= 32;
		using PackedPublic = std::conditional_t<
			!PacksPublicCoefficients,
			Ext,
			std::conditional_t<CompressionFactor * Ctx::fieldBits <= 8,
			u8,
			std::conditional_t<CompressionFactor * Ctx::fieldBits <= 16, u16, u32>>>;
		static constexpr bool PowerOfTwoCoordinates =
			Ctx::coordinateSize == (u64{ 1 } << Ctx::coordinateBits);
		static_assert(Ctx::extensionDegree > 0,
			"AnyFieldOle requires a positive extension degree.");
		static_assert(Ctx::coordinateBits > 0 && Ctx::coordinateBits < 64,
			"AnyFieldOle requires a coordinate width between one and 63 bits.");
		static_assert(Ctx::coordinateSize > (u64{ 1 } << (Ctx::coordinateBits - 1)) &&
			Ctx::coordinateSize <= (u64{ 1 } << Ctx::coordinateBits),
			"AnyFieldOle coordinateBits must be ceil(log2(coordinateSize)).");
		static_assert(CompressionFactor > 1 && Ctx::fieldBits > 0,
			"AnyFieldOle requires at least two public polynomials and a nonzero field width.");
		static_assert(Params::minimumDimension > BlockDimensions,
			"AnyFieldOle requires a nontrivial within-block DPF domain.");
		static_assert(Params::minimumDimension <= Params::maximumDimension,
			"AnyFieldOle dimension bounds are inconsistent.");

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
				mDimension = std::exchange(source.mDimension, 0);
				mRequestedOleCount = std::exchange(source.mRequestedOleCount, 0);
				mN = std::exchange(source.mN, 0);
				mBlockSize = std::exchange(source.mBlockSize, 0);
				mPublicSeed = std::exchange(source.mPublicSeed, block{});
				mPublicA = std::move(source.mPublicA);
				mPositionGmw = std::move(source.mPositionGmw);
				mPositionCircuit = std::move(source.mPositionCircuit);
				mPositionOleCount = std::exchange(source.mPositionOleCount, 0);
				mSendOts = std::move(source.mSendOts);
				mRecvOts = std::move(source.mRecvOts);
				mRecvChoices = std::move(source.mRecvChoices);
				mBaseCorsAvailable = std::exchange(source.mBaseCorsAvailable, false);
				mSparsePositions = std::move(source.mSparsePositions);
				mSparseCoefficients = std::move(source.mSparseCoefficients);
				mDpfKeys = std::move(source.mDpfKeys);
				mHasSetup = std::exchange(source.mHasSetup, false);

				source.mPublicA = {};
				source.mPositionGmw.clear();
				source.mPositionCircuit = {};
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
			u64 numOles,
			block publicSeed,
			Ctx ctx = {})
		{
			if (partyIdx > 1)
				throw std::invalid_argument("AnyFieldOle party index must be zero or one. " LOCATION);
			if (!numOles)
				throw std::invalid_argument("AnyFieldOle requires at least one requested OLE. " LOCATION);

			const auto requestedRingSize = divCeil(numOles, Ctx::extensionDegree);
			u64 dimension = 0;
			u64 domain = 1;
			while (domain < requestedRingSize && dimension < Params::maximumDimension)
			{
				if (domain > std::numeric_limits<u64>::max() / Ctx::coordinateSize)
					throw std::length_error("AnyFieldOle domain size overflows u64. " LOCATION);
				domain *= Ctx::coordinateSize;
				++dimension;
			}
			dimension = std::max<u64>(dimension, Params::minimumDimension);
			if (dimension > Params::maximumDimension)
				throw std::invalid_argument("AnyFieldOle request exceeds one secure expansion domain. " LOCATION);
			domain = Ctx::domainSize(dimension);
			if (domain < requestedRingSize)
				throw std::invalid_argument("AnyFieldOle request exceeds one secure expansion domain. " LOCATION);
			if (Ctx::coordinateBits * dimension >= 64)
				throw std::invalid_argument("AnyFieldOle binary DPF depth must be below 64. " LOCATION);

			constexpr auto pointsPerGroup = Weight * Weight;
			if (pointsPerGroup > std::numeric_limits<u64>::max() / GroupCount)
				throw std::length_error("AnyFieldOle total point count overflows u64. " LOCATION);
			const auto pointCount = GroupCount * pointsPerGroup;
			const auto localDimensions = dimension - BlockDimensions;
			if (pointCount > std::numeric_limits<u64>::max() / localDimensions)
				throw std::length_error("AnyFieldOle coordinate conversion count overflows u64. " LOCATION);
			const auto positionInstances = PowerOfTwoCoordinates ?
				pointCount * localDimensions : pointCount;
			if (positionInstances > Gmw::MaxOleDimension)
				throw std::invalid_argument("AnyFieldOle position conversion exceeds GMW capacity. " LOCATION);

			if (domain > std::numeric_limits<u64>::max() / Ctx::extensionDegree)
				throw std::length_error("AnyFieldOle output size overflows u64. " LOCATION);
			const auto blockSize = domain / BlockCount;
			if (PointsPerBlock > blockSize)
				throw std::invalid_argument("AnyFieldOle regular block is too small for its points. " LOCATION);

			// Build the replacement state in temporaries so a rejected
			// reconfiguration leaves the current object unchanged.
			RegularDpf<Ext, DpfCoeffCtx> validator;
			validator.init(partyIdx, blockSize, pointsPerGroup, ctx.dpfCoeffCtx());

			BetaCircuit positionCircuit;
			if constexpr (PowerOfTwoCoordinates)
			{
				BetaLibrary library;
				positionCircuit = *library.int_int_add(
					Ctx::coordinateBits,
					Ctx::coordinateBits,
					Ctx::coordinateBits,
					BetaLibrary::Optimized::Depth);
			}
			else
			{
				positionCircuit = anyField::detail::makePositionCircuit(
					Ctx::coordinateSize, Ctx::coordinateBits,
					localDimensions, blockSize);
			}
			Gmw positionGmw;
			positionGmw.init(partyIdx, positionInstances, positionCircuit);
			const auto positionOleCount = positionGmw.oleCount();

			// Expansion returns a basis-major prefix and never reads a public
			// multiplier past that prefix. Avoid materializing the unused tail of
			// the much larger secure ring domain.
			const auto publicCount = std::min(domain, numOles);
			std::vector<PackedPublic> publicA;
			PRNG publicPrng(publicSeed);
			auto coeffCtx = ctx.dpfCoeffCtx();
			if constexpr (PacksPublicCoefficients)
			{
				publicA.resize(publicCount);
				for (auto& output : publicA)
				{
					u32 packed = Ext::one().index();
					for (u64 polynomial = 1; polynomial < CompressionFactor; ++polynomial)
						packed |= u32(coeffCtx.sample(publicPrng).index()) <<
							(polynomial * Ctx::fieldBits);
					output = static_cast<PackedPublic>(packed);
				}
			}
			else
			{
				if (publicCount > std::numeric_limits<u64>::max() / (CompressionFactor - 1))
					throw std::length_error("AnyFieldOle public coefficient count overflows u64. " LOCATION);
				publicA.resize(publicCount * (CompressionFactor - 1));
				for (u64 polynomial = 1; polynomial < CompressionFactor; ++polynomial)
					for (u64 index = 0; index < publicCount; ++index)
						publicA[(polynomial - 1) * publicCount + index] = coeffCtx.sample(publicPrng);
			}

			clear();
			mCtx = std::move(ctx);
			mPartyIdx = partyIdx;
			mDimension = dimension;
			mRequestedOleCount = numOles;
			mN = domain;
			mBlockSize = blockSize;
			mPublicSeed = publicSeed;
			mPublicA = std::move(publicA);
			mPositionCircuit = std::move(positionCircuit);
			mPositionGmw = std::move(positionGmw);
			mPositionOleCount = positionOleCount;
		}

		bool isInitialized() const { return mN != 0; }
		bool hasSetup() const { return mHasSetup; }

		u64 outputSize() const
		{
			if (!isInitialized())
				throw std::logic_error("AnyFieldOle::init must be called first. " LOCATION);
			return mRequestedOleCount;
		}

		u64 expandedOutputSize() const
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
			dpf.init(mPartyIdx, mBlockSize, pointsPerGroup(), mCtx.dpfCoeffCtx());
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

			result.mOleCount = mPositionOleCount;
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
				positionInstanceCount(),
				mPositionCircuit);
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
					block(mDimension, mRequestedOleCount),
					block(mN, mPartyIdx),
					block(Ctx::baseCharacteristic, Ctx::extensionDegree),
					block(CompressionFactor, Weight),
					block(BlockCount, PointsPerBlock)
				};
				std::vector<block> peerParams(localParams.size());
				co_await socket.send(coproto::copy(localParams));
				co_await socket.recv(peerParams);
				if (peerParams[0] != mPublicSeed ||
					peerParams[1] != block(mDimension, mRequestedOleCount) ||
					peerParams[2] != block(mN, 1 ^ mPartyIdx) ||
					peerParams[3] != block(Ctx::baseCharacteristic, Ctx::extensionDegree) ||
					peerParams[4] != block(CompressionFactor, Weight) ||
					peerParams[5] != block(BlockCount, PointsPerBlock))
					throw std::invalid_argument(
						"AnyFieldOle peers initialized incompatible parameters. " LOCATION);

				sampleSparseInputs(prng);

				std::vector<Ext> productShares(leftCoefficientCount() * rightCoefficientCount());
				co_await tensorCoefficients(productShares, prng, socket);

				std::vector<u64> pointShares;
				co_await makePointShares(pointShares, socket);

				const auto dpfOtCount = dpfBaseOtCount();
				mDpfKeys = {};
				typename RegularDpf<Ext, DpfCoeffCtx>::CompactScratch dpfScratch;
				for (u64 group = 0; group < GroupCount; ++group)
				{
					RegularDpf<Ext, DpfCoeffCtx> dpf;
					dpf.init(mPartyIdx, mBlockSize, pointsPerGroup(), mCtx.dpfCoeffCtx());
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
						dpfScratch,
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

		// The conceptual full expansion is basis-major: entry j*mN+i is the i-th
		// OLE extracted with Tr(xi^(p^j) * x). Only the requested prefix is
		// returned. Expansion consumes the PCG seed to prevent accidental reuse of
		// the same correlation.
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
				const auto publicCount = std::min(mN, mRequestedOleCount);

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

				// Transform one sparse polynomial at a time. This keeps the working
				// set O(N). Small-field public multipliers remain packed in one
				// integral word; large-field multipliers are stored polynomial-major.
				std::vector<Ext> work(mN, Ext::zero());
				for (u64 polynomial = 0; polynomial < CompressionFactor; ++polynomial)
				{
					std::fill(work.begin(), work.end(), Ext::zero());
					const auto coefficientOffset = polynomial * Weight;
					for (u64 point = 0; point < Weight; ++point)
						work[fullPosition(point, mSparsePositions[coefficientOffset + point])] +=
							mSparseCoefficients[coefficientOffset + point];
					mCtx.transform(work, mDimension);
					if (polynomial)
					{
						if constexpr (PacksPublicCoefficients)
						{
							for (u64 index = 0; index < publicCount; ++index)
								work[index] *= publicValue(index, polynomial);
						}
						else
						{
							const auto* publicValues = mPublicA.data() +
								(polynomial - 1) * publicCount;
							for (u64 index = 0; index < publicCount; ++index)
								work[index] *= publicValues[index];
						}
					}

					for (u64 basis = 0; basis < Ctx::extensionDegree; ++basis)
					{
						const auto outputOffset = basis * mN;
						if (outputOffset >= x.size())
							break;
						const auto count = std::min<u64>(mN, x.size() - outputOffset);
						for (u64 index = 0; index < count; ++index)
							x[outputOffset + index] +=
								mCtx.trace(traceBasis[basis] * work[index]);
					}
				}

				typename RegularDpf<Ext, DpfCoeffCtx>::CompactScratch dpfScratch;
				for (u64 group = 0; group < GroupCount; ++group)
				{
					std::fill(work.begin(), work.end(), Ext::zero());
					RegularDpf<Ext, DpfCoeffCtx>::expand(
						mPartyIdx,
						mBlockSize,
						mDpfKeys[group],
						dpfScratch,
						[&](u64 tree, u64 leaf, Ext value, block) {
							const auto left = tree / Weight;
							const auto right = tree - left * Weight;
							work[productBlock(group, left, right) + BlockCount * leaf] += value;
						},
						mCtx.dpfCoeffCtx());
					mCtx.transform(work, mDimension);

					const auto frobeniusPower = group / (CompressionFactor * CompressionFactor);
					const auto pair = group % (CompressionFactor * CompressionFactor);
					const auto leftPolynomial = pair / CompressionFactor;
					const auto rightPolynomial = pair % CompressionFactor;
					if constexpr (PacksPublicCoefficients)
					{
						if (leftPolynomial && rightPolynomial)
						{
							for (u64 index = 0; index < publicCount; ++index)
								work[index] *= publicValue(index, leftPolynomial) *
									mCtx.frobenius(
										publicValue(index, rightPolynomial), frobeniusPower);
						}
						else if (leftPolynomial)
						{
							for (u64 index = 0; index < publicCount; ++index)
								work[index] *= publicValue(index, leftPolynomial);
						}
						else if (rightPolynomial)
						{
							for (u64 index = 0; index < publicCount; ++index)
								work[index] *= mCtx.frobenius(
									publicValue(index, rightPolynomial), frobeniusPower);
						}
					}
					else
					{
						const auto* leftPublic = leftPolynomial ?
							mPublicA.data() + (leftPolynomial - 1) * publicCount : nullptr;
						const auto* rightPublic = rightPolynomial ?
							mPublicA.data() + (rightPolynomial - 1) * publicCount : nullptr;
						if (leftPublic && rightPublic)
						{
							for (u64 index = 0; index < publicCount; ++index)
								work[index] *= leftPublic[index] *
									mCtx.frobenius(rightPublic[index], frobeniusPower);
						}
						else if (leftPublic)
						{
							for (u64 index = 0; index < publicCount; ++index)
								work[index] *= leftPublic[index];
						}
						else if (rightPublic)
						{
							for (u64 index = 0; index < publicCount; ++index)
								work[index] *=
									mCtx.frobenius(rightPublic[index], frobeniusPower);
						}
					}
					for (u64 basis = 0; basis < Ctx::extensionDegree; ++basis)
					{
						const auto outputOffset = basis * mN;
						if (outputOffset >= z.size())
							break;
						const auto count = std::min<u64>(mN, z.size() - outputOffset);
						for (u64 index = 0; index < count; ++index)
							z[outputOffset + index] += mCtx.trace(
								traceFactors[frobeniusPower][basis] * work[index]);
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
			mDimension = 0;
			mRequestedOleCount = 0;
			mN = 0;
			mBlockSize = 0;
			mPublicSeed = block{};
			// Explicit clear releases the potentially dominant public matrix. It is
			// retained across expand() calls until the caller clears or reinitializes
			// the object so that independent setups can reuse the same matrix.
			mPublicA = {};
			mPositionGmw.clear();
			mPositionCircuit = {};
			mPositionOleCount = 0;
		}

	private:
		Ctx mCtx;
		u64 mPartyIdx = 0;
		u64 mDimension = 0;
		u64 mRequestedOleCount = 0;
		u64 mN = 0;
		u64 mBlockSize = 0;
		block mPublicSeed{};
		std::vector<PackedPublic> mPublicA;

		Gmw mPositionGmw;
		BetaCircuit mPositionCircuit;
		u64 mPositionOleCount = 0;
		std::vector<std::array<block, 2>> mSendOts;
		std::vector<block> mRecvOts;
		BitVector mRecvChoices;
		bool mBaseCorsAvailable = false;

		std::vector<u64> mSparsePositions;
		std::vector<Ext> mSparseCoefficients;
		std::array<RegularDpfKey, GroupCount> mDpfKeys;
		bool mHasSetup = false;

		static constexpr u64 pointsPerGroup() { return Weight * Weight; }
		u64 positionInstanceCount() const
		{
			const auto points = GroupCount * pointsPerGroup();
			return PowerOfTwoCoordinates ? points * localDimensions() : points;
		}
		static constexpr u64 leftCoefficientCount() { return CompressionFactor * Weight; }
		static constexpr u64 rightCoefficientCount()
		{
			return CompressionFactor * Ctx::extensionDegree * Weight;
		}

		u64 dpfBaseOtCount() const
		{
			RegularDpf<Ext, DpfCoeffCtx> dpf;
			dpf.init(mPartyIdx, mBlockSize, pointsPerGroup(), mCtx.dpfCoeffCtx());
			return dpf.baseOtCount();
		}

		void clearBaseCors()
		{
			// These correlations are one-shot, and setBaseCors builds fresh
			// replacement storage. Release their capacity once setup consumes them.
			mSendOts = {};
			mRecvOts = {};
			mRecvChoices = {};
			mPositionGmw.clear();
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
			for (u64 polynomial = 0; polynomial < CompressionFactor; ++polynomial)
			{
				const auto polynomialOffset = polynomial * Weight;
				for (u64 blockIndex = 0; blockIndex < BlockCount; ++blockIndex)
				{
					const auto blockOffset = polynomialOffset + blockIndex * PointsPerBlock;
					for (u64 slot = 0; slot < PointsPerBlock; ++slot)
					{
						u64 position;
						bool duplicate;
						do
						{
							position = fieldSampling::sample(prng, mBlockSize);
							duplicate = false;
							for (u64 previous = 0; previous < slot; ++previous)
								duplicate |= mSparsePositions[blockOffset + previous] == position;
						}
						while (duplicate);
						mSparsePositions[blockOffset + slot] = position;
						mSparseCoefficients[blockOffset + slot] = coeffCtx.sampleNonZero(prng);
					}
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
				for (u64 polynomial = 0; polynomial < CompressionFactor; ++polynomial)
					for (u64 power = 0; power < Ctx::extensionDegree; ++power)
						for (u64 i = 0; i < Weight; ++i)
							right[(Ctx::extensionDegree * polynomial + power) * Weight + i] =
								mCtx.frobenius(mSparseCoefficients[polynomial * Weight + i], power);

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
			const auto pointCount = GroupCount * pointsPerGroup();
			const auto positionInstances = positionInstanceCount();
			std::vector<u64> localPositions(positionInstances);
			for (u64 group = 0; group < GroupCount; ++group)
			{
				const auto power = group / (CompressionFactor * CompressionFactor);
				const auto pair = group % (CompressionFactor * CompressionFactor);
				const auto leftPolynomial = pair / CompressionFactor;
				const auto rightPolynomial = pair % CompressionFactor;
				for (u64 left = 0; left < Weight; ++left)
				{
					const auto leftPosition =
						mSparsePositions[leftPolynomial * Weight + left];
					for (u64 right = 0; right < Weight; ++right)
					{
						const auto rightPosition =
							mSparsePositions[rightPolynomial * Weight + right];
						const auto point = group * pointsPerGroup() + left * Weight + right;
						if constexpr (PowerOfTwoCoordinates)
						{
							for (u64 coordinate = 0; coordinate < localDimensions(); ++coordinate)
							{
								const auto position = mPartyIdx ? rightPosition : leftPosition;
								const auto coordinatePower = mPartyIdx ? power : 0;
								localPositions[point * localDimensions() + coordinate] =
									mCtx.frobeniusCoordinate(
										mCtx.positionCoordinate(position, coordinate), coordinatePower);
							}
						}
						else
						{
							localPositions[point] = mPartyIdx ?
								packPositionInput(rightPosition, power) :
								packPositionInput(leftPosition, 0);
						}
					}
				}
			}

			MatrixView<const u64> input(localPositions.data(), positionInstances, 1);
			mPositionGmw.setInput<const u64>(mPartyIdx, input);
			mPositionGmw.setZeroInput(1 ^ mPartyIdx);
			co_await mPositionGmw.run(socket);

			if constexpr (PowerOfTwoCoordinates)
			{
				std::vector<u64> coordinates(positionInstances);
				MatrixView<u64> output(coordinates.data(), positionInstances, 1);
				mPositionGmw.getOutput<u64>(0, output);
				pointShares.assign(pointCount, 0);
				for (u64 point = 0; point < pointCount; ++point)
					for (u64 coordinate = 0; coordinate < localDimensions(); ++coordinate)
						pointShares[point] |=
							(coordinates[point * localDimensions() + coordinate] &
								(Ctx::coordinateSize - 1)) <<
							(Ctx::coordinateBits * coordinate);
			}
			else
			{
				pointShares.assign(pointCount, 0);
				MatrixView<u64> output(pointShares.data(), pointCount, 1);
				mPositionGmw.getOutput<u64>(0, output);
			}
		}

		u64 packPositionInput(u64 position, u64 frobeniusPower) const
		{
			u64 packed = 0;
			for (u64 coordinate = 0; coordinate < localDimensions(); ++coordinate)
			{
				const auto value = mCtx.frobeniusCoordinate(
					mCtx.positionCoordinate(position, coordinate), frobeniusPower);
				packed |= value << (Ctx::coordinateBits * coordinate);
			}
			return packed;
		}

		u64 localDimensions() const
		{
			return mDimension - BlockDimensions;
		}

		u64 fullPosition(u64 point, u64 localPosition) const
		{
			return point / PointsPerBlock + BlockCount * localPosition;
		}

		OC_FORCEINLINE Ext publicValue(u64 index, u64 polynomial) const
		{
			if constexpr (PacksPublicCoefficients)
			{
				const auto mask = (u32{ 1 } << Ctx::fieldBits) - 1;
				return Ext::fromIndex(static_cast<u8>(
					(static_cast<u32>(mPublicA[index]) >>
						(polynomial * Ctx::fieldBits)) & mask));
			}
			else
			{
				if (polynomial == 0)
					return Ext::one();
				const auto publicCount = std::min(mN, mRequestedOleCount);
				return mPublicA[(polynomial - 1) * publicCount + index];
			}
		}

		u64 productBlock(u64 group, u64 leftPoint, u64 rightPoint) const
		{
			const auto power = group / (CompressionFactor * CompressionFactor);
			auto leftBlock = leftPoint / PointsPerBlock;
			auto rightBlock = rightPoint / PointsPerBlock;
			u64 result = 0;
			u64 radix = 1;
			for (u64 coordinate = 0; coordinate < BlockDimensions; ++coordinate)
			{
				const auto left = leftBlock % Ctx::coordinateSize;
				const auto right = mCtx.frobeniusCoordinate(
					rightBlock % Ctx::coordinateSize, power);
				result += ((left + right) % Ctx::coordinateSize) * radix;
				leftBlock /= Ctx::coordinateSize;
				rightBlock /= Ctx::coordinateSize;
				radix *= Ctx::coordinateSize;
			}
			return result;
		}

		void fillGroupValues(u64 group, span<const Ext> productShares, span<Ext> values) const
		{
			const auto power = group / (CompressionFactor * CompressionFactor);
			const auto pair = group % (CompressionFactor * CompressionFactor);
			const auto leftPolynomial = pair / CompressionFactor;
			const auto rightPolynomial = pair % CompressionFactor;
			const auto leftOffset = leftPolynomial * Weight;
			const auto rightOffset =
				(Ctx::extensionDegree * rightPolynomial + power) * Weight;
			for (u64 left = 0; left < Weight; ++left)
				for (u64 right = 0; right < Weight; ++right)
					values[left * Weight + right] = productShares[
						(leftOffset + left) * rightCoefficientCount() + rightOffset + right];
		}
	};

	using AnyFieldF2Ole = AnyFieldOle<AnyFieldF4Ctx>;
	using AnyFieldF3Ole = AnyFieldOle<AnyFieldF9Ctx>;
	using AnyFieldGoldilocksOle = AnyFieldOle<AnyFieldGoldilocksCtx>;
}

#endif
