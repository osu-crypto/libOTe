#pragma once

#include "libOTe/config.h"
#if defined(ENABLE_REGULAR_DPF) && defined(ENABLE_CIRCUITS)

#include "libOTe/Triple/AnyField/AnyFieldCtx.h"
#include "libOTe/Dpf/SumDmpf.h"
#ifdef ENABLE_SPARSE_DPF
#include "libOTe/Dpf/RevCuckooDmpf.h"
#endif
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
#include <variant>
#include <vector>

namespace osuCrypto
{
	enum class AnyFieldDpfMode
	{
		RegularDpf,
		RevCuckoo
	};

	enum class AnyFieldNoiseMode
	{
		SingleUse,
		Stationary
	};

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
	// Callers request a number of OLEs and choose the runtime compression factor
	// c through LpnParameterConfig. The implementation derives t from the shared
	// 128-bit policy, rounds small requests up to the minimum secure domain, and
	// returns exactly the requested prefix. Noise is generalized regular:
	// every sparse polynomial has a fixed number of points in each public coset,
	// allowing each product DPF to expand over a domain smaller by BlockCount.
	// The DPF backend and noise lifecycle are independent runtime choices.
	// RegularDpf and RevCuckoo implement the same sparse product expansion.
	// SingleUse samples fresh sparse positions for every expansion, while
	// Stationary retains positions and samples fresh nonzero coefficients for
	// every expansion. The latter uses the stationary/shared-support QA-SD
	// assumption regardless of which DPF backend is selected.
	//
	// Tensor correlations are one-shot and must be freshly installed before every
	// setup. RegularDpf also needs fresh DPF base OTs for every expansion.
	// RevCuckoo consumes its position-setup correlations once and reuses that
	// position state in Stationary mode. Binary OLEs are needed whenever fresh
	// positions are sampled. The public seed must be sampled honestly and uniformly,
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

		static constexpr u64 BlockDimensions = Params::blockDimensions;
		static constexpr u64 BlockCount = [] {
			u64 result = 1;
			for (u64 i = 0; i < BlockDimensions; ++i)
				result *= Ctx::coordinateSize;
			return result;
		}();
		static constexpr u64 MaxCompressionFactor = 8;
		// Product-degree channels have multiplicities 1,2,...,c,...,2,1. Ordinary
		// DPFs handle multiplicities one and two. RevCuckoo handles multiplicities
		// three through c, grouping the two channels of each equal multiplicity into
		// one rectangular multi-set instance. The center channel is the sole set
		// group at multiplicity c.
		static constexpr u64 SmallPairCountLimit = 2;
		static constexpr bool PacksPublicCoefficients =
			MaxCompressionFactor * Ctx::fieldBits <= 32;
		using PackedPublic = std::conditional_t<
			!PacksPublicCoefficients,
			Ext,
			std::conditional_t<MaxCompressionFactor * Ctx::fieldBits <= 8,
			u8,
			std::conditional_t<MaxCompressionFactor * Ctx::fieldBits <= 16, u16, u32>>>;
		static constexpr bool PowerOfTwoCoordinates =
			Ctx::coordinateSize == (u64{ 1 } << Ctx::coordinateBits);
		static_assert(Ctx::extensionDegree > 0,
			"AnyFieldOle requires a positive extension degree.");
		static_assert(Ctx::coordinateBits > 0 && Ctx::coordinateBits < 64,
			"AnyFieldOle requires a coordinate width between one and 63 bits.");
		static_assert(Ctx::coordinateSize > (u64{ 1 } << (Ctx::coordinateBits - 1)) &&
			Ctx::coordinateSize <= (u64{ 1 } << Ctx::coordinateBits),
			"AnyFieldOle coordinateBits must be ceil(log2(coordinateSize)).");
		static_assert(Ctx::fieldBits > 0,
			"AnyFieldOle requires a nonzero field width.");
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

		// Exact structural counts for this implementation. These are operation
		// counts, not timing predictions: DPF leaves, field transforms, network
		// rounds, and tensor products have backend- and field-dependent costs.
		struct CostEstimate
		{
			u64 mRingSize = 0;
			u64 mProductPointCount = 0;
			u64 mPositionGmwInstanceCount = 0;
			u64 mTensorProductCount = 0;
			u64 mInputTransformCount = 0;
			u64 mProductTransformCount = 0;
			u64 mRegularDpfPointCount = 0;
			u64 mRegularDpfLeafCount = 0;
			u64 mRevCuckooPointCount = 0;
			u64 mRevCuckooCachedLeafCount = 0;
			u64 mRevCuckooLeafVisitCount = 0;
			u64 mRevCuckooValueExpansionCount = 0;
			u64 mRevCuckooCriticalWaveCount = 0;
			BaseCorCount mInitialBaseCorCount;
			BaseCorCount mStationaryBaseCorCount;
		};

		using RegularBackend = SumDmpf<Ext, DpfCoeffCtx>;
#ifdef ENABLE_SPARSE_DPF
		// RevCuckoo caches the position-dependent leaf seeds. Each later expansion
		// maps one logical product polynomial's scalar extension-field coefficients
		// onto that setup, matching the RingLPN integration. Trace and Frobenius
		// bookkeeping remain outside RevCuckoo.
		using RevCuckooBackend = RevCuckooDmpf<Ext, DpfCoeffCtx>;
		using RevCuckooBackends = std::vector<RevCuckooBackend>;
		struct HybridBackend
		{
			RegularBackend mSmall;
			RevCuckooBackends mLarge;

			void clear()
			{
				mSmall.clear();
				for (auto& dpf : mLarge)
					dpf.clear();
				mLarge.clear();
			}
		};
		using DpfBackend = std::variant<RegularBackend, HybridBackend>;
#else
		using DpfBackend = std::variant<RegularBackend>;
#endif

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
				mDpfMode = std::exchange(source.mDpfMode, AnyFieldDpfMode::RegularDpf);
				mNoiseMode = std::exchange(source.mNoiseMode, AnyFieldNoiseMode::SingleUse);
				mCompressionFactor = std::exchange(source.mCompressionFactor, 0);
				mPointsPerBlock = std::exchange(source.mPointsPerBlock, 0);
				mWeight = std::exchange(source.mWeight, 0);
				mDimension = std::exchange(source.mDimension, 0);
				mRequestedOleCount = std::exchange(source.mRequestedOleCount, 0);
				mN = std::exchange(source.mN, 0);
				mBlockSize = std::exchange(source.mBlockSize, 0);
				mPublicSeed = std::exchange(source.mPublicSeed, block{});
				mPublicA = std::move(source.mPublicA);
				mPositionGmw = std::move(source.mPositionGmw);
				mPositionCircuit = std::move(source.mPositionCircuit);
				mPositionOleCount = std::exchange(source.mPositionOleCount, 0);
				mDpf = std::move(source.mDpf);
				mSendOts = std::move(source.mSendOts);
				mRecvOts = std::move(source.mRecvOts);
				mRecvChoices = std::move(source.mRecvChoices);
				mBaseCorsAvailable = std::exchange(source.mBaseCorsAvailable, false);
				mInstalledDpfSendOtCount = std::exchange(source.mInstalledDpfSendOtCount, 0);
				mInstalledDpfRecvOtCount = std::exchange(source.mInstalledDpfRecvOtCount, 0);
				mInitialBaseCorEstimate = std::exchange(
					source.mInitialBaseCorEstimate, BaseCorCount{});
				mStationaryBaseCorEstimate = std::exchange(
					source.mStationaryBaseCorEstimate, BaseCorCount{});
				mDpfOrder = std::move(source.mDpfOrder);
				mSparsePositions = std::move(source.mSparsePositions);
				mSparseCoefficients = std::move(source.mSparseCoefficients);
				mDpfValues = std::move(source.mDpfValues);
				mProductShares = std::move(source.mProductShares);
				mHasPositions = std::exchange(source.mHasPositions, false);
				mHasSetup = std::exchange(source.mHasSetup, false);

				source.mPublicA = {};
				source.mPositionGmw.clear();
				source.mPositionCircuit = {};
				source.mSendOts.clear();
				source.mRecvOts.clear();
				source.mRecvChoices.resize(0);
				source.mDpfOrder.clear();
				source.mSparsePositions.clear();
				source.mSparseCoefficients.clear();
				source.mDpfValues.clear();
				source.mProductShares.clear();
			}
			return *this;
		}

		void init(
			u64 partyIdx,
			u64 numOles,
			block publicSeed,
			AnyFieldDpfMode dpfMode = AnyFieldDpfMode::RegularDpf,
			AnyFieldNoiseMode noiseMode = AnyFieldNoiseMode::SingleUse,
			Ctx ctx = {})
		{
			if constexpr (requires { Params::compressionFactor; Params::pointsPerBlock; })
			{
				// Legacy test/benchmark policies select deliberately tiny insecure
				// layouts. They feed runtime state and do not specialize hot code.
				initImpl(
					partyIdx, numOles, publicSeed, dpfMode, noiseMode,
					Params::compressionFactor, Params::pointsPerBlock, false,
					std::move(ctx));
			}
			else
			{
				init(
					partyIdx, numOles, publicSeed, dpfMode, noiseMode,
					LpnParameterConfig{}, std::move(ctx));
			}
		}

		void init(
			u64 partyIdx,
			u64 numOles,
			block publicSeed,
			AnyFieldDpfMode dpfMode,
			AnyFieldNoiseMode noiseMode,
			LpnParameterConfig parameters,
			Ctx ctx = {})
		{
			initImpl(
				partyIdx, numOles, publicSeed, dpfMode, noiseMode,
				parameters.mCompressionFactor, 0, true,
				std::move(ctx));
		}

	private:
		void initImpl(
			u64 partyIdx,
			u64 numOles,
			block publicSeed,
			AnyFieldDpfMode dpfMode,
			AnyFieldNoiseMode noiseMode,
			u64 compressionFactor,
			u64 pointsPerBlock,
			bool enforceSecurity,
			Ctx ctx)
		{
			if (partyIdx > 1)
				throw std::invalid_argument("AnyFieldOle party index must be zero or one. " LOCATION);
			if (!numOles)
				throw std::invalid_argument("AnyFieldOle requires at least one requested OLE. " LOCATION);
			if (dpfMode != AnyFieldDpfMode::RegularDpf &&
				dpfMode != AnyFieldDpfMode::RevCuckoo)
				throw std::invalid_argument("AnyFieldOle DPF mode is invalid. " LOCATION);
			if (noiseMode != AnyFieldNoiseMode::SingleUse &&
				noiseMode != AnyFieldNoiseMode::Stationary)
				throw std::invalid_argument("AnyFieldOle noise mode is invalid. " LOCATION);
#ifndef ENABLE_SPARSE_DPF
			if (dpfMode == AnyFieldDpfMode::RevCuckoo)
				throw std::invalid_argument(
					"AnyFieldOle RevCuckoo mode requires ENABLE_SPARSE_DPF. " LOCATION);
#endif

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
			if (enforceSecurity && !compressionFactor)
				compressionFactor = selectAutomaticCompressionFactor(dpfMode, dimension);
			if (compressionFactor < 2 || compressionFactor > MaxCompressionFactor)
				throw std::invalid_argument(
					"AnyFieldOle compression factor must be in [2, 8]. " LOCATION);
			if (enforceSecurity)
			{
				const auto selected = lpnParameters::select(
					compressionFactor,
					static_cast<double>(Ctx::fieldCardinality),
					LpnCoefficientDistribution::NonZero);
				pointsPerBlock = lpnParameters::divCeil(
					selected.mNoiseWeight, BlockCount);
			}
			if (!pointsPerBlock)
				throw std::invalid_argument(
					"AnyFieldOle requires at least one point per regular block. " LOCATION);
			if (pointsPerBlock > std::numeric_limits<u64>::max() / BlockCount)
				throw std::length_error("AnyFieldOle noise weight overflows u64. " LOCATION);
			const auto weight = BlockCount * pointsPerBlock;
			if (enforceSecurity)
			{
				const auto selected = lpnParameters::select(
					compressionFactor,
					static_cast<double>(Ctx::fieldCardinality),
					LpnCoefficientDistribution::NonZero);
				if (weight < selected.mNoiseWeight)
					throw std::logic_error(
						"AnyFieldOle parameter policy is below its linear or decoding floor. " LOCATION);
				if (!lpnParameters::qaSdHasNoExpectedEvaluationPoint(
					compressionFactor,
					static_cast<double>(Ctx::fieldCardinality),
					Ctx::coordinateSize,
					dimension))
					throw std::invalid_argument(
						"AnyFieldOle compression factor is too small for the requested dimension under the QA-SD interpolation check. " LOCATION);
			}
			domain = Ctx::domainSize(dimension);
			if (domain < requestedRingSize)
				throw std::invalid_argument("AnyFieldOle request exceeds one secure expansion domain. " LOCATION);
			if (Ctx::coordinateBits * dimension >= 64)
				throw std::invalid_argument("AnyFieldOle binary DPF depth must be below 64. " LOCATION);

			if (weight > std::numeric_limits<u64>::max() / weight)
				throw std::length_error("AnyFieldOle points per product group overflow u64. " LOCATION);
			const auto pointsPerGroup = weight * weight;
			const auto groupCount = compressionFactor * compressionFactor * Ctx::extensionDegree;
			if (pointsPerGroup > std::numeric_limits<u64>::max() / groupCount)
				throw std::length_error("AnyFieldOle total point count overflows u64. " LOCATION);
			const auto pointCount = groupCount * pointsPerGroup;
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
			if (pointsPerBlock > blockSize)
				throw std::invalid_argument("AnyFieldOle regular block is too small for its points. " LOCATION);

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
					for (u64 polynomial = 1; polynomial < compressionFactor; ++polynomial)
						packed |= u32(coeffCtx.sample(publicPrng).index()) <<
							(polynomial * Ctx::fieldBits);
					output = static_cast<PackedPublic>(packed);
				}
			}
			else
			{
				if (publicCount > std::numeric_limits<u64>::max() / (compressionFactor - 1))
					throw std::length_error("AnyFieldOle public coefficient count overflows u64. " LOCATION);
				publicA.resize(publicCount * (compressionFactor - 1));
				for (u64 polynomial = 1; polynomial < compressionFactor; ++polynomial)
					for (u64 index = 0; index < publicCount; ++index)
						publicA[(polynomial - 1) * publicCount + index] = coeffCtx.sample(publicPrng);
			}

			clear();
			mCtx = std::move(ctx);
			mPartyIdx = partyIdx;
			mDpfMode = dpfMode;
			mNoiseMode = noiseMode;
			mCompressionFactor = compressionFactor;
			mPointsPerBlock = pointsPerBlock;
			mWeight = weight;
			mDimension = dimension;
			mRequestedOleCount = numOles;
			mN = domain;
			mBlockSize = blockSize;
			mPublicSeed = publicSeed;
			mPublicA = std::move(publicA);
			mPositionCircuit = std::move(positionCircuit);
			mPositionGmw = std::move(positionGmw);
			mPositionOleCount = positionOleCount;
			initDpfBackend();
			mInitialBaseCorEstimate = baseCorCountFor(false);
			mStationaryBaseCorEstimate = baseCorCountFor(true);
			buildDpfOrder();
		}

	public:
		bool isInitialized() const { return mN != 0; }
		bool hasSetup() const { return mHasSetup; }
		bool hasPositions() const { return mHasPositions; }
		AnyFieldDpfMode dpfMode() const { return mDpfMode; }
		AnyFieldNoiseMode noiseMode() const { return mNoiseMode; }
		u64 compressionFactor() const { return mCompressionFactor; }
		u64 noiseWeight() const { return mWeight; }
		u64 pointsPerBlock() const { return mPointsPerBlock; }

		CostEstimate costEstimate() const
		{
			if (!isInitialized())
				throw std::logic_error("AnyFieldOle::init must be called first. " LOCATION);

			CostEstimate result;
			result.mRingSize = mN;
			result.mProductPointCount = groupCount() * pointsPerGroup();
			result.mPositionGmwInstanceCount = positionInstanceCount();
			result.mTensorProductCount =
				leftCoefficientCount() * rightCoefficientCount();
			result.mInputTransformCount = mCompressionFactor;
			result.mProductTransformCount = groupCount();
			result.mInitialBaseCorCount = mInitialBaseCorEstimate;
			result.mStationaryBaseCorCount = mStationaryBaseCorEstimate;

			if (mDpfMode == AnyFieldDpfMode::RegularDpf)
			{
				result.mRegularDpfPointCount = result.mProductPointCount;
				result.mRegularDpfLeafCount =
					result.mRegularDpfPointCount * mBlockSize;
				return result;
			}

#ifdef ENABLE_SPARSE_DPF
			result.mRegularDpfPointCount = smallDpfPointCount();
			result.mRegularDpfLeafCount =
				result.mRegularDpfPointCount * mBlockSize;
			result.mRevCuckooPointCount =
				result.mProductPointCount - result.mRegularDpfPointCount;
			for (u64 pairCount = SmallPairCountLimit + 1;
				pairCount <= mCompressionFactor; ++pairCount)
			{
				const auto cachedLeaves =
					2 * revChannelCount(pairCount) * mN;
				const auto expansions = pairCount * Ctx::extensionDegree;
				result.mRevCuckooCachedLeafCount += cachedLeaves;
				result.mRevCuckooLeafVisitCount += cachedLeaves * expansions;
				result.mRevCuckooValueExpansionCount += expansions;
			}
			if (result.mRevCuckooValueExpansionCount)
				result.mRevCuckooCriticalWaveCount =
					mCompressionFactor * Ctx::extensionDegree;
#endif
			return result;
		}

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

			return baseCorCountFor(mHasPositions);
		}

		void setBaseCors(
			span<const std::array<block, 2>> sendOts,
			span<const block> recvOts,
			const BitVector& recvChoices,
			span<block> oleMult,
			span<block> oleAdd)
		{
			if (mHasSetup)
				throw std::logic_error(
					"AnyFieldOle cannot replace correlations while a seed is pending expansion. " LOCATION);
			const auto count = baseCorCount();
			if (sendOts.size() != count.mSendOtCount ||
				recvOts.size() != count.mRecvOtCount ||
				recvChoices.size() != count.mRecvOtCount)
				throw std::invalid_argument("AnyFieldOle base-OT count mismatch. " LOCATION);
			if (oleMult.size() != divCeil(count.mOleCount, 128) ||
				oleAdd.size() != divCeil(count.mOleCount, 128))
				throw std::invalid_argument("AnyFieldOle binary-OLE count mismatch. " LOCATION);
			setBaseCorsOwned(
				std::vector<std::array<block, 2>>(sendOts.begin(), sendOts.end()),
				std::vector<block>(recvOts.begin(), recvOts.end()),
				BitVector(recvChoices), oleMult, oleAdd);
		}

		// Consuming overload for large correlation batches. RevCuckoo can require
		// millions of base OTs, so retaining both the caller's vectors and an
		// internal copy needlessly doubles peak memory during installation.
		void setBaseCors(
			std::vector<std::array<block, 2>>&& sendOts,
			std::vector<block>&& recvOts,
			BitVector&& recvChoices,
			span<block> oleMult,
			span<block> oleAdd)
		{
			setBaseCorsOwned(
				std::move(sendOts), std::move(recvOts), std::move(recvChoices),
				oleMult, oleAdd);
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
					block(mCompressionFactor, mWeight),
					block(BlockCount, mPointsPerBlock),
					block(static_cast<u64>(mDpfMode), static_cast<u64>(mNoiseMode)),
					block(mHasPositions, 0)
				};
				std::vector<block> peerParams(localParams.size());
				co_await socket.send(coproto::copy(localParams));
				co_await socket.recv(peerParams);
				if (peerParams[0] != mPublicSeed ||
					peerParams[1] != block(mDimension, mRequestedOleCount) ||
					peerParams[2] != block(mN, 1 ^ mPartyIdx) ||
					peerParams[3] != block(Ctx::baseCharacteristic, Ctx::extensionDegree) ||
					peerParams[4] != block(mCompressionFactor, mWeight) ||
					peerParams[5] != block(BlockCount, mPointsPerBlock) ||
					peerParams[6] != block(
						static_cast<u64>(mDpfMode), static_cast<u64>(mNoiseMode)) ||
					peerParams[7] != block(mHasPositions, 0))
					throw std::invalid_argument(
						"AnyFieldOle peers initialized incompatible parameters. " LOCATION);

				if (!mHasPositions)
				{
					sampleSparsePositions(prng);
					std::vector<u64> pointShares;
					co_await makePointShares(pointShares, socket);
					std::vector<u64> orderedPoints(mDpfOrder.size());
					for (u64 i = 0; i < orderedPoints.size(); ++i)
						orderedPoints[i] = pointShares[mDpfOrder[i]];
					if (mDpfMode == AnyFieldDpfMode::RegularDpf)
					{
						auto& dpf = std::get<RegularBackend>(mDpf);
						if (mTimer)
							dpf.setTimer(*mTimer);
						MatrixView<const u64> points(
							orderedPoints.data(), dpfSetCount(), pointsPerDpfSet());
						co_await dpf.setPoints(points, prng, socket);
					}
#ifdef ENABLE_SPARSE_DPF
					else
					{
						auto& hybrid = std::get<HybridBackend>(mDpf);
						if (mTimer)
							hybrid.mSmall.setTimer(*mTimer);
						MatrixView<const u64> smallPoints(
							orderedPoints.data(), smallDpfSetCount(), pointsPerDpfSet());
						co_await hybrid.mSmall.setPoints(smallPoints, prng, socket);

						std::vector<coproto::Socket> sockets(revCountClassCount());
						std::vector<PRNG> prngs(revCountClassCount());
						std::vector<macoro::task<>> tasks(revCountClassCount());
						for (u64 pairCount = SmallPairCountLimit + 1;
							pairCount <= mCompressionFactor; ++pairCount)
						{
							const auto instance = revCountClassIndex(pairCount);
							auto& dpf = hybrid.mLarge[instance];
							if (mTimer)
								dpf.setTimer(*mTimer);
							const auto pointCount = revPointsPerDpfSet(pairCount);
							MatrixView<const u64> points(
								orderedPoints.data() + revClassPointOffset(pairCount),
								revSetCount(pairCount), pointCount);
							sockets[instance] = socket.fork();
							prngs[instance] = prng.fork();
							tasks[instance] = dpf.setPoints(
								points, prngs[instance], sockets[instance]);
						}
						auto results = co_await macoro::when_all_ready(std::move(tasks));
						for (auto& result : results)
							result.result();
						u64 realLeafCount = 0;
						for (auto& dpf : hybrid.mLarge)
							realLeafCount += dpf.realLeafCount();
						if (realLeafCount != 2 * largeRevChannelCount() * mN)
							throw std::runtime_error(
								"AnyFieldOle RevCuckoo built the wrong number of real leaves. " LOCATION);
					}
#endif
					mHasPositions = true;
				}

				sampleSparseCoefficients(prng);

				std::vector<Ext> productShares(leftCoefficientCount() * rightCoefficientCount());
				co_await tensorCoefficients(productShares, prng, socket);
				if (mDpfMode == AnyFieldDpfMode::RegularDpf)
					fillRegularDpfValues(productShares);
				else
				{
					fillSmallDpfValues(productShares);
					mProductShares = std::move(productShares);
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
		// returned. SingleUse consumes both the coefficient and position state;
		// Stationary consumes only the fresh coefficient/tensor state.
		macoro::task<> expand(
			span<Base> x,
			span<Base> z,
			PRNG& prng,
			coproto::Socket& socket)
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
				for (u64 polynomial = 0; polynomial < mCompressionFactor; ++polynomial)
				{
					std::fill(work.begin(), work.end(), Ext::zero());
					const auto coefficientOffset = polynomial * mWeight;
					for (u64 point = 0; point < mWeight; ++point)
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

				std::fill(work.begin(), work.end(), Ext::zero());
				if (mDpfMode == AnyFieldDpfMode::RegularDpf)
				{
					u64 nextSet = 0;
					u64 setLeafCount = 0;
					auto& dpf = std::get<RegularBackend>(mDpf);
					if (mTimer)
						dpf.setTimer(*mTimer);
					co_await dpf.expand(
						mDpfValues, prng, socket,
						[&](u64 set, u64 leaf, const auto& value) {
							if (set != nextSet || leaf >= mBlockSize)
								throw std::runtime_error(
									"AnyFieldOle DPF emitted an invalid leaf sequence. " LOCATION);
							const auto blockIndex = set % BlockCount;
							work[blockIndex + BlockCount * leaf] += value;
							if (++setLeafCount == mBlockSize)
							{
								setLeafCount = 0;
								++nextSet;
								if (nextSet % BlockCount == 0)
								{
									const auto group = nextSet / BlockCount - 1;
									accumulateProductGroup(
										group, publicCount, work, traceFactors, z);
									std::fill(work.begin(), work.end(), Ext::zero());
								}
							}
						},
						mCtx.dpfCoeffCtx());
					if (nextSet != dpfSetCount() || setLeafCount)
						throw std::runtime_error(
							"AnyFieldOle DPF expansion ended early. " LOCATION);
				}
				else
				{
#ifdef ENABLE_SPARSE_DPF
					auto& hybrid = std::get<HybridBackend>(mDpf);

					// Low-multiplicity channels are cheaper as one ordinary sum-DPF.
					std::fill(work.begin(), work.end(), Ext::zero());
					u64 nextSmallSet = 0;
					u64 smallSetLeafCount = 0;
					if (mTimer)
						hybrid.mSmall.setTimer(*mTimer);
					auto smallSocket = socket.fork();
					auto smallPrng = prng.fork();
					auto smallTask = hybrid.mSmall.expand(
						mDpfValues, smallPrng, smallSocket,
						[&](u64 set, u64 leaf, const auto& value) {
							if (set != nextSmallSet || leaf >= mBlockSize)
								throw std::runtime_error(
									"AnyFieldOle small DPF emitted an invalid leaf sequence. " LOCATION);
							const auto region = set % BlockCount;
							work[region + BlockCount * leaf] += value;
							if (++smallSetLeafCount == mBlockSize)
							{
								smallSetLeafCount = 0;
								++nextSmallSet;
								if (nextSmallSet % BlockCount == 0)
								{
									const auto group = smallGroup(
										nextSmallSet / BlockCount - 1);
									accumulateProductGroup(
										group, publicCount, work, traceFactors, z);
									std::fill(work.begin(), work.end(), Ext::zero());
								}
							}
						},
						mCtx.dpfCoeffCtx());
					// RevCuckoo natively batches sets with an equal point count. Run one
					// scalar product from every count class in the same wave; the first
					// wave also carries the ordinary DPF above. The two symmetric channels
					// of a class are emitted by the same expansion.
					std::vector<std::vector<Ext>> values(revCountClassCount());
					std::vector<std::vector<Ext>> productWork(revCountClassCount());
					for (u64 pairCount = SmallPairCountLimit + 1;
						pairCount <= mCompressionFactor; ++pairCount)
						productWork[revCountClassIndex(pairCount)].resize(
							revChannelCount(pairCount) * mN);

					const auto waveCount = mCompressionFactor * Ctx::extensionDegree;
					for (u64 wave = 0; wave < waveCount; ++wave)
					{
						std::vector<coproto::Socket> sockets(revCountClassCount());
						std::vector<PRNG> prngs(revCountClassCount());
						std::vector<macoro::task<>> tasks;
						std::vector<u64> active;
						std::vector<u64> nextSet(revCountClassCount());
						std::vector<u64> setLeafCount(revCountClassCount());
						tasks.reserve(revCountClassCount() + 1);
						active.reserve(revCountClassCount());
						if (wave == 0)
							tasks.push_back(std::move(smallTask));
						for (u64 pairCount = SmallPairCountLimit + 1;
							pairCount <= mCompressionFactor; ++pairCount)
						{
							if (wave >= pairCount * Ctx::extensionDegree)
								continue;
							const auto instance = revCountClassIndex(pairCount);
							auto& dpf = hybrid.mLarge[instance];
							if (mTimer)
								dpf.setTimer(*mTimer);
							fillRevValues(pairCount, wave, values[instance]);
							sockets[instance] = socket.fork();
							prngs[instance] = prng.fork();
							active.push_back(instance);
							tasks.push_back(dpf.expand(
								values[instance], prngs[instance], sockets[instance],
								[&, instance, pairCount](u64 set, u64 leaf, const auto& value) {
									if (set != nextSet[instance] || leaf >= mBlockSize)
										throw std::runtime_error(
											"AnyFieldOle RevCuckoo emitted an invalid set sequence. " LOCATION);
									const auto channelSlot = set / BlockCount;
									const auto region = set % BlockCount;
									productWork[instance][channelSlot * mN +
										region + BlockCount * leaf] = value;
									if (++setLeafCount[instance] == mBlockSize)
									{
										setLeafCount[instance] = 0;
										++nextSet[instance];
									}
								},
								mCtx.dpfCoeffCtx()));
						}
						auto results = co_await macoro::when_all_ready(std::move(tasks));
						for (auto& result : results)
							result.result();
						if (wave == 0 &&
							(nextSmallSet != smallDpfSetCount() || smallSetLeafCount))
							throw std::runtime_error(
								"AnyFieldOle small DPF expansion ended early. " LOCATION);
						for (auto instance : active)
						{
							const auto pairCount = instance + SmallPairCountLimit + 1;
							if (nextSet[instance] != revSetCount(pairCount) ||
								setLeafCount[instance])
								throw std::runtime_error(
									"AnyFieldOle RevCuckoo expansion ended early. " LOCATION);
							for (u64 channelSlot = 0;
								channelSlot < revChannelCount(pairCount); ++channelSlot)
							{
								const auto channel = channelSlot == 0 ?
									pairCount - 1 : revProductChannelCount() - pairCount;
								const auto group = revGroup(channel, wave);
								accumulateProductGroup(
									group, publicCount,
									span<Ext>(productWork[instance]).subspan(
										channelSlot * mN, mN),
									traceFactors, z);
							}
						}
					}
#else
					throw std::logic_error(
						"AnyFieldOle RevCuckoo mode requires ENABLE_SPARSE_DPF. " LOCATION);
#endif
				}

				clearExpansionState();
				if (mNoiseMode == AnyFieldNoiseMode::SingleUse)
					clearPositionState();
			}
			catch (...)
			{
				clearExpansionState();
				clearPositionState();
				throw;
			}
			co_return;
		}

		void clear()
		{
			clearBaseCors();
			clearExpansionState();
			mSparsePositions.clear();
			mHasPositions = false;
			std::visit([](auto& dpf) { dpf.clear(); }, mDpf);
			mDpfOrder.clear();
			mPartyIdx = 0;
			mDpfMode = AnyFieldDpfMode::RegularDpf;
			mNoiseMode = AnyFieldNoiseMode::SingleUse;
			mCompressionFactor = 0;
			mPointsPerBlock = 0;
			mWeight = 0;
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
			mInitialBaseCorEstimate = {};
			mStationaryBaseCorEstimate = {};
		}

	private:
		Ctx mCtx;
		u64 mPartyIdx = 0;
		AnyFieldDpfMode mDpfMode = AnyFieldDpfMode::RegularDpf;
		AnyFieldNoiseMode mNoiseMode = AnyFieldNoiseMode::SingleUse;
		u64 mCompressionFactor = 0;
		u64 mPointsPerBlock = 0;
		u64 mWeight = 0;
		u64 mDimension = 0;
		u64 mRequestedOleCount = 0;
		u64 mN = 0;
		u64 mBlockSize = 0;
		block mPublicSeed{};
		std::vector<PackedPublic> mPublicA;

		Gmw mPositionGmw;
		BetaCircuit mPositionCircuit;
		u64 mPositionOleCount = 0;
		DpfBackend mDpf;
		std::vector<std::array<block, 2>> mSendOts;
		std::vector<block> mRecvOts;
		BitVector mRecvChoices;
		bool mBaseCorsAvailable = false;
		u64 mInstalledDpfSendOtCount = 0;
		u64 mInstalledDpfRecvOtCount = 0;
		BaseCorCount mInitialBaseCorEstimate;
		BaseCorCount mStationaryBaseCorEstimate;

		std::vector<u64> mDpfOrder;
		std::vector<u64> mSparsePositions;
		std::vector<Ext> mSparseCoefficients;
		std::vector<Ext> mDpfValues;
		std::vector<Ext> mProductShares;
		bool mHasPositions = false;
		bool mHasSetup = false;

		static u64 selectAutomaticCompressionFactor(
			AnyFieldDpfMode dpfMode,
			u64 dimension)
		{
			u64 bestCompressionFactor = 0;
			u64 bestLeafCoefficient = std::numeric_limits<u64>::max();
			for (u64 compressionFactor = 2;
				compressionFactor <= MaxCompressionFactor; ++compressionFactor)
			{
				if (!lpnParameters::qaSdHasNoExpectedEvaluationPoint(
					compressionFactor,
					static_cast<double>(Ctx::fieldCardinality),
					Ctx::coordinateSize,
					dimension))
					continue;

				const auto selected = lpnParameters::select(
					compressionFactor,
					static_cast<double>(Ctx::fieldCardinality),
					LpnCoefficientDistribution::NonZero);
				const auto pointsPerBlock = lpnParameters::divCeil(
					selected.mNoiseWeight, BlockCount);
				const auto weight = BlockCount * pointsPerBlock;
				u64 leafCoefficient;
				if (dpfMode == AnyFieldDpfMode::RegularDpf)
				{
					leafCoefficient = compressionFactor * compressionFactor *
						weight * weight / BlockCount;
				}
				else
				{
					u64 smallProductGroups = 0;
					u64 largeWeightedChannels = 0;
					const auto channelCount = 2 * compressionFactor - 1;
					for (u64 channel = 0; channel < channelCount; ++channel)
					{
						const auto pairCount = channel < compressionFactor ?
							channel + 1 : channelCount - channel;
						if (pairCount <= SmallPairCountLimit)
							smallProductGroups += pairCount;
						else
							largeWeightedChannels += pairCount;
					}
					leafCoefficient = smallProductGroups * weight * weight /
						BlockCount + 2 * largeWeightedChannels;
				}

				// Prefer lower c on an exact tie: it uses fewer transforms and fewer
				// RevCuckoo value-expansion waves.
				if (leafCoefficient < bestLeafCoefficient)
				{
					bestLeafCoefficient = leafCoefficient;
					bestCompressionFactor = compressionFactor;
				}
			}
			if (!bestCompressionFactor)
				throw std::invalid_argument(
					"AnyFieldOle has no secure compression factor for the requested dimension. " LOCATION);
			return bestCompressionFactor;
		}

		u64 groupCount() const
		{
			return mCompressionFactor * mCompressionFactor * Ctx::extensionDegree;
		}
		u64 dpfSetCount() const { return groupCount() * BlockCount; }
		u64 pointsPerDpfSet() const
		{
			return BlockCount * mPointsPerBlock * mPointsPerBlock;
		}
		u64 revProductChannelCount() const { return 2 * mCompressionFactor - 1; }
		u64 revCountClassCount() const
		{
			return mCompressionFactor > SmallPairCountLimit ?
				mCompressionFactor - SmallPairCountLimit : 0;
		}
		u64 pointsPerGroup() const { return mWeight * mWeight; }
		u64 revPairCount(u64 channel) const
		{
			return channel < mCompressionFactor ?
				channel + 1 : revProductChannelCount() - channel;
		}
		bool useSmallDpf(u64 channel) const
		{
			return revPairCount(channel) <= SmallPairCountLimit;
		}
		u64 smallProductGroupCount() const
		{
			u64 result = 0;
			for (u64 group = 0; group < groupCount(); ++group)
			{
				const auto pair = group % (mCompressionFactor * mCompressionFactor);
				const auto channel = pair / mCompressionFactor + pair % mCompressionFactor;
				result += useSmallDpf(channel);
			}
			return result;
		}
		u64 smallDpfSetCount() const
		{
			return smallProductGroupCount() * BlockCount;
		}
		u64 smallDpfPointCount() const
		{
			return smallDpfSetCount() * pointsPerDpfSet();
		}
		u64 revPointsPerDpfSet(u64 pairCount) const
		{
			return pairCount * Ctx::extensionDegree *
				BlockCount * mPointsPerBlock * mPointsPerBlock;
		}
		u64 revChannelCount(u64 pairCount) const
		{
			return pairCount == mCompressionFactor ? 1 : 2;
		}
		u64 revSetCount(u64 pairCount) const
		{
			return revChannelCount(pairCount) * BlockCount;
		}
		u64 revCountClassIndex(u64 pairCount) const
		{
			return pairCount - (SmallPairCountLimit + 1);
		}
		u64 revClassSetOffset(u64 pairCount) const
		{
			u64 result = smallDpfSetCount();
			for (u64 previous = SmallPairCountLimit + 1;
				previous < pairCount; ++previous)
				result += revSetCount(previous);
			return result;
		}
		u64 hybridSetCount() const
		{
			u64 result = smallDpfSetCount();
			for (u64 pairCount = SmallPairCountLimit + 1;
				pairCount <= mCompressionFactor; ++pairCount)
				result += revSetCount(pairCount);
			return result;
		}
		u64 largeRevChannelCount() const
		{
			u64 result = 0;
			for (u64 pairCount = SmallPairCountLimit + 1;
				pairCount <= mCompressionFactor; ++pairCount)
				result += revChannelCount(pairCount);
			return result;
		}
		u64 revClassPointOffset(u64 pairCount) const
		{
			u64 result = smallDpfPointCount();
			for (u64 previous = SmallPairCountLimit + 1;
				previous < pairCount; ++previous)
				result += revSetCount(previous) * revPointsPerDpfSet(previous);
			return result;
		}
		u64 revSetIndex(u64 channel, u64 region) const
		{
			const auto pairCount = revPairCount(channel);
			const auto firstChannel = pairCount - 1;
			return (channel == firstChannel ? 0 : BlockCount) + region;
		}
		u64 revGroup(u64 channel, u64 groupSlot) const
		{
			const auto pairCount = revPairCount(channel);
			const auto power = groupSlot / pairCount;
			const auto pairSlot = groupSlot % pairCount;
			const auto firstLeft = channel < mCompressionFactor ?
				0 : channel - (mCompressionFactor - 1);
			const auto leftPolynomial = firstLeft + pairSlot;
			const auto rightPolynomial = channel - leftPolynomial;
			return power * mCompressionFactor * mCompressionFactor +
				leftPolynomial * mCompressionFactor + rightPolynomial;
		}
		u64 smallGroup(u64 ordinal) const
		{
			for (u64 group = 0; group < groupCount(); ++group)
			{
				const auto pair = group % (mCompressionFactor * mCompressionFactor);
				const auto channel = pair / mCompressionFactor + pair % mCompressionFactor;
				if (useSmallDpf(channel) && ordinal-- == 0)
					return group;
			}
			throw std::logic_error("AnyFieldOle small DPF group is invalid. " LOCATION);
		}
		u64 positionInstanceCount() const
		{
			const auto points = groupCount() * pointsPerGroup();
			return PowerOfTwoCoordinates ? points * localDimensions() : points;
		}
		u64 leftCoefficientCount() const { return mCompressionFactor * mWeight; }
		u64 rightCoefficientCount() const
		{
			return mCompressionFactor * Ctx::extensionDegree * mWeight;
		}

		struct DpfBaseOtCount
		{
			u64 mSendCount = 0;
			u64 mRecvCount = 0;
		};

		BaseCorCount baseCorCountFor(bool positionsCached) const
		{
			BaseCorCount result;
			const auto dpfCount = dpfBaseOtCount(positionsCached);
			result.mSendOtCount = dpfCount.mSendCount;
			result.mRecvOtCount = dpfCount.mRecvCount;

			const auto tensorOtCount = rightCoefficientCount() *
				mCtx.dpfCoeffCtx().template bitSize<Ext>();
			if ((mPartyIdx ? result.mRecvOtCount : result.mSendOtCount) >
				std::numeric_limits<u64>::max() - tensorOtCount)
				throw std::length_error("AnyFieldOle base-OT count overflows u64. " LOCATION);
			if (mPartyIdx)
				result.mRecvOtCount += tensorOtCount;
			else
				result.mSendOtCount += tensorOtCount;

			result.mOleCount = positionsCached ? 0 : mPositionOleCount;
			return result;
		}

		void setBaseCorsOwned(
			std::vector<std::array<block, 2>>&& newSendOts,
			std::vector<block>&& newRecvOts,
			BitVector&& newRecvChoices,
			span<block> oleMult,
			span<block> oleAdd)
		{
			if (mHasSetup)
				throw std::logic_error(
					"AnyFieldOle cannot replace correlations while a seed is pending expansion. " LOCATION);
			const auto count = baseCorCount();
			if (newSendOts.size() != count.mSendOtCount ||
				newRecvOts.size() != count.mRecvOtCount ||
				newRecvChoices.size() != count.mRecvOtCount)
				throw std::invalid_argument("AnyFieldOle base-OT count mismatch. " LOCATION);
			if (oleMult.size() != divCeil(count.mOleCount, 128) ||
				oleAdd.size() != divCeil(count.mOleCount, 128))
				throw std::invalid_argument("AnyFieldOle binary-OLE count mismatch. " LOCATION);

			Gmw newPositionGmw;
			if (!mHasPositions)
			{
				newPositionGmw.init(
					mPartyIdx, positionInstanceCount(), mPositionCircuit);
				newPositionGmw.setOle(oleMult, oleAdd);
			}

			const auto dpfCount = dpfBaseOtCount();
			if (dpfCount.mSendCount || dpfCount.mRecvCount)
			{
				if (mDpfMode == AnyFieldDpfMode::RegularDpf)
				{
					auto& dpf = std::get<RegularBackend>(mDpf);
					dpf.setBaseOts(
						span<const std::array<block, 2>>(newSendOts).subspan(
							0, dpfCount.mSendCount),
						span<const block>(newRecvOts).subspan(0, dpfCount.mRecvCount),
						newRecvChoices.subvec(0, dpfCount.mRecvCount));
				}
#ifdef ENABLE_SPARSE_DPF
				else
				{
					u64 sendOffset = 0;
					u64 recvOffset = 0;
					auto& hybrid = std::get<HybridBackend>(mDpf);
					const auto smallCount = hybrid.mSmall.baseOtCount();
					hybrid.mSmall.setBaseOts(
						span<const std::array<block, 2>>(newSendOts).subspan(
							sendOffset, smallCount.mSendCount),
						span<const block>(newRecvOts).subspan(
							recvOffset, smallCount.mRecvCount),
						newRecvChoices.subvec(recvOffset, smallCount.mRecvCount));
					sendOffset += smallCount.mSendCount;
					recvOffset += smallCount.mRecvCount;
					for (auto& dpf : hybrid.mLarge)
					{
						if (mHasPositions)
							break;
						const auto subCount = dpf.baseOtCount();
						dpf.setBaseOts(
							span<const std::array<block, 2>>(newSendOts).subspan(
								sendOffset, subCount.mSendCount),
							span<const block>(newRecvOts).subspan(
								recvOffset, subCount.mRecvCount),
							newRecvChoices.subvec(recvOffset, subCount.mRecvCount));
						sendOffset += subCount.mSendCount;
						recvOffset += subCount.mRecvCount;
					}
					if (sendOffset != dpfCount.mSendCount || recvOffset != dpfCount.mRecvCount)
						throw std::logic_error(
							"AnyFieldOle RevCuckoo base-OT slicing mismatch. " LOCATION);
				}
#endif
			}

			mSendOts = std::move(newSendOts);
			mRecvOts = std::move(newRecvOts);
			mRecvChoices = std::move(newRecvChoices);
			mPositionGmw = std::move(newPositionGmw);
			mInstalledDpfSendOtCount = dpfCount.mSendCount;
			mInstalledDpfRecvOtCount = dpfCount.mRecvCount;
			mBaseCorsAvailable = true;
		}

		DpfBaseOtCount dpfBaseOtCount() const
		{
			return dpfBaseOtCount(mHasPositions);
		}

		DpfBaseOtCount dpfBaseOtCount(bool positionsCached) const
		{
			if (mDpfMode == AnyFieldDpfMode::RegularDpf)
			{
				const auto count = std::get<RegularBackend>(mDpf).baseOtCount();
				return { count.mSendCount, count.mRecvCount };
			}
#ifdef ENABLE_SPARSE_DPF
			const auto& hybrid = std::get<HybridBackend>(mDpf);
			const auto smallCount = hybrid.mSmall.baseOtCount();
			DpfBaseOtCount result{ smallCount.mSendCount, smallCount.mRecvCount };
			if (positionsCached)
				return result;
			for (const auto& dpf : hybrid.mLarge)
			{
				const auto count = dpf.baseOtCount();
				result.mSendCount += count.mSendCount;
				result.mRecvCount += count.mRecvCount;
			}
			return result;
#else
			throw std::logic_error(
				"AnyFieldOle RevCuckoo mode requires ENABLE_SPARSE_DPF. " LOCATION);
#endif
		}

		void initDpfBackend()
		{
			if (mDpfMode == AnyFieldDpfMode::RegularDpf)
			{
				mDpf = RegularBackend{};
				std::get<RegularBackend>(mDpf).init(
					mPartyIdx, mBlockSize, pointsPerDpfSet(), dpfSetCount(),
					mCtx.dpfCoeffCtx());
				return;
			}
#ifdef ENABLE_SPARSE_DPF
			mDpf = HybridBackend{};
			auto& hybrid = std::get<HybridBackend>(mDpf);
			hybrid.mSmall.init(
				mPartyIdx, mBlockSize, pointsPerDpfSet(), smallDpfSetCount(),
				mCtx.dpfCoeffCtx());
			hybrid.mLarge.resize(revCountClassCount());
			for (u64 pairCount = SmallPairCountLimit + 1;
				pairCount <= mCompressionFactor; ++pairCount)
				hybrid.mLarge[revCountClassIndex(pairCount)].init(
					mPartyIdx,
					revPointsPerDpfSet(pairCount),
					revSetCount(pairCount),
					mBlockSize,
					2,
					2,
					40,
					mCtx.dpfCoeffCtx().template characteristicTwo<Ext>());
#else
			throw std::logic_error(
				"AnyFieldOle RevCuckoo mode requires ENABLE_SPARSE_DPF. " LOCATION);
#endif
		}

		void clearBaseCors()
		{
			// These correlations are one-shot, and setBaseCors builds fresh
			// replacement storage. Release their capacity once setup consumes them.
			mSendOts = {};
			mRecvOts = {};
			mRecvChoices = {};
			mPositionGmw.clear();
			mInstalledDpfSendOtCount = 0;
			mInstalledDpfRecvOtCount = 0;
			mBaseCorsAvailable = false;
		}

		void clearExpansionState()
		{
			mSparseCoefficients.clear();
			mDpfValues.clear();
			mProductShares.clear();
			mHasSetup = false;
		}

		void clearPositionState()
		{
			mSparsePositions.clear();
			mHasPositions = false;
			std::visit([](auto& dpf) { dpf.clear(); }, mDpf);
			initDpfBackend();
		}

		void sampleSparsePositions(PRNG& prng)
		{
			mSparsePositions.resize(leftCoefficientCount());
			for (u64 polynomial = 0; polynomial < mCompressionFactor; ++polynomial)
			{
				const auto polynomialOffset = polynomial * mWeight;
				for (u64 blockIndex = 0; blockIndex < BlockCount; ++blockIndex)
				{
					const auto blockOffset = polynomialOffset + blockIndex * mPointsPerBlock;
					for (u64 slot = 0; slot < mPointsPerBlock; ++slot)
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
					}
				}
			}
		}

		void sampleSparseCoefficients(PRNG& prng)
		{
			mSparseCoefficients.resize(leftCoefficientCount());
			auto coeffCtx = mCtx.dpfCoeffCtx();
			for (auto& coefficient : mSparseCoefficients)
				coefficient = coeffCtx.sampleNonZero(prng);
		}

		macoro::task<> tensorCoefficients(
			span<Ext> productShares,
			PRNG& prng,
			coproto::Socket& socket)
		{
			if (productShares.size() != leftCoefficientCount() * rightCoefficientCount())
				throw std::invalid_argument("AnyFieldOle tensor output has the wrong size. " LOCATION);

			if (mPartyIdx)
			{
				std::vector<Ext> right(rightCoefficientCount());
				for (u64 polynomial = 0; polynomial < mCompressionFactor; ++polynomial)
					for (u64 power = 0; power < Ctx::extensionDegree; ++power)
						for (u64 i = 0; i < mWeight; ++i)
							right[(Ctx::extensionDegree * polynomial + power) * mWeight + i] =
								mCtx.frobenius(mSparseCoefficients[polynomial * mWeight + i], power);

				auto tensorOts = span<block>(mRecvOts).subspan(mInstalledDpfRecvOtCount);
				BitVector choices = mRecvChoices.subvec(
					mInstalledDpfRecvOtCount, tensorOts.size());
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
				auto tensorOts = span<std::array<block, 2>>(mSendOts).subspan(
					mInstalledDpfSendOtCount);
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
			const auto pointCount = groupCount() * pointsPerGroup();
			const auto positionInstances = positionInstanceCount();
			std::vector<u64> localPositions(positionInstances);
			for (u64 group = 0; group < groupCount(); ++group)
			{
				const auto power = group / (mCompressionFactor * mCompressionFactor);
				const auto pair = group % (mCompressionFactor * mCompressionFactor);
				const auto leftPolynomial = pair / mCompressionFactor;
				const auto rightPolynomial = pair % mCompressionFactor;
				for (u64 left = 0; left < mWeight; ++left)
				{
					const auto leftPosition =
						mSparsePositions[leftPolynomial * mWeight + left];
					for (u64 right = 0; right < mWeight; ++right)
					{
						const auto rightPosition =
							mSparsePositions[rightPolynomial * mWeight + right];
						const auto point = group * pointsPerGroup() + left * mWeight + right;
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
			return point / mPointsPerBlock + BlockCount * localPosition;
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
			const auto power = group / (mCompressionFactor * mCompressionFactor);
			auto leftBlock = leftPoint / mPointsPerBlock;
			auto rightBlock = rightPoint / mPointsPerBlock;
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

		void buildDpfOrder()
		{
			const auto revMode = mDpfMode == AnyFieldDpfMode::RevCuckoo;
			mDpfOrder.resize(groupCount() * pointsPerGroup());
			std::vector<u64> next(revMode ? hybridSetCount() : dpfSetCount());
			u64 smallOrdinal = 0;
			for (u64 group = 0; group < groupCount(); ++group)
			{
				const auto pair = group % (mCompressionFactor * mCompressionFactor);
				const auto leftPolynomial = pair / mCompressionFactor;
				const auto rightPolynomial = pair % mCompressionFactor;
				const auto productChannel = leftPolynomial + rightPolynomial;
				const auto small = revMode && useSmallDpf(productChannel);
				for (u64 left = 0; left < mWeight; ++left)
					for (u64 right = 0; right < mWeight; ++right)
					{
						const auto region = productBlock(group, left, right);
						u64 set;
						u64 capacity;
						u64 targetOffset;
						if (!revMode)
						{
							set = group * BlockCount + region;
							capacity = pointsPerDpfSet();
							targetOffset = set * capacity;
						}
						else if (small)
						{
							set = smallOrdinal * BlockCount + region;
							capacity = pointsPerDpfSet();
							targetOffset = set * capacity;
						}
						else
						{
							const auto pairCount = revPairCount(productChannel);
							const auto classSet = revSetIndex(productChannel, region);
							set = revClassSetOffset(pairCount) + classSet;
							capacity = revPointsPerDpfSet(pairCount);
							targetOffset = revClassPointOffset(pairCount) +
								classSet * capacity;
						}
						if (next[set] >= capacity)
							throw std::logic_error(
								"AnyFieldOle product block capacity is too small. " LOCATION);
						const auto target = targetOffset + next[set]++;
						mDpfOrder[target] =
							group * pointsPerGroup() + left * mWeight + right;
					}
				if (small)
					++smallOrdinal;
			}
			if (mDpfMode == AnyFieldDpfMode::RegularDpf)
				for (auto count : next)
					if (count != pointsPerDpfSet())
						throw std::logic_error(
							"AnyFieldOle product blocks are not regular. " LOCATION);
			if (revMode)
			{
				if (smallOrdinal != smallProductGroupCount())
					throw std::logic_error(
						"AnyFieldOle small DPF group count is invalid. " LOCATION);
				for (u64 set = 0; set < smallDpfSetCount(); ++set)
					if (next[set] != pointsPerDpfSet())
						throw std::logic_error(
							"AnyFieldOle small DPF product block is invalid. " LOCATION);
				for (u64 pairCount = SmallPairCountLimit + 1;
					pairCount <= mCompressionFactor; ++pairCount)
					for (u64 classSet = 0; classSet < revSetCount(pairCount); ++classSet)
						if (next[revClassSetOffset(pairCount) + classSet] !=
							revPointsPerDpfSet(pairCount))
							throw std::logic_error(
								"AnyFieldOle RevCuckoo product block is invalid. " LOCATION);
			}
		}

		Ext productShare(span<const Ext> productShares, u64 source) const
		{
			const auto group = source / pointsPerGroup();
			const auto point = source % pointsPerGroup();
			const auto left = point / mWeight;
			const auto right = point % mWeight;
			const auto power = group / (mCompressionFactor * mCompressionFactor);
			const auto pair = group % (mCompressionFactor * mCompressionFactor);
			const auto leftPolynomial = pair / mCompressionFactor;
			const auto rightPolynomial = pair % mCompressionFactor;
			const auto leftOffset = leftPolynomial * mWeight;
			const auto rightOffset =
				(Ctx::extensionDegree * rightPolynomial + power) * mWeight;
			return productShares[
				(leftOffset + left) * rightCoefficientCount() + rightOffset + right];
		}

		void fillDpfValues(span<const Ext> productShares, u64 pointCount)
		{
			mDpfValues.resize(pointCount);
			for (u64 target = 0; target < pointCount; ++target)
				mDpfValues[target] = productShare(productShares, mDpfOrder[target]);
		}

		void fillRegularDpfValues(span<const Ext> productShares)
		{
			fillDpfValues(productShares, mDpfOrder.size());
		}

		void fillSmallDpfValues(span<const Ext> productShares)
		{
			fillDpfValues(productShares, smallDpfPointCount());
		}

#ifdef ENABLE_SPARSE_DPF
		void fillRevValues(
			u64 pairCount,
			u64 groupSlot,
			std::vector<Ext>& dpfValues)
		{
			if (mProductShares.size() != leftCoefficientCount() * rightCoefficientCount())
				throw std::logic_error(
					"AnyFieldOle RevCuckoo tensor state is missing. " LOCATION);
			const auto pointCount = revPointsPerDpfSet(pairCount);
			const auto setCount = revSetCount(pairCount);
			dpfValues.resize(setCount * pointCount);
			for (u64 set = 0; set < setCount; ++set)
			{
				const auto channelSlot = set / BlockCount;
				const auto channel = channelSlot == 0 ?
					pairCount - 1 : revProductChannelCount() - pairCount;
				const auto group = revGroup(channel, groupSlot);
				const auto orderOffset = revClassPointOffset(pairCount) + set * pointCount;
				const auto valueOffset = set * pointCount;
				for (u64 target = 0; target < pointCount; ++target)
				{
					const auto source = mDpfOrder[orderOffset + target];
					dpfValues[valueOffset + target] =
						source / pointsPerGroup() == group ?
						productShare(mProductShares, source) : Ext::zero();
				}
			}
		}
#endif

		void accumulateProductGroup(
			u64 group,
			u64 publicCount,
			span<Ext> work,
			const std::array<std::array<Ext, Ctx::extensionDegree>,
				Ctx::extensionDegree>& traceFactors,
			span<Base> z)
		{
			const auto frobeniusPower = group / (mCompressionFactor * mCompressionFactor);
			const auto pair = group % (mCompressionFactor * mCompressionFactor);
			accumulateProductPair(
				frobeniusPower,
				pair / mCompressionFactor,
				pair % mCompressionFactor,
				publicCount, work, traceFactors, z);
		}

		void accumulateProductPair(
			u64 frobeniusPower,
			u64 leftPolynomial,
			u64 rightPolynomial,
			u64 publicCount,
			span<Ext> work,
			const std::array<std::array<Ext, Ctx::extensionDegree>,
				Ctx::extensionDegree>& traceFactors,
			span<Base> z)
		{
			mCtx.transform(work, mDimension);
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
	};

	using AnyFieldF2Ole = AnyFieldOle<AnyFieldF4Ctx>;
	using AnyFieldF3Ole = AnyFieldOle<AnyFieldF9Ctx>;
	using AnyFieldGoldilocksOle = AnyFieldOle<AnyFieldGoldilocksCtx>;
}

#endif
