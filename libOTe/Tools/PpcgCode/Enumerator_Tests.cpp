
#include <bitset>
#include <cassert>
#include <random>

#include "EnumeratorTools.h"
#include "MinimumDistance.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "RepeaterEnumerator.h"
#include "CompositionEnumerator.h"
#include "libOTe/Tools/LDPC/Util.h"
#include "AccumulateEnumerator.h"
#include "BlockEnumerator.h"
#include "BandedEnumerator.h"
#include "ExpandEnumerator.h"
#include "RandConvEnumerator.h"
#include "BallsBins.h"
#include "WrapConvEnumerator.h"
#include "WrapConvDPEnumerator.h"
#include "SystematicEnumerator.h"
#include "ClippedEnumerator.h"
#include "RandomEnumerator.h"

#define BITSET_SIZE 128

namespace osuCrypto {

	template<typename R>
	void ensureFiniteNonNegative(span<const R> dist)
	{
		for (u64 i = 0; i < dist.size(); ++i)
		{
			if (!isFiniteValue(dist[i]))
			{
				std::cout << "non-finite distribution value at " << i << ": " << dist[i] << std::endl;
				throw RTE_LOC;
			}
			if (dist[i] < R(0))
			{
				std::cout << "negative distribution value at " << i << ": " << dist[i] << std::endl;
				throw RTE_LOC;
			}
		}
	}

	template<typename R0, typename R1>
	void compareFloatLike(const std::vector<R0>& a, const std::vector<R1>& b, double relTol, double absTol)
	{
		if (a.size() != b.size())
			throw RTE_LOC;
		for (u64 i = 0; i < a.size(); ++i)
		{
			auto aa = Float(a[i]);
			auto bb = Float(b[i]);
			auto diff = boost::multiprecision::abs(aa - bb);
			auto scale = std::max(boost::multiprecision::abs(aa), boost::multiprecision::abs(bb));
			auto limit = std::max(Float(absTol), Float(relTol) * scale);
			if (diff > limit)
			{
				std::cout << "mismatch at " << i << ": " << aa << " vs " << bb << ", diff " << diff << std::endl;
				throw RTE_LOC;
			}
		}
	}

	template<typename R0, typename R1>
	Float tailL1(span<const R0> a, span<const R1> b, u64 hMax)
	{
		if (a.size() != b.size())
			throw RTE_LOC;
		Float err = 0;
		for (u64 h = 0; h <= hMax; ++h)
			err += boost::multiprecision::abs(Float(a[h]) - Float(b[h]));
		return err;
	}

	template<typename R0, typename R1>
	Float tailL1(const std::vector<R0>& a, const std::vector<R1>& b, u64 hMax)
	{
		return tailL1<R0, R1>(span<const R0>(a.data(), a.size()), span<const R1>(b.data(), b.size()), hMax);
	}

	template<typename R>
	u64 firstWeightAtLeastOne(span<const R> dist)
	{
		for (u64 h = 0; h < dist.size(); ++h)
			if (dist[h] >= R(1))
				return h;
		return ~u64(0);
	}

	u64 labeledBallsBinsCapExhaustive(i64 balls, i64 bins, i64 cap)
	{
		if (balls < 0)
			return 0;
		if (bins < 0)
			return 0;
		if (cap < 0)
			return 0;
		i64 n = bins * cap;
		auto nck = choose_<Int>(n, balls);

		Matrix<u8> M(bins, cap);
		u64 count = 0;
		std::vector<u64> idx(balls);
		for (u64 i = 0; i < nck; ++i)
		{
			ithCombination(i, n, idx);
			std::fill(M.begin(), M.end(), 0);
			for (auto j : idx)
			{
				M(j) = 1;
			}

			bool bad = false;
			for (u64 j = 0; j < bins; ++j)
			{
				if (std::accumulate(M[j].begin(), M[j].end(), 0) == 0)
				{
					bad = true;
					break;
				}
			}

			if (!bad)
			{
				//for (u64 i = 0; i < M.rows(); ++i)
				//{
				//	for (u64 j = 0; j < M.cols(); ++j)
				//	{
				//		std::cout << int(M(i, j)) << " ";
				//	}
				//	std::cout << std::endl;
				//}
				//std::cout << std::endl;

				++count;
			}
		}

		return count;
	}

	void labeledBallsBinsCap_Test(const CLP& cmd)
	{
		u64 binsMax = cmd.getOr("bins", 5);
		u64 capMax = cmd.getOr("cap", 5);

		Choose<Int> pas(binsMax * capMax);

		for (u64 bins = -1; bins < binsMax; ++bins)
		{
			for (u64 cap = -1; cap < capMax; ++cap)
			{

				for (u64 balls = -1; balls < bins * cap; ++balls)
				{
					auto count1 = labeledBallsBinsCapExhaustive(balls, bins, cap);
					auto count2 = labeledBallsBinsCap(balls, bins, cap, pas);
					//std::cout << "balls: " << balls << " bins: " << bins << " cap: " << cap << " count: " << count << std::endl;
					if (count1 != count2)
					{
						std::cout << "balls: " << balls << " bins: " << bins << " cap: " << cap << " count: " << count1 << " != " << count2 << std::endl;
						throw RTE_LOC;
					}
				}
			}
		}
	}



	u64 ballsBinsCapExhaustive(i64 balls, i64 bins, i64 cap)
	{

		if (balls < 0)
			return 0;
		if (bins < 0)
			return 0;
		if (cap < 0)
			return 0;

		// we have a position for each ball and (bins-1) dividers.
		// balls into bins is the same as choosing (bins-1) dividers.
		auto n = balls + bins - 1;
		auto nck = choose(n, bins - 1);;
		if(balls <= cap)
			return nck;
		u64 count = 0;
		std::vector<u64> idx(bins-1);
		//std::cout << "bbc " << balls << " " << bins << " " << cap << std::endl;

		for (u64 i = 0; i < nck; ++i)
		{
			ithCombination(i, n, idx);

			// count this combination if there are no bins it more than cap balls.
			auto b = [&] {
				if(idx[0] > cap || n-idx.back()-1 > cap)
					return 0;
				for (u64 j = 1; j < idx.size(); ++j)
					if(idx[j] - idx[j - 1] - 1 > cap)
						return 0;
				return 1;
				}();

			//if (b)
			//{
			//	std::cout << int(b) << " [ " << idx[0] << ", ";
			//	for (u64 j = 1; j < idx.size(); ++j)
			//		std::cout << (idx[j] - idx[j - 1]) << ", ";
			//	std::cout << (n - idx.back()-1) << " ] ~ ( ";
			//	for (u64 j = 0; j < idx.size(); ++j)
			//		std::cout << idx[j] << " ";
			//	std::cout << " )" << std::endl;


			//}
			count += b;
		}

		return count;
	}

	void ballsBinsCap_Test(const CLP& cmd)
	{
		u64 binsMax = cmd.getOr("bins", 5);
		u64 capMax = cmd.getOr("cap", 5);

		Choose<Int> pas(binsMax * capMax);
		std::vector<BallsBinsCap<Int>> cache(capMax);
		Choose<Int> choose(binsMax * capMax);

		for (i64 cap = 0; cap < capMax; ++cap)
		{
			cache[cap] = BallsBinsCap<Int>(capMax, binsMax, cap, choose);
		}
		for (i64 bins = -1; bins < binsMax; ++bins)
		{
			for (i64 cap = -1; cap < capMax; ++cap)
			{

				for (u64 balls = -1; balls < bins * cap; ++balls)
				{
					auto count1 = ballsBinsCapExhaustive(balls, bins, cap);
					auto count2 = ballsBinsCap(balls, bins, cap, pas);

					//std::cout << "balls: " << balls << " bins: " << bins << " cap: " << cap << " count: " << count << std::endl;
					if (count1 != count2)
					{
						std::cout << "balls: " << balls << " bins: " << bins << " cap: " << cap << " count: " << count1 << " != " << count2 << std::endl;
						throw RTE_LOC;
					}

					if (cap >= 0)
					{
						auto count3 = cache[cap](balls, bins);
						if (count1 != count3)
						{
							std::cout << "cache balls: " << balls << " bins: " << bins << " cap: " << cap << " count: " << count1 << " != " << count3 << std::endl;
							throw RTE_LOC;
						}
					}
				}
			}
		}

		// Regression check: when bins*cap is even, the cache must include the midpoint.
		{
			Choose<Int> choose(64);
			BallsBinsCap<Int> cache(16, 6, 3, choose);
			auto cached = cache(9, 6);
			auto direct = ballsBinsCap<Int>(9, 6, 3, choose);
			if (cached != direct)
			{
				std::cout << "midpoint cache mismatch: " << cached << " != " << direct << std::endl;
				throw RTE_LOC;
			}
		}
	}

	void minimumDistanceTestMain(oc::CLP& cmd) {
		TestCollection tests;

		tests.add("RepeaterEnum_exhaustive_Test        ", RepeaterEnum_exhaustive_Test);
		tests.add("ballsBinsCap_Test                   ", ballsBinsCap_Test);
		tests.add("labeledBallsBinsCap_Test            ", labeledBallsBinsCap_Test);
		tests.add("accumulateEnum_exhaustive_Test      ", accumulateEnum_exhaustive_Test);
		tests.add("blockEnum_exhaustive_Test           ", blockEnum_exhaustive_Test);
		tests.add("BandedEnum_exhaustive_Test          ", BandedEnum_exhaustive_Test);
		tests.add("expandEnum_exhaustive_Test          ", expandEnum_exhaustive_Test);
		tests.add("RandomEnum_exhaustive_Test          ", RandomEnum_exhaustive_Test);
		tests.add("SystematicEnum_compare_Test        ", [](const CLP&)
		{
			Choose<Int> choose(40);
			std::vector<Rat> inDist(9), outSys(17), outWrap(17);
			for (u64 w = 0; w <= 8; ++w)
				inDist[w] = choose(8, w);

			Matrix<Rat> fullSys(9, 17), fullWrap(9, 17);
			RandomEnumerator<Int, Rat> sysEnum(8, 16, true, choose);
			sysEnum.enumerate(inDist, outSys, fullSys);

			auto parity = std::make_unique<RandomEnumerator<Int, Rat>>(8, 8, false, choose);
			SystematicEnumerator<Int, Rat> wrapEnum(std::move(parity), choose);
			wrapEnum.enumerate(inDist, outWrap, fullWrap);

			for (u64 w = 0; w < fullSys.rows(); ++w)
			{
				for (u64 h = 0; h < fullSys.cols(); ++h)
				{
					auto a = fullSys(w, h);
					auto b = fullWrap(w, h);
					a.backend().normalize();
					b.backend().normalize();
					if (a != b)
						throw RTE_LOC;
				}
			}

			for (u64 h = 0; h < outSys.size(); ++h)
			{
				auto a = outSys[h];
				auto b = outWrap[h];
				a.backend().normalize();
				b.backend().normalize();
				if (a != b)
					throw RTE_LOC;
			}
		});
		tests.add("ClippedEnum_compare_Test           ", [](const CLP&)
		{
			Choose<Int> choose(40);
			std::vector<Rat> inDist(9), outClip(9), outManual(9);
			for (u64 w = 0; w <= 8; ++w)
				inDist[w] = choose(8, w);

			Matrix<Rat> fullClip(9, 9), fullManual(9, 9), fullBase(9, 9);
			RandomEnumerator<Int, Rat> baseEnum(8, 8, false, choose);
			baseEnum.enumerate(inDist, outManual, fullBase);
			for (u64 w = 1; w < fullBase.rows(); ++w)
			{
				for (u64 h = 0; h < 3; ++h)
					fullBase(w, h) = Rat(0);
			}
			osuCrypto::enumerate<Rat>(fullBase, inDist, outManual, choose, nullptr);

			auto inner = std::make_unique<RandomEnumerator<Int, Rat>>(8, 8, false, choose);
			ClippedEnumerator<Int, Rat> clipEnum(std::move(inner), choose, 3);
			clipEnum.enumerate(inDist, outClip, fullClip);

			for (u64 w = 0; w < fullClip.rows(); ++w)
			{
				for (u64 h = 0; h < fullClip.cols(); ++h)
				{
					auto a = fullClip(w, h);
					auto b = fullBase(w, h);
					a.backend().normalize();
					b.backend().normalize();
					if (a != b)
						throw RTE_LOC;
				}
			}

			for (u64 h = 0; h < outClip.size(); ++h)
			{
				auto a = outClip[h];
				auto b = outManual[h];
				a.backend().normalize();
				b.backend().normalize();
				if (a != b)
					throw RTE_LOC;
			}
		});
		
		tests.add("RandConvEnum_single_Test            ", RandConvEnum_single_Test);;
		tests.add("RandConvEnum_exhaustive_Test        ", RandConvEnum_exhaustive_Test);
		tests.add("WrapConvEnum_single_Test            ", WrapConvEnum_single_Test);;
		tests.add("WrapConvEnum_exhaustive_Test        ", WrapConvEnum_exhaustive_Test);
		tests.add("WrapConvDP_compare_Test            ", WrapConvDP_compare_Test);
		tests.add("WrapConvDP_exhaustive_Test         ", WrapConvDP_exhaustive_Test);
		tests.add("FloatEnum_compare_Test            ", [](const CLP&)
		{
			const u64 k = 8;
			const u64 outerN = 18;
			const u64 innerN = 20;
			const u64 sigma = 2;

			Choose<Int> choose(64);
			BallsBinsCap<Int> bbc(outerN, k, sigma > 1 ? sigma - 2 : 0, choose);

			std::vector<Rat> inExact(k + 1), outExact(innerN + 1);
			std::vector<Float> inFloat(k + 1), outFloat(innerN + 1);
			for (u64 w = 0; w <= k; ++w)
			{
				inExact[w] = choose(k, w);
				inFloat[w] = to<Float>(choose(k, w));
			}

			auto parityExact = std::make_unique<BandedEnumerator<Int, Rat>>(k, outerN - k, sigma, choose, bbc, 1);
			auto parityFloat = std::make_unique<BandedEnumerator<Int, Float>>(k, outerN - k, sigma, choose, bbc, 1);
			SystematicEnumerator<Int, Rat> sysExact(std::move(parityExact), choose);
			SystematicEnumerator<Int, Float> sysFloat(std::move(parityFloat), choose);
			WrapConvDPEnumerator<Int, Rat> innerExact(outerN, innerN, sigma, choose);
			WrapConvDPEnumerator<Int, Float> innerFloat(outerN, innerN, sigma, choose);

			std::vector<Enumerator<Rat>*> subsExact{ &sysExact, &innerExact };
			std::vector<Enumerator<Float>*> subsFloat{ &sysFloat, &innerFloat };
			ComposeEnumerator<Int, Rat> compExact(subsExact, false, choose, 1);
			ComposeEnumerator<Int, Float> compFloat(subsFloat, false, choose, 1);

			compExact.enumerate(inExact, outExact);
			compFloat.enumerate(inFloat, outFloat);

			ensureFiniteNonNegative<Float>(outFloat);
			compareFloatLike(outExact, outFloat, 1e-24, 1e-30);
		});
		tests.add("FloatEnum_smoke_Test              ", [](const CLP&)
		{
			const u64 k = 16;
			const u64 sigma = 4;
			const u64 outerN = 2 * k + sigma;
			const u64 innerN = outerN + 4;

			Choose<Int> choose(96);
			BallsBinsCap<Int> bbc(outerN - k, k, sigma > 1 ? sigma - 2 : 0, choose);

			std::vector<Float> in(k + 1), out(innerN + 1);
			for (u64 w = 0; w <= k; ++w)
				in[w] = to<Float>(choose(k, w));

			auto parity = std::make_unique<BandedEnumerator<Int, Float>>(k, outerN - k, sigma, choose, bbc, 1);
			SystematicEnumerator<Int, Float> sys(std::move(parity), choose);
			WrapConvDPEnumerator<Int, Float> inner(outerN, innerN, sigma, choose);
			std::vector<Enumerator<Float>*> subs{ &sys, &inner };
			ComposeEnumerator<Int, Float> comp(subs, false, choose, 1);

			comp.enumerate(in, out);
			ensureFiniteNonNegative<Float>(out);
			Float sum = 0;
			for (auto& v : out)
				sum += v;
			if (!isFiniteValue(sum) || sum <= 0)
				throw RTE_LOC;
		});
		tests.add("WrapConvDP_tailCap_Test          ", [](const CLP&)
		{
			const u64 k = 8;
			const u64 n = 10;
			const u64 sigma = 3;
			const u64 hMax = 4;

			Choose<Int> choose(64);
			std::vector<Rat> in(k + 1), outFull(n + 1), outTail(n + 1);
			for (u64 w = 0; w <= k; ++w)
				in[w] = choose(k, w);

			WrapConvDPEnumerator<Int, Rat> fullEnum(k, n, sigma, choose);
			WrapConvDPEnumerator<Int, Rat> tailEnum(k, n, sigma, choose);
			tailEnum.mHMax = hMax;

			fullEnum.enumerate(in, outFull);
			tailEnum.enumerate(in, outTail);

			for (u64 h = 0; h <= hMax; ++h)
			{
				auto a = outFull[h];
				auto b = outTail[h];
				a.backend().normalize();
				b.backend().normalize();
				if (a != b)
					throw RTE_LOC;
			}

			for (u64 h = hMax + 1; h <= n; ++h)
			{
				if (outTail[h] != Rat(0))
					throw RTE_LOC;
			}

			if (tailEnum.mDiscardedMassUpper <= Rat(0))
				throw RTE_LOC;
		});
		tests.add("WrapConvDP_approxSmoke_Test      ", [](const CLP&)
		{
			const u64 k = 12;
			const u64 n = 16;
			const u64 sigma = 4;

			Choose<Int> choose(96);
			std::vector<Float> in(k + 1), out(n + 1);
			for (u64 w = 0; w <= k; ++w)
				in[w] = to<Float>(choose(k, w));

			WrapConvDPEnumerator<Int, Float> approxEnum(k, n, sigma, choose);
			approxEnum.mApproxRelEps = 1e-2;
			approxEnum.enumerate(in, out);

			ensureFiniteNonNegative<Float>(out);
			if (!isFiniteValue(approxEnum.mDiscardedMassUpper) || approxEnum.mDiscardedMassUpper <= Float(0))
				throw RTE_LOC;
		});
		tests.add("WrapConvDP_approxBound_Test      ", [](const CLP&)
		{
			const u64 k = 16;
			const u64 n = 20;
			const u64 sigma = 4;
			const u64 hMax = 8;

			Choose<Int> choose(96);
			std::vector<Float> in(k + 1), outFull(n + 1), outApprox(n + 1);
			for (u64 w = 0; w <= k; ++w)
				in[w] = to<Float>(choose(k, w));

			WrapConvDPEnumerator<Int, Float> fullEnum(k, n, sigma, choose);
			fullEnum.mHMax = hMax;
			WrapConvDPEnumerator<Int, Float> approxEnum(k, n, sigma, choose);
			approxEnum.mHMax = hMax;
			approxEnum.mApproxRelEps = 1e-7;

			fullEnum.enumerate(in, outFull);
			approxEnum.enumerate(in, outApprox);

			ensureFiniteNonNegative<Float>(outApprox);
			if (approxEnum.mPrunedEntries == 0)
				throw RTE_LOC;

			auto err = tailL1(outFull, outApprox, hMax);
			if (err > approxEnum.mDiscardedMassUpper)
			{
				std::cout << "tail error " << err
					<< " exceeds discarded upper bound " << approxEnum.mDiscardedMassUpper << std::endl;
				throw RTE_LOC;
			}

			auto hFull = firstWeightAtLeastOne<Float>(outFull);
			auto hApprox = firstWeightAtLeastOne<Float>(outApprox);
			if (hFull != hApprox)
			{
				std::cout << "threshold changed under approximation: "
					<< hFull << " vs " << hApprox << std::endl;
				throw RTE_LOC;
			}

			for (u64 h = 0; h <= hMax; ++h)
			{
				auto a = outFull[h];
				auto b = outApprox[h];
				auto diff = boost::multiprecision::abs(a - b);
				auto limit = std::max(Float("1e-6"), boost::multiprecision::abs(a) * Float("1e-4"));
				if (diff > limit)
				{
					std::cout << "unexpected low-tail drift at h=" << h << ": "
						<< a << " vs " << b << std::endl;
					throw RTE_LOC;
				}
			}
		});
		
		tests.add("composeEnum_exhaustive_Test         ", composeEnum_exhaustive_Test);
		tests.add("composeEnum_sysExhaustive_Test      ", composeEnum_sysExhaustive_Test);
		

		//tests.add("chooseTest                          ", chooseTest);
		//tests.add("expanding_distribution_opt_test     ", expanding_distribution_opt_test);
		//tests.add("minimum_distance_tests              ", minimum_distance_tests);
		tests.runIf(cmd);
	}


}

