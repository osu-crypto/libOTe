#pragma once
#include "cryptoTools/Common/Defines.h"
#include <vector>
#include "NttOrder.h"
#include <bit>
#include <format>

namespace osuCrypto
{
	// ============================================================================
	//  Negative‑wrapping NTT / iNTT (Cooley‑Tukey & Gentleman‑Sande)
	//  ---------------------------------------------------------------------------
	//  ‑  Field element type `F` must model:
	//        * static constexpr u64 outputOrder();            // field size (prime)
	//        * F  operator+(F,F)  ,  operator-(F,F)
	//        * F  operator*(F,F)
	//        * F  pow(u64)  (fast exponentiation)
	//  ‑  `span<T>` is the standard C++20 view from <span> (or gsl::span).
	//  ‑  The transform is **negacyclic** modulo (x^n + 1).  This matches the
	//     NTT primitive used in many lattice / RLWE cryptosystems.
	//  ‑  Recursion is kept for clarity; an *iterative* version is faster and
	//     avoids repeated heap allocations — see the TODO at the bottom.
	// ============================================================================


	//---------------------------------------------------------------------------
	//   (1) NEGACYCLIC NTT  —  Cooley‑Tukey, decimation‑in‑frequency
	//---------------------------------------------------------------------------
	// *Input*   a[0..n‑1]         coefficients (time domain)
	// *Output*  aHat[0..n‑1]      evaluations  (freq. domain)
	// *psi*     primitive 2n‑th root of unity in F  (i.e. psi^{2n}=1 , psi^n=-1)
	// *outputOrder*   output outputOrder:  BitReversedOrder | NaturalOrder
	//
	//  Recurrence:
	//     split a(x) = A(x^2) + x B(x^2)
	//     NTT_{n}(a)  =  ( NTT_{n/2}(A)  ± psi^{2i+1} NTT_{n/2}(B) )_{i}
	//---------------------------------------------------------------------------
	// ntt negative-wrapping using the fast COOLEY-TUKEY NTT algo.
	// This will perform an ntt with respect to modulus
	// (x^n +1)
	// 
	// O(n log n) time.
	// a are the coeffs,
	// aHat are the evaluations
	// psi is the 2n-th root of unity.

	struct NttRange
	{
		u64 mBaseIndex = 0;
		u64 mStride;
		u64 mSize;

		// split the range into even and odd elements
		std::pair<NttRange, NttRange> split() const
		{
			auto half = mSize / 2;
			return {
				{ mBaseIndex, mStride * 2, half },
				{ mBaseIndex + mStride, mStride * 2, half }
			};
		}

		u64 operator[](u64 i) const
		{
			if (i >= mSize)
				throw RTE_LOC;
			return mBaseIndex + i * mStride;
		}
	};

	// This is a basic version of the ntt that uses recursion.
	// It is not the most efficient, but it is clear and easy to follow.
	template<typename F>
	void nttNegWrapCt(
		span<F> aHat,
		span<const F> a,
		const auto& psi,
		const auto& basePsi,
		NttRange range,
		u64 depth,
		NttOrder outputOrder)
	{
		u64 n = a.size();
		auto ln = log2ceil(n);
		auto qq = F::order() - 1;
		auto q = static_cast<std::conditional_t<(sizeof(decltype(qq)) < sizeof(u64)), u64, decltype(qq)>>(qq);

		if (n != 1ull << ln)
			throw RTE_LOC;
		if (n > q)
			throw RTE_LOC;
		if (q % n != 0)
			throw RTE_LOC;
		if (psi.pow(2 * n) != 1)
			throw RTE_LOC;

		if (n == 1)
		{
			aHat[0] = a[0];
			return;
		}

#ifndef NDEBUG
		if (isPrimRootOfUnity(2 * n, psi) == false)
			throw RTE_LOC;
#endif

		std::vector<F> A(n / 2), B(n / 2);
		for (u64 i = 0; i < A.size(); ++i)
		{
			A[i] = a[2 * i + 0];
			B[i] = a[2 * i + 1];
		}

		std::vector<F> AHat(n / 2), BHat(n / 2);
		// psi^{2} is primitive n‑th root
		auto psi2 = psi * psi;
		auto [aRange, bRange] = range.split();
		nttNegWrapCt<F>(AHat, A, psi2, basePsi, aRange, depth + 1, NttOrder::NormalOrder);
		nttNegWrapCt<F>(BHat, B, psi2, basePsi, bRange, depth + 1, NttOrder::NormalOrder);

		// -------- combine ------------------------------------------------
		// Pre‑compute successive powers  psi^{2i+1}  iteratively→ saves O(n log n)
		auto psiPow = psi;                      // i = 0  ⇒  psi^{1}
		const auto psiStep = psi2;              // multiply by psi^{2} each iteration

		for (u64 i = 0; i < A.size(); ++i)
		{

			// psi = bPsi^bExp
			// psiPow = psi^{2i+1}
			//        = bPsi^{bExp * (2i + 1)}
			auto basePsiExp = 1ull << depth;
			auto index = basePsiExp * (2 * i + 1);

			//	throw RTE_LOC;
			if (psiPow != basePsi.pow(index))
				throw RTE_LOC;

			const auto psiB = BHat[i] * psiPow;   // psi^{2i+1} B̂_i
			const u64 idx0 = i;
			const u64 idx1 = i + n / 2;
			aHat[idx0] = AHat[i] + psiB;
			aHat[idx1] = AHat[i] - psiB;

			//std::cout << std::format("{0}({1}, {2}, {3} = {4} * (2 * {5} + 1), {6} {7})\n",
			//	std::string(4 * depth, ' '),
			//	range[idx0], range[idx1],
			//	index, basePsiExp, i,
			//	AHat[i].integer(), BHat[i].integer());

			//std::cout << std::string(4*depth, ' ')
			//	<< "(" << range[idx0] << "," << range[idx1] 
			//	<< ", " << index << " ," << AHat[i] <<", " << BHat[i] << ")\n";

			//std::cout
			//	<< "aHat[" <<depth <<", " << range[idx0] << "] = " << aHat[idx0] << " = " <<
			//	AHat[i] << " + " << psiB << "\n"
			//	<< "aHat[" <<depth << ", " << range[idx1] << "] = " << aHat[idx1] << " = " <<
			//	AHat[i] << " - " << psiB << "\n";

			psiPow *= psiStep;              // next  psi^{2(i+1)+1}
		}
		if (outputOrder == NttOrder::NormalOrder)
		{
		}
		else
		{
			bitReversePermute(aHat);
		}
	}


	// Convenience wrapper: full range, base psi, specified output order.
	template<typename F>
	void nttNegWrapCt(
		span<F> aHat,
		span<const F> a,
		auto psi,
		NttOrder order)
	{
		auto rng = NttRange{ .mBaseIndex = 0, .mStride = 1, .mSize = a.size() };
		nttNegWrapCt(aHat, a, psi, psi, rng, 0, order);
	}


	// Pre-compute powers of a primitive 2n-th root of unity.
	template<typename F>
	void nttPrecomputeRootsOfUnity(const F& psi, span<F> roots)
	{
		auto n = roots.size();
		auto ln = log2ceil(n);
		auto qq = F::order() - 1;
		auto q = static_cast<std::conditional_t<(sizeof(decltype(qq)) < sizeof(u64)), u64, decltype(qq)>>(qq);
		if (n != 1ull << ln)
			throw RTE_LOC;
		if (n > q)
			throw RTE_LOC;
		if (q % n != 0)
			throw RTE_LOC;
		if (psi.pow(2 * n) != 1)
			throw RTE_LOC;
#ifndef NDEBUG
		if (isPrimRootOfUnity(2 * n, psi) == false)
			throw RTE_LOC;
#endif

		//auto logn = log2ceil(n);
		F root = F(1);
		for (u64 i = 0; i < n; ++i)
		{
			roots[i] = root;
			root *= psi;
		}
	}

	// Build stage-major twiddles for radix-2 CT negacyclic NTT.
	// w must be powers of ψ: w[k] = ψ^k, with size >= 2*n.
	template<typename F>
	void getNegWrapRoots(span<const F> w, span<F> T, uint64_t n) {
		const uint64_t ln = log2ceil(n);
		if ((1ull << ln) != n)           throw RTE_LOC;           // n must be power of two
		if (w.size() < 2 * n)            throw RTE_LOC;           // need ψ^k for k∈[0,2n)

		if (T.size() < n - 1)            throw RTE_LOC;           // need n-1 twiddles
		auto pos = 0ull;

		uint64_t stride = n / 2;
		for (uint64_t s = 0; s < ln; ++s) {
			const uint64_t size = n / stride / 2;  // == n >> (s+1)

			for (uint64_t j = 0; j < size; ++j) {
				const uint64_t r = bitReversal(static_cast<int>(s), j);
				const uint64_t idx = stride * (2 * r + 1);   // odd ψ-exponents for negacyclic CT
				T[pos++] = w[idx];
			}
			stride >>= 1;
		}
		//return T;
	}


	// Build stage-major twiddles for radix-2 CT negacyclic NTT.
	// w must be powers of ψ: w[k] = ψ^k, with size >= 2*n.
	template<typename F>
	std::vector<F> getNegWrapRoots(span<const F> w, uint64_t n)
	{
		std::vector<F> T(n - 1);
		getNegWrapRoots<F>(w, T, n);
		return T;
	}

#define SIMD8(VAR, STATEMENT) do{\
	{ constexpr u64 VAR = 0; STATEMENT; }\
	{ constexpr u64 VAR = 1; STATEMENT; }\
	{ constexpr u64 VAR = 2; STATEMENT; }\
	{ constexpr u64 VAR = 3; STATEMENT; }\
	{ constexpr u64 VAR = 4; STATEMENT; }\
	{ constexpr u64 VAR = 5; STATEMENT; }\
	{ constexpr u64 VAR = 6; STATEMENT; }\
	{ constexpr u64 VAR = 7; STATEMENT; }\
	}while(0)


	// Iterative version of the negacyclic Cooley-Tukey NTT.
	// - a are the coeffs,
	// - w are the precomputed twiddles for each stage (see getNegWrapRoots)
	// - order is the output order (normal or bit-reversed)
	template<typename F, typename SF = F>
	void nttNegWrapCt(
		span<F> a,
		span<SF> w,
		NttOrder order = NttOrder::BitReversedOrder)
	{

		F* __restrict aPtr = a.data();
		SF* __restrict wPtr = w.data();

		u64 n = a.size();
		auto ln = log2ceil(n);
		if (n != 1ull << ln)
			throw RTE_LOC;
		if (w.size() != n - 1)
			throw std::runtime_error("expecting the n-1 roots that are specific to the negcyclic ntt. "
				"obtain them by calling nttPrecomputeRootsOfUnity(...) and getNegWrapRoots(...)." LOCATION);

#ifndef NDEBUG
		{
			auto psi = w[n / 2 - 1]; // the expected position of the 2n root of unity
			if (isPrimRootOfUnity<SF>(2 * n, psi) == false)
				throw RTE_LOC;
		}
#endif
		u64 stride = n / 2;

		u64 stage = 0;
		while (stride)
		{
			u64 size = n / stride / 2;
			u64 base = 0;
			for (u64 j = 0; j < size; ++j)
			{
				// wi = psi^{stride * (2*bitReversal(stage,j)+1)}
				auto wi = *wPtr++;
#ifndef NDEBUG
				auto psi = w[n / 2 - 1]; // the expected position of the 2n root of unity
				auto index = stride * (2 * bitReversal(stage, j) + 1);
				if (psi.pow(index) != wi) // check that the caller passed in the right roots.
					throw RTE_LOC;
#endif // !NDEBUG


				for (u64 i = 0; i < stride; ++i)
				{
					F a0 = aPtr[base];
					F a1 = aPtr[base + stride];

					auto b = a1 * wi;
					aPtr[base] = a0 + b;
					aPtr[base + stride] = a0 - b;

					++base;

					//std::cout << "(" << idx0 << "," << idx1 << ", " << index << ", " <<a0 <<", " <<a1  <<") ";
					//std::cout << std::format("{0}({1}, {2}, {3} = {4} * (2 * {5} + 1), {6} {7} )\n",
					//	std::string(4 * depth, ' '),
					//	idx0, idx1,
					//	index, stride, bitReversal(stage, j),
					//	a0.integer(), a1.integer());
				}

				base += stride;
			}
			//std::cout << std::endl;

			++stage;
			stride /= 2;
		}

		(void)stage;

		if (order == NttOrder::NormalOrder)
			bitReversePermute(a);
	}


	//---------------------------------------------------------------------------
	//   (2) NEGACYCLIC iNTT  —  Gentleman‑Sande, decimation‑in‑time
	//---------------------------------------------------------------------------
	// *Input*   aHat   frequency domain (bit‑reversed outputOrder **required**)
	// *Output*  a      time domain coefficients
	// *psi*     same primitive 2n‑th root used for forward NTT.
	//---------------------------------------------------------------------------
	// inverse ntt negative-wrapping using the fast GENTLEMAN-SANDE  NTT algo.
	// This will perform an ntt with respect to modulus
	// (x^n +1)
	// 
	// O(n log n) time.
	// a are the coeffs,
	// aHat are the evaluations
	// psi is the 2n-th root of unity where n is the length of a and aHat.
	template<typename F>
	void inttNegWrapGs(
		span<F> a,
		span<const F> aHat,
		const F& psi,
		NttOrder inputOrder)
	{
		auto n = a.size();
		auto ln = log2ceil(n);
		auto qq = F::order() - 1;

		if (n != 1ull << ln)
			throw RTE_LOC;
		if (n > qq)
			throw RTE_LOC;
		if (qq % n != 0)
			throw RTE_LOC;
		if (psi.pow(2 * n) != 1)
			throw RTE_LOC;

		if (inputOrder != NttOrder::BitReversedOrder)
			throw RTE_LOC;

		if (n == 1)
		{
			a[0] = aHat[0];
			return;
		}

#ifndef NDEBUG
		if (isPrimRootOfUnity(2 * n, psi) == false)
			throw RTE_LOC;
#endif

		span<const F>
			AHat = aHat.subspan(0, n / 2),
			BHat = aHat.subspan(n / 2);

		std::vector<F> A(n / 2), B(n / 2);
		auto psi2 = psi * psi;
		inttNegWrapGs<F>(A, AHat, psi2, NttOrder::BitReversedOrder);
		inttNegWrapGs<F>(B, BHat, psi2, NttOrder::BitReversedOrder);

		// Pre‑compute descending powers psi^{2n‑2i}
		F psiPow = psi.pow(2 * n - 2);        // when i=0
		const F psiStepInv = psi2.inverse();     // multiply by psi^{-2} each iteration

		const u64 half = n >> 1;
		for (u64 i = 0; i < half; ++i) {
			a[2 * i + 0] = (A[i] + B[i]) * psiPow; //  (A_i + B_i) * psi^{2n-2i}
			a[2 * i + 1] = (A[i] - B[i]) * psiPow; //  (A_i - B_i) * psi^{2n-2i}
			psiPow *= psiStepInv;           // next power
		}
	}



#undef SIMD8

}