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

	template<typename F>
	void nttNegWrapCt(
		span<F> aHat,
		span<const F> a,
		const F& psi,
		const F& basePsi,
		NttRange range,
		u64 depth,
		NttOrder outputOrder)
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
		F psiPow = psi;                      // i = 0  ⇒  psi^{1}
		const F psiStep = psi2;              // multiply by psi^{2} each iteration

		for (u64 i = 0; i < A.size(); ++i)
		{
			const F psiB = psiPow * BHat[i];   // psi^{2i+1} B̂_i

			// psi = bPsi^bExp
			// psiPow = psi^{2i+1}
			//        = bPsi^{bExp * (2i + 1)}
			auto basePsiExp = 1ull << depth;
			auto index = basePsiExp * (2 * i + 1);

			//	throw RTE_LOC;
			if (psiPow != basePsi.pow(index))
				throw RTE_LOC;

			const u64 idx0 = i;
			const u64 idx1 = i + n / 2;
			aHat[idx0] = AHat[i] + psiB;
			aHat[idx1] = AHat[i] - psiB;

			std::cout << std::format("{0}({1}, {2}, {3} = {4} * (2 * {5} + 1), {6} {7})\n",
				std::string(4 * depth, ' '),
				range[idx0], range[idx1],
				index, basePsiExp, i,
				AHat[i].integer(), BHat[i].integer());

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
			//for (u64 i = 0; i < A.size(); ++i)
			//{
			//	const F psiB = psiPow * BHat[i];   // psi^{2i+1} B̂_i
			//	const u64 idx0 = bitReversal(ln, i);
			//	const u64 idx1 = bitReversal(ln, i + 1);
			//	aHat[idx0] = AHat[i] + psiB;
			//	aHat[idx1] = AHat[i] - psiB;

			//	//std::cout
			//	//	<< "aHat[" << depth << ", " << idx0 << "] = "
			//	//	<< "AHat[" << depth + 1 << ", " << i << "] + BHat[i] = " << aHat[idx0] << " = " 
			//	//	<< AHat[i] << " + " << psiB << "\n"

			//	//	<< "aHat[" << depth << ", " << idx1 << "] = "
			//	//	<< "AHat[" << depth + 1 << ", " << i << "] - BHat[i] = " << aHat[idx1] << " = " 
			//	//	<< AHat[i] << " - " << psiB << "\n";

			//	psiPow *= psiStep;              // next  psi^{2(i+1)+1}
			//}
		}
	}



	template<typename F>
	void nttNegWrapCt(
		span<F> aHat,
		span<const F> a,
		F psi,
		NttOrder order)
	{
		auto rng = NttRange{.mBaseIndex = 0, .mStride = 1, .mSize = a.size()};
		nttNegWrapCt(aHat, a, psi, psi, rng, 0, order);
	}



	template<typename F>
	void nttNegWrapCt2(
		span<F> a,
		span<F> w,
		F psi,
		NttOrder order)
	{

		auto n = a.size();
		auto ln = log2ceil(n);
		auto qq = F::order() - 1;
		if (n != 1ull << ln)
			throw RTE_LOC;
		if (n > qq)
			throw RTE_LOC;
		if(w.size() != 2* n)
			throw RTE_LOC;

		u64 stride = n / 2;

		u64 stage = 0;
		while (stride)
		{
			u64 size = n / stride / 2;
			//std::cout << " stride " << stride << " size " << size << " depth " << depth << ": \n";
			u64 base = 0;
			for(u64 j = 0; j < size; ++j)
			{
				for (u64 i = 0; i < stride; ++i)
				{
					u64 idx0 = base + i;
					u64 idx1 = idx0 + stride;
					if (idx1 >= n)
						throw RTE_LOC;
					F a0 = a[idx0];
					F a1 = a[idx1];

					//if (ln - depth - 1 != stage)
					//	throw RTE_LOC;
					auto index = stride * (2 * bitReversal(stage, j) + 1);
					//auto psiPow = psi.pow(index);
					auto psiPow = w[index]; // precomputed powers of psi
					auto b = psiPow * a1;
					a[idx0] = a0 + b;
					a[idx1] = a0 - b;

					//std::cout << "(" << idx0 << "," << idx1 << ", " << index << ", " <<a0 <<", " <<a1  <<") ";

					//std::cout << std::format("{0}({1}, {2}, {3} = {4} * (2 * {5} + 1), {6} {7} )\n",
					//	std::string(4 * depth, ' '),
					//	idx0, idx1,
					//	index, stride, bitReversal(stage, j),
					//	a0.integer(), a1.integer());

				}
				base += stride * 2;
			}
			//std::cout << std::endl;

			stride /= 2;
			//--depth;
			++stage;
		}


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








	//inline u64 bitReverse(u64 bits, u64 x)
	//{
	//	return std::rotr(x, bits) >> (64 - bits);
	//}



	// ---------- field interface sketch -----------------------------------------
	//  You need +,-,*,pow.  Replace `F` with your own type (e.g. BarrettModInt).
	// ----------------------------------------------------------------------------
	template<typename F>
	void ntt_negacyclic_recursive_bitrev(
		span<F> out,   // size = n
		span<const F> in,    // same size
		const F& psi)                // primitive 2n-th root
	{
		const u64 n = in.size();
		const u64 ln = log2ceil(n);
		assert(n == (1ull << ln));          // n power-of-two
		if (n == 1) { out[0] = in[0]; return; }

		// -------- split a(x) = A(x²) + x B(x²) ------------------------------
		const u64 half = n >> 1;
		std::vector<F> A(half), B(half);
		for (u64 i = 0; i < half; ++i) {
			A[i] = in[2 * i];                 // even coefficients
			B[i] = in[2 * i + 1];               // odd  coefficients
		}

		// -------- recursive calls with ψ² (still primitive for length n/2) ---
		const F psi2 = psi * psi;
		std::vector<F> AHat(half), BHat(half);
		ntt_negacyclic_recursive_bitrev<F>(AHat, A, psi2);
		ntt_negacyclic_recursive_bitrev<F>(BHat, B, psi2);

		// -------- combine; write directly in bit-reversed outputOrder -------------
		for (u64 i = 0; i < half; ++i) {
			const F t = BHat[i] * psi.pow(2 * i + 1);   // ψ^{2i+1}·B̂_i
			const u64 d = 2 * i;
			const u64 idx0 = bitReversal(ln, d);
			const u64 idx1 = bitReversal(ln, d + 1);
			out[idx0] = AHat[i] + t;
			out[idx1] = AHat[i] - t;
		}
	}

























	// ============================================================================
	//  Iterative NTT / iNTT
	// ============================================================================

	template<typename F>
	void nttPrecomputeRootsOfUnity(const F& psi, span<F> roots)
	{
		auto n = roots.size();
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
#ifndef NDEBUG
		if (isPrimRootOfUnity(2 * n, psi) == false)
			throw RTE_LOC;
#endif

		auto logn = log2ceil(n);
		for (u64 i = 0; i < n; ++i)
		{
			roots[bitReversal(i, logn)] = psi.pow(i);
		}
	}

	template<typename F>
	void inttPrecomputeRootsofUnity(const F& psi, span<F> invRoots)
	{
		auto n = invRoots.size();
		auto psiInv = psi.inverse();
		auto logn = log2ceil(n);
		//F x = 1;
		for (u64 i = 0; i < n; ++i)
		{
			invRoots[bitReversal(i, logn)] = psiInv.pow(i);
		}
	}

	// Iterative forward NTT (Cooley-Tukey, DIT).
	// In-place, input in natural outputOrder, output in bit-reversed outputOrder.
	template<typename F>
	void nttNegacyclicIterative(span<F> a, span<const F> roots)
	{
		const u64 n = a.size();
		u64 t = n;
		for (u64 m = 1; m < n; m <<= 1)
		{
			u64 h = t >> 1;
			for (u64 i = 0; i < m; ++i)
			{
				u64 j1 = i * t;
				u64 j2 = j1 + h;
				const F& S = roots[m + i];
				for (u64 k = j1; k < j2; ++k)
				{
					auto u = a[k];
					auto v = a[k + h] * S;
					a[k] = u + v;
					a[k + h] = u - v;
				}
			}
			t >>= 1;
		}
	}

	// Iterative inverse NTT (Gentleman-Sande, DIF).
	// In-place, input in bit-reversed outputOrder, output in natural outputOrder.
	template<typename F>
	void inttNegacyclicIterative(span<F> a, span<const F> inv_roots)
	{
		const u64 n = a.size();
		u64 t = 2;
		for (u64 m = n >> 1; m > 0; m >>= 1)
		{
			u64 h = t >> 1;
			for (u64 i = 0; i < m; ++i)
			{
				u64 j1 = i * t;
				u64 j2 = j1 + h;
				const F& S = inv_roots[m + i];
				for (u64 k = j1; k < j2; ++k)
				{
					auto u = a[k];
					auto v = a[k + h];
					a[k] = u + v;
					a[k + h] = (u - v) * S;
				}
			}
			t <<= 1;
		}

		F inv_n = F(n).inverse();
		for (u64 i = 0; i < n; ++i)
		{
			a[i] *= inv_n;
		}
	}

	// ---------------------------------------------------------------------------
	//  Negacyclic NTT class template
	// ---------------------------------------------------------------------------

	template<typename F>
	class NegacyclicNtt
	{

	public:
		enum class NttOrder { BitReversedOrder, NaturalOrder };
		const u64 n;                 // transform length (power of two)
		const F   psi;               // primitive 2n‑th root of unity

		// psiPows[k] = psi^{k}  for 0 ≤ k < 2n
		std::vector<F> psiPows;

		//--------------------------------------------------------------------
		//  Constructor: pre‑computes the twiddle table.
		//--------------------------------------------------------------------
		NegacyclicNtt(u64 n_, const F& psi_) : n(n_), psi(psi_)
		{
			const u64 ln = log2ceil(n);
			assert(n == (1ull << ln));                    // n must be power of two
			assert(psi.pow(2 * n) == F{ 1 });                // psi must be 2n‑th root

			psiPows.resize(2 * n);
			psiPows[0] = F{ 1 };
			for (u64 k = 1; k < 2 * n; ++k)
				psiPows[k] = psiPows[k - 1] * psi;
			//bitReversePermute(psiPows);
		}

		//--------------------------------------------------------------------
		//  In‑place forward NTT (DIF, bit‑reversed output order).
		//--------------------------------------------------------------------
		void forward(std::span<F> a, NttOrder order = NttOrder::BitReversedOrder) const
		{
			assert(a.size() == n);
			u64 stage = 0;
			for (u64 m = n; m > 1; m >>= 1, ++stage) {
				const u64 half = m >> 1;
				const u64 step = n / m;              // index stride inside psiPows
				for (u64 k = 0; k < half; ++k) {
					for (u64 j = k; j < n; j += m) {
						const F tw = psiPows[(2 * j + 1) * step % (2 * n)];
						F u = a[j];
						F v = a[j + half] * tw;
						a[j] = u + v;
						a[j + half] = u - v;

						std::cout << "a[" << j << "] = " << a[j] << " = " << u << " + " << v << " @ " << tw << "\n";
						std::cout << "a[" << j + half << "] = " << a[j + half] << " = " << u << " - " << v << " @ " << tw << "\n";
					}
				}
				//            std::cout << "stage " << stage << ": m=" << m
							//	<< ", half=" << half << ", step=" << step << std::endl;
				//            for (u64 i = 0; i < a.size(); ++i)
				//            {
							//	std::cout << "a[" << i << "] = " << a[i] << "\n";
				//            }
							//std::cout << std::endl;
			}

			if (order == NttOrder::NaturalOrder)
				bitReversePermute(a);
		}

		//--------------------------------------------------------------------
		//  In‑place inverse NTT (DIT, expects bit‑reversed *input* order).
		//  Multiplies by n^{-1} so that forward ∘ inverse = identity.
		//--------------------------------------------------------------------
		void inverse(std::span<F> a, NttOrder order = NttOrder::BitReversedOrder) const
		{
			assert(a.size() == n);
			u64 stage = 0;

			for (u64 m = 1; m < n; m <<= 1, ++stage) {
				const u64 half = m;
				const u64 step = n / (2 * m);
				for (u64 k = 0; k < half; ++k) {
					// Gentleman–Sande uses the *inverse* twiddle: psi^{2n‑(2k+1)}
					const u64 idx = (2 * n) - (2 * k + 1) * step;
					const F twInv = psiPows[idx % (2 * n)];
					for (u64 j = k; j < n; j += 2 * m) {
						F u = a[j];
						F v = a[j + half];
						a[j] = (u + v) * twInv;
						a[j + half] = (u - v) * twInv;
					}
				}
			}

			// multiply by n^{-1}
			const F nInv = F(n).inverse();
			for (auto& x : a) x *= nInv;

			if (order == NttOrder::NaturalOrder)
				bitReversePermute(a);
		}

	private:
		////----------------------------------------------------------------
		////  Lazy bit‑reverse permutation (used only if NaturalOrder requested)
		////----------------------------------------------------------------
		//void bitReversePermute(std::span<F> a) const
		//{
		//	const u64 bits = log2ceil(n);
		//	for (u64 i = 0; i < n; ++i) {
		//		u64 j = bitReversal(bits, i);
		//		if (i < j) std::swap(a[i], a[j]);
		//	}
		//}




		// ---------------------------------------------------------------------------
		// Helper: next power‑of‑two exponent  (log2ceil)
		// ---------------------------------------------------------------------------
		//static inline u64 log2ceil(u64 n) { return 64 - std::countl_zero(n - 1); }

		//static inline u64 bitReverse(u64 bits, u64 x)
		//{
		//    return std::rotr(x, bits) >> (64 - bits);
		//}

	};


	// ----------------------------------------------------------------------------
	//  TODO / Possible Improvements
	// ----------------------------------------------------------------------------
	//  • Replace recursion with an iterative breadth‑first loop + in‑place stockham
	//    style butterflies: removes dynamic allocations and halves stack depth.
	//  • Pre‑compute all psi^{k} into a table if many transforms of the same size
	//    are required (trading O(n) memory for ~2× speed).
	//  • Accept `NttOrder` for input as well (instead of enforcing bit‑reversed),
	//    adding in‑place bit‑reverse permutations when needed.
	//  • Provide constexpr‑enabled variant for compile‑time size transforms (useful
	//    in micro‑kernel or constant‑time polynomial multipliers).
	//  • Consider using a memory pool / arena for the temporary vectors `A, B`
	//    to avoid per‑call `new/delete`.
	// ============================================================================


}