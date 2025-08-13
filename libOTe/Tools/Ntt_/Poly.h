#pragma once

#include "libOTe/config.h"
#include <vector>
#include <iostream>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace osuCrypto
{


	template<typename F>
	struct Poly
	{
		std::vector<F> mCoeffs;

		Poly() = default;
		Poly(const Poly&) = default;
		Poly(Poly&&) = default;
		Poly& operator = (const Poly&) = default;
		Poly& operator = (Poly&&) = default;

		Poly(span<const F>f)
		{
			*this = f;
		}


		explicit Poly(u64 deg, F coeff = 0)
		{
			setCoeff(deg, coeff);
		}

		Poly& operator=(PRNG::Any prng)
		{
			for (u64 i = 0; i < mCoeffs.size(); ++i)
				mCoeffs[i] = prng.mPrng.get();

			// the leading coeff can't be zero
			while (size() > 1 && back() == 0)
			{
				back() = prng.mPrng.get();
			}

			// spacial case, we represent the zero poly as size 0.
			//if (size() == 1 && back() == 0)
			//	pop_back();

			return *this;
		}

		Poly& operator=(span<const F> coeffs)
		{
			for (u64 i = coeffs.size() - 1; i < coeffs.size(); --i)
			{
				setCoeff(i, coeffs[i]);
			}
			return *this;
		}

		bool isZero() const {
			for(auto & c : mCoeffs)
			{
				if (c != 0)
					return false;
			}
			return true;
			//return mCoeffs.size() == 0 || (mCoeffs.size() == 1 && mCoeffs[0] == 0);
		}

		void setCoeff(u64 i, const F& f)
		{
			if (mCoeffs.size() <= i)
				mCoeffs.resize(i + 1);

			mCoeffs[i] = f;

			// shrink to fit.
			//while (mCoeffs.size() && mCoeffs.back() == 0)
			//	mCoeffs.pop_back();
		}

		F getCoeff(u64 i) const
		{
			if (i < size())
				return mCoeffs[i];
			else
				return 0;
		}


		F& operator[](u64 i)
		{
			if (mCoeffs.size() <= i)
				mCoeffs.resize(i + 1);
			return mCoeffs[i];
		}
		const F& operator[](u64 i)const
		{
			if (mCoeffs.size() <= i)
				throw RTE_LOC;

			return mCoeffs[i];
		}

		F& back() { return mCoeffs.back(); }
		const F& back()const { return mCoeffs.back(); }
		F& front() { return mCoeffs.front(); }
		const F& front()const { return mCoeffs.front(); }
		auto begin() { return mCoeffs.begin(); }
		auto begin()const { return mCoeffs.begin(); }
		auto end() { return mCoeffs.end(); }
		auto end()const { return mCoeffs.end(); }


		Poly operator+(const F& o) const
		{
			Poly r;
			add(r, *this, o);
			return r;
		}

		Poly operator*(const F& o) const
		{
			Poly r;
			mult(r, *this, o);
			return r;
		}


		Poly operator/(const F& o) const
		{
			return *this * o.inverse();
		}

		Poly operator+(const Poly& o) const
		{
			Poly r;
			add(r, *this, o);
			return r;
		}

		Poly operator*(const Poly& o) const
		{
			Poly r;
			mult(r, *this, o);
			return r;
		}

		Poly operator/(const Poly& o) const
		{
			Poly r;
			divide(&r, nullptr, *this, o);
			return r;
		}

		Poly operator%(const Poly& o) const
		{
			Poly r;
			modulo(r, *this, o);
			return r;
		}


		bool operator==(const F& o) const
		{
			if (degree())
				return false;
			if (isZero())
				return o == 0;
			return (*this)[0] == o;
		}

		bool operator!=(const F& o) const
		{
			return !(*this == o);
		}

		bool operator==(const Poly& o) const
		{
			if (degree() != o.degree())
				return false;

			auto d = degree();
			for (u64 i = 0; i <= d; ++i)
				if ((*this)[i] != o[i])
					return false;

			return true;
		}

		bool operator!=(const Poly& o) const
		{
			return !(*this == o);
		}

		operator span<F>() { return mCoeffs; }
		operator span<const F>() const { return mCoeffs; }

		u64 size() const { return mCoeffs.size(); }
		u64 degree()  const { 
			for (u64 i = mCoeffs.size() - 1; i < mCoeffs.size(); --i)
				if (mCoeffs[i] != 0)
					return i;
			return 0;
			//return mCoeffs.size() ? mCoeffs.size() - 1 : 0; 
		}


		void pop_back() { mCoeffs.pop_back(); }

		void compact()
		{
			while (size() && back() == 0)
				pop_back();
		}

		static void add(Poly& ret, const Poly& a, const F& b)
		{
			if (&ret != &a)
				ret = a;
			if (ret.size())
				ret[0] += b;
			else
				ret.setCoeff(0, b);

			ret.compact();
		}

		static void mult(Poly& ret, const Poly& a, const F& b)
		{

			if (&ret != &a)
				ret = a;
			if (b == 0)
				ret.mCoeffs.resize(0);
			else
			{
				for (u64 i = 0; i < ret.size(); ++i)
					ret[i] *= b;
			}
		}

		static void add(Poly& ret, const Poly& a, const Poly& b)
		{
			auto& longest = (a.size() > b.size()) ? a : b;
			auto max = longest.size();
			auto min = std::min<u64>(a.size(), b.size());

			ret.mCoeffs.resize(max);


			for (u64 i = 0; i < min; ++i)
			{
				ret[i] = a[i] + b[i];
			}

			if (&ret != &longest)
			{
				for (u64 i = min; i < max; ++i)
				{
					ret[i] = longest[i];
				}
			}
		}

		static void mult(Poly& ret, const Poly& a, const Poly& b)
		{
			Poly t;

			auto& dst = &ret == &a || &ret == &b ? t : ret;

			auto size = a.size() + b.size();
			dst.mCoeffs.resize(size ? size - 1 : 0);
			std::fill(dst.begin(), dst.end(), 0);

			for (u64 i = 0; i < a.size(); ++i)
			{
				for (u64 j = 0; j < b.size(); ++j)
				{
					dst[i + j] += a[i] * b[j];
				}
			}

			assert(dst.size() == 0 || dst.back() != 0);

			if (&dst == &t)
				ret = std::move(t);
		}

		static void divide(
			Poly* quo,
			Poly* rem,
			const Poly& a,
			const Poly& mod)

		{
			// Edge case: division by zero polynomial
			if (mod.isZero())
				throw RTE_LOC;

			// Edge case: dividend is zero
			if (a.isZero()) {
				if (quo) {
					quo->mCoeffs.clear();
				}
				if (rem) {
					rem->mCoeffs.clear();
				}
				return;
			}

			// Safety check for aliasing
			if (&mod == quo || &mod == rem)
				throw RTE_LOC;

			// Find actual degrees (highest non-zero coefficient)
			auto aDegree = a.degree();
			auto modDegree = mod.degree();

			// Edge case: modulus degree is 0 (constant polynomial)
			if (modDegree == 0) {
				// Division by constant: quo = a / mod[0], rem = 0
				if (quo) {
					*quo = a;
					auto divisor = mod.getCoeff(0);
					if (divisor == 0)
						throw RTE_LOC;

					for (u64 i = 0; i <= aDegree; ++i) 
						(*quo)[i] = (*quo)[i] / divisor;
					
					quo->compact();
				}
				if (rem) 
					rem->mCoeffs.clear(); // remainder is 0
				
				return;
			}

			// Edge case: dividend degree < modulus degree
			if (aDegree < modDegree) {
				if (quo) {
					quo->mCoeffs.clear(); // quotient is 0
				}
				if (rem) {
					*rem = a; // remainder is the dividend
					rem->compact();
				}
				return;
			}

			// Get leading coefficient of modulus
			auto modLeadCoeff = mod.getCoeff(modDegree);
			if (modLeadCoeff == 0)
				throw RTE_LOC;

			// Initialize remainder as copy of dividend
			Poly remainder = a;
			remainder.compact(); // Remove leading zeros

			// Initialize quotient if needed
			if (quo) {
				auto quoDegree = aDegree - modDegree;
				quo->mCoeffs.clear();
				quo->mCoeffs.resize(quoDegree + 1, F(0));
			}

			// Polynomial long division
			while (!remainder.isZero() && remainder.degree() >= modDegree) {
				auto remDegree = remainder.degree();
				auto remLeadCoeff = remainder.getCoeff(remDegree);

				// Calculate quotient coefficient
				auto quotCoeff = remLeadCoeff / modLeadCoeff;
				auto quotDegree = remDegree - modDegree;

				// Store quotient coefficient
				if (quo) {
					(*quo)[quotDegree] = quotCoeff;
				}

				// Subtract mod * quotCoeff * x^quotDegree from remainder
				for (u64 i = 0; i <= modDegree; ++i) {
					auto modCoeff = mod.getCoeff(i);
					if (modCoeff != 0) {
						remainder[quotDegree + i] -= modCoeff * quotCoeff;
					}
				}

				// Remove leading zeros from remainder
				remainder.compact();
			}

			// Set outputs
			if (quo) {
				quo->compact();
			}
			if (rem) {
				*rem = std::move(remainder);
			}
		}

		//{

		//	if (mod.back() == 0)
		//		throw RTE_LOC;
		//	//auto A = span<const F>(a.begin(), a.begin() + a.degree() + 1);
		//	if (&mod == quo || &mod == rem)
		//		throw RTE_LOC;

		//	Poly remainder = a;
		//	if (quo && a.degree() > mod.degree())
		//		quo->mCoeffs.resize(a.size() - mod.size() + 1);


		//	while (remainder.size() >= mod.size())
		//	{
		//		auto s = mod.back() == 1 ?
		//			remainder.back() :
		//			remainder.back() / mod.back();

		//		if (quo)
		//			(*quo)[remainder.size() - mod.size()] = s;

		//		auto d = remainder.size() - mod.size();
		//		for (u64 i = 0; i < mod.size(); ++i)
		//		{
		//			remainder[d + i] -= mod[i] * s;
		//		}
		//		assert(remainder.back() == 0);

		//		while (remainder.size() && remainder.back() == 0)
		//			remainder.pop_back();
		//	}

		//	if (rem)
		//		*rem = std::move(remainder);
		//}


		static void modulo(Poly& ret, const Poly& a, const Poly& mod)
		{
			divide(nullptr, &ret, a, mod);
		}


	};

	template<typename F>
	void hadamarProd(span<F> ret, span<const F> a, span<const F> b)
	{
		if (ret.size() != a.size() || ret.size() != b.size())
			throw RTE_LOC;

		for (u64 i = 0; i < ret.size(); ++i)
			ret[i] = a[i] * b[i];
	}

	template<typename F>
	void hadamarProdAdd(span<F> ret, span<const F> a, span<const F> b)
	{
		if (ret.size() != a.size() || ret.size() != b.size())
			throw RTE_LOC;

		for (u64 i = 0; i < ret.size(); ++i)
			ret[i] += a[i] * b[i];
	}

	template<typename F>
	std::ostream& operator<<(std::ostream& o, const Poly<F>& p)
	{
		o << "[ ";
		if (p.size() == 0)
		{
			o << "0 ";
		}
		for (u64 i = 0; i < p.size(); ++i)
		{
			o << p[i] << " ";
		}

		o << "]";
		return o;
	}
}