

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

		Poly(u64 deg, F coeff)
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
			if (size() == 1 && back() == 0)
				pop_back();

			return *this;
		}

		bool isZero() const {
			return mCoeffs.size() == 0 || (mCoeffs.size() == 1 && mCoeffs[0] == 0);
		}

		void setCoeff(u64 i, const F& f)
		{
			if (mCoeffs.size() <= i)
				mCoeffs.resize(i + 1);

			mCoeffs[i] = f;

			// shrink to fit.
			while (mCoeffs.size() && mCoeffs.back() == 0)
				mCoeffs.pop_back();
		}

		F getCoeff(u64 i)
		{
			if (i < size())
				return mCoeffs[i];
			else
				return 0;
		}

		F& operator[](u64 i)
		{
			return mCoeffs[i];
		}
		const F& operator[](u64 i)const
		{
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
			if (size() != o.size())
				return false;

			for (u64 i = 0; i < size(); ++i)
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
		u64 degree()  const { return mCoeffs.size() ? mCoeffs.size() - 1 : 0; }


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


			auto last = 0ull;
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
			if (mod.back() == 0)
				throw RTE_LOC;
			if (a.size() && a.back() == 0)
				throw RTE_LOC;
			if (&mod == quo || &mod == rem)
				throw RTE_LOC;

			Poly remainder = a;
			if (quo)
				quo->mCoeffs.resize(a.size() - mod.size() + 1);


			while (remainder.size() >= mod.size())
			{
				auto s = mod.back() == 1 ?
					remainder.back() :
					remainder.back() / mod.back();

				if (quo)
					(*quo)[remainder.size() - mod.size()] = s;

				auto d = remainder.size() - mod.size();
				for (u64 i = 0; i < mod.size(); ++i)
				{
					remainder[d + i] -= mod[i] * s;
				}
				assert(remainder.back() == 0);

				while (remainder.size() && remainder.back() == 0)
					remainder.pop_back();
			}

			if (rem)
				*rem = std::move(remainder);
		}


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