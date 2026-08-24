

#include "libOTe/Tools/Field/Fp.h"
#include "libOTe/Tools/Field/GF128.h"
#include "libOTe/Tools/Field/FVec.h"
#include "libOTe/Tools/Field/Goldilocks.h"

#include "libOTe/Tools/Ntt/Poly.h"
#include "Field_Tests.h"
using namespace osuCrypto;
#include <vector>

namespace tests_libOTe
{


	template<typename F>
	void VecField_Test()
	{
		PRNG prng(AllOneBlock);

		for (u64 i = 0; i < 100; ++i)
		{
			FVec<F, 4> a(prng.get()), b(prng.get());
			auto c = a + b;
			auto d = b + a;
			if (c != d)
				throw RTE_LOC;
			c = a - b;
			d = a + (-b);
			if (c != d)
			{
				std::cout << "a" << a << std::endl;
				std::cout << "b" << b << std::endl;
				std::cout << "c" << c << std::endl;
				std::cout << "d" << d << std::endl;
				throw RTE_LOC;
			}
			c = a * b;
			d = b * a;
			if (c != d)
				throw RTE_LOC;

			auto aInv = a.inverse();
			c = a * aInv;
			for (u64 j = 0; j < a.size_static; ++j)
				if (a[j] != 0)
				{
					if (c[j] != 1)
						throw RTE_LOC;
				}
		}
	}

	template<typename F>
	void Field_Test()
	{
		PRNG prng(AllOneBlock);

		// Test basic field properties
		F a(prng.get()), b(prng.get());

		a = 1467;
		b = 2489;

		auto c = a + b;
		auto d = b + a;
		if (c != d)
			throw RTE_LOC;

		c = a - b;
		d = a + (-b);
		if (c != d)
			throw RTE_LOC;

		c = a * b;
		d = b * a;
		if (c != d)
			throw RTE_LOC;

		if (a != 0)
		{
			auto aInv = a.inverse();
			c = a * aInv;
			if (c != 1)
				throw RTE_LOC;
		}

		auto g = findGenerator<F>(prng);
		//std::cout << "Generator: " << g << std::endl;

		auto factors = uniqueFactor(F::order() - 1);

		// compute some valid n of the form  n = p1^e1 * p2^e2 * ... * pk^ek
		// where p1, p2, ..., pk are the prime factors of (p-1).
		std::vector<u64> ns;
		for (u64 i = 0; i < 10; ++i)
		{
			u64 n = 1;
			for (auto fe : factors)
			{
				auto e = (prng.get<u64>() % fe.mExp) + 1;
				u64 f = 1;
				for (u64 j = 0; j < e; ++j)
					f *= fe.mFactor;
				//std::cout << fe.mFactor << "^" << e << " " << std::endl;
				n *= f;
			}
			ns.push_back(n);
			//std::cout << "  " << n << std::endl;
		}

		for (auto n : ns)
		{
			auto unity = primRootOfUnity<F>(n, g);

			// Check that it is an n-th root of unity
			if (unity.pow(n) != 1)
				throw RTE_LOC;

			// Check that it is a primitive n-th root of unity
			if (!isPrimRootOfUnity(n, unity))
			{
				std::cout << unity << " is not a primitive root of unity for n = " << n << std::endl;
				std::cout << " (p-1) = " << (F::mMod - 1) / n << " n + " << (F::mMod - 1) % n << std::endl;
				for (u64 i = 1; i < n; ++i)
				{
					if (unity.pow(i) == 1)
					{
						std::cout << "It is a " << i << "-th root of unity." << std::endl;
						break;
					}
				}
				throw RTE_LOC;
			}
		}

	}


	void Field_F7681_Test()
	{
		Field_Test<F7681>();


		{
			using F32769 = Fp<32769, u16, u32>;
			F32769 a(12345), b(67890);
			auto c = F32769::barrettMul(a, b);
			if (c.mVal != (12345 * 67890) % 32769)
			{
				std::cout << "p=32769 berrett multiplication failed: "
					<< c.mVal << " != " << (12345 * 67890 % 32769) << std::endl;
				throw RTE_LOC;
			}
		}
	}

	void Field_F12289_Test()
	{
		Field_Test<F12289>();
		VecField_Test<F12289>();
	}


	void Field_Fp31_Test()
	{
		Field_Test<Fp31>();
		VecField_Test<Fp31>();
	}



	void Field_GF128_Test()
	{
		//GF128 g;
	}

	void Field_Audit_Test()
	{
		using F = F7681;

		auto expectInvalid = [](auto&& fn)
		{
			bool rejected = false;
			try
			{
				fn();
			}
			catch (const std::invalid_argument&)
			{
				rejected = true;
			}
			if (!rejected)
				throw RTE_LOC;
		};
		auto expectRejected = [](auto&& fn)
		{
			bool rejected = false;
			try
			{
				fn();
			}
			catch (const std::exception&)
			{
				rejected = true;
			}
			if (!rejected)
				throw RTE_LOC;
		};

		F a = 3;
		if (a.pow(F::order() + 1) != a * a)
			throw RTE_LOC;
		if (F::zero().inverse() != F::zero())
			throw RTE_LOC;

		bool divisionRejected = false;
		try
		{
			(void)(a / F::zero());
		}
		catch (const std::domain_error&)
		{
			divisionRejected = true;
		}
		if (!divisionRejected)
			throw RTE_LOC;

		F minusOne = F::order() - 1;
		if (isPrimRootOfUnity<F>(8, minusOne))
			throw RTE_LOC;
		if (!isPrimRootOfUnity<F>(1, F::one()))
			throw RTE_LOC;

		expectInvalid([&] { (void)primRootOfUnity<F>(0, F(2)); });
		expectInvalid([&] { (void)primRootOfUnity<F>(7, F(2)); });
		expectInvalid([&] { (void)primRootOfUnity<Fp31>(u64{ 1 } << 28); });
		expectInvalid([&] { (void)primRootOfUnity<Goldilocks>(u64{ 1 } << 33); });

		using WideFp = Fp<32769, u16, u32>;
		const WideFp wideMax = 32768;
		if (wideMax + wideMax != WideFp(32767) ||
			WideFp(0) - wideMax != WideFp(1))
			throw RTE_LOC;
		auto wideAccum = wideMax;
		wideAccum += wideMax;
		if (wideAccum != WideFp(32767))
			throw RTE_LOC;
		wideAccum = 0;
		wideAccum -= wideMax;
		if (wideAccum != WideFp(1))
			throw RTE_LOC;

		CoeffCtxInteger ctx;
		u8 coefficient = 0;
		expectRejected([&] { ctx.powerOfTwo(coefficient, 8); });
		ctx.powerOfTwo(coefficient, 7);
		if (coefficient != 0x80)
			throw RTE_LOC;

		std::array<u8, 3> bytes{ 1, 2, 3 };
		std::array<u8, 3> copy{};
		expectRejected([&] { ctx.copy(bytes.end(), bytes.begin(), copy.begin()); });
		expectRejected([&] { ctx.zero(bytes.end(), bytes.begin()); });
		expectRejected([&] { ctx.one(bytes.end(), bytes.begin()); });
		u16 decoded = 0;
		auto byteBegin = bytes.begin();
		auto byteEnd = bytes.end();
		auto decodedBegin = &decoded;
		expectRejected([&] { ctx.deserialize(byteBegin, byteEnd, decodedBegin); });
	}

}
