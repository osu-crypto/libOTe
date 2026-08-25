

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
		const auto maxExponent = std::numeric_limits<u64>::max();
		if (a.pow(maxExponent) != a.pow(maxExponent % (F::order() - 1)))
			throw RTE_LOC;
		expectRejected([&] { (void)a.pow(i64{ -1 }); });
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

		CoeffCtxFp fpCtx;
		std::array<u8, sizeof(F12289)> noncanonicalBytes;
		noncanonicalBytes.fill(0xff);
		F12289 noncanonical = 0;
		expectInvalid([&]
		{
			fpCtx.deserialize(
				noncanonicalBytes.begin(), noncanonicalBytes.end(), &noncanonical);
		});
		if (noncanonical != F12289::zero())
			throw RTE_LOC;

		F12289 canonical = 4091;
		std::array<u8, sizeof(F12289)> canonicalBytes{};
		fpCtx.serialize(&canonical, &canonical + 1, canonicalBytes.begin());
		F12289 canonicalRoundTrip = 0;
		fpCtx.deserialize(
			canonicalBytes.begin(), canonicalBytes.end(), &canonicalRoundTrip);
		if (canonicalRoundTrip != canonical)
			throw RTE_LOC;

		block fpSample = ZeroBlock;
		const auto fpThreshold = fieldSampling::rejectionThreshold(Fp31::mMod);
		fpSample.set<u64>(0, fpThreshold - 1);
		fpSample.set<u64>(1, fpThreshold + 7);
		Fp31 mappedFp;
		fpCtx.fromBlock(mappedFp, fpSample);
		if (mappedFp.mVal != (fpThreshold + 7) % Fp31::mMod)
			throw RTE_LOC;

		using GoldCtx = DefaultCoeffCtx<Goldilocks>;
		static_assert(std::is_same_v<GoldCtx, CoeffCtxGoldilocks>);
		GoldCtx goldCtx;
		block goldSample = ZeroBlock;
		const auto goldThreshold =
			fieldSampling::rejectionThreshold(Goldilocks::mModulus);
		goldSample.set<u64>(0, goldThreshold - 1);
		goldSample.set<u64>(1, goldThreshold + 11);
		Goldilocks mappedGold;
		goldCtx.fromBlock(mappedGold, goldSample);
		if (mappedGold.mVal != goldThreshold + 11 ||
			!goldCtx.template isField<Goldilocks>() ||
			goldCtx.template additiveGroupBitCount<Goldilocks>() != 64)
			throw RTE_LOC;

		using VF2 = FVec<Fp31, 2>;
		using VF4 = FVec<Fp31, 4>;
		using VCtx = DefaultCoeffCtx<VF4>;
		static_assert(std::is_same_v<VCtx, CoeffCtxFVec<Fp31, 4>>);

		CoeffCtxFVec<Fp31, 2> vec2Ctx;
		if (vec2Ctx.template byteSize<VF2>() != 2 * sizeof(Fp31) ||
			vec2Ctx.template bitSize<VF2>() != 2 * sizeof(Fp31) * 8 ||
			vec2Ctx.template additiveGroupBitCount<VF2>() != log2ceil(Fp31::mMod))
			throw RTE_LOC;

		VF2 vec2{ Fp31(11), Fp31(29) };
		std::array<u8, sizeof(VF2)> vecBytes;
		vecBytes.fill(0xa5);
		vec2Ctx.serialize(&vec2, &vec2 + 1, vecBytes.begin());
		for (u64 i = vec2Ctx.template byteSize<VF2>(); i < vecBytes.size(); ++i)
			if (vecBytes[i] != 0xa5)
				throw RTE_LOC;

		VF2 vec2RoundTrip;
		std::memset(&vec2RoundTrip, 0xcc, sizeof(vec2RoundTrip));
		vec2Ctx.deserialize(
			vecBytes.begin(),
			vecBytes.begin() + vec2Ctx.template byteSize<VF2>(),
			&vec2RoundTrip);
		if (vec2RoundTrip != vec2)
			throw RTE_LOC;
		for (u64 i = 2 * sizeof(Fp31); i < sizeof(VF2); ++i)
			if (reinterpret_cast<u8*>(&vec2RoundTrip)[i] != 0)
				throw RTE_LOC;

		vecBytes[0] = vecBytes[1] = vecBytes[2] = vecBytes[3] = 0xff;
		expectInvalid([&]
		{
			vec2Ctx.deserialize(
				vecBytes.begin(),
				vecBytes.begin() + vec2Ctx.template byteSize<VF2>(),
				&vec2RoundTrip);
		});
		if (vec2RoundTrip != VF2::zero())
			throw RTE_LOC;

		VCtx vec4Ctx;
		VF4 sampled;
		vec4Ctx.fromBlock(sampled, AllOneBlock);
		for (auto& lane : sampled.v)
			if (!vec4Ctx.mScalarCtx.isCanonical(lane))
				throw RTE_LOC;

		VF4 gapPower;
		vec4Ctx.powerOfTwoUnchecked(gapPower, 31);
		if (gapPower != VF4::zero())
			throw RTE_LOC;

		auto decomposition = vec4Ctx.binaryDecomposition(sampled);
		VF4 reconstructed = VF4::zero();
		for (u64 i = 0; i < decomposition.size(); ++i)
		{
			if (decomposition[i])
			{
				VF4 power;
				vec4Ctx.powerOfTwoUnchecked(power, i);
				reconstructed += power;
			}
		}
		if (reconstructed != sampled)
			throw RTE_LOC;
	}

}
