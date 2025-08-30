#include "libOTe/Tools/Field/Goldilocks.h"
#include "libOTe/Tools/Field/UInt.h"
#include <stdexcept>
#include <string>
#include "cryptoTools/Common/TestCollection.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace osuCrypto
{
	void ThrowIfNotEqual(u64 actual, u64 expected, const std::string& message = "")
	{
		if (actual != expected)
		{
			throw std::runtime_error("Test failed: " + message +
				"\nActual: " + std::to_string(actual) +
				", Expected: " + std::to_string(expected));
		}
	}

	void Goldilocks_add_Test()
	{
		using namespace osuCrypto;

		// Test values to use
		u64 a_val = 3;
		u64 b_val = 9;
		u64 large_val = 0xFFFFFFFF00000000ULL; // Value near modulus

		// Create Goldilocks elements
		Goldilocks a{ a_val };
		Goldilocks b{ b_val };
		Goldilocks large{ large_val };
		Goldilocks result;

		// Basic addition - Test small values
		result = a + b;
		ThrowIfNotEqual((u64)result, a_val + b_val, "Basic addition");

		// Test addition with operator+= 
		result = a;
		result += b;
		ThrowIfNotEqual((u64)result, a_val + b_val, "Addition with operator+=");

		// Test modular wrapping (p-1) + 1 = 0
		Goldilocks p_minus_1{ Goldilocks::mModulus - 1 };
		Goldilocks one{ 1 };
		result = p_minus_1 + one;
		ThrowIfNotEqual((u64)result, 0, "Modular wrapping (p-1) + 1 = 0");

		// Test addition with non-canonical form values (p+i)
		for (u64 i = 0; i < 100; ++i)
		{
			// Test addition with values beyond modulus (p+i)
			Goldilocks beyond_p(Goldilocks::mModulus + i);

			// (p+i) + a should equal i + a
			result = beyond_p + a;
			ThrowIfNotEqual((u64)result, a_val + i, "Addition with non-canonical forms (p+i) + a");

			// Test negative values (represented as p-i)
			Goldilocks neg_val(-i); // Represents p-i in the field
			Goldilocks canonical_neg = neg_val.canonical();

			result = neg_val + a;
			ThrowIfNotEqual((u64)result, (u64)(a + canonical_neg), "Addition with negative values");

			// Test addition of two non-canonical values
			result = neg_val + neg_val;
			ThrowIfNotEqual((u64)result, (u64)(canonical_neg + canonical_neg), "Addition of two non-canonical values");
		}

		// Test addition near modulus boundary with explicit add function
		Goldilocks::add(result, large, b);
		ThrowIfNotEqual((u64)result, (large_val + b_val) % Goldilocks::mModulus, "Addition near modulus boundary");

		// Test addition where both inputs are near modulus (double carry case)
		Goldilocks near_max1{ Goldilocks::mModulus - 10 };
		Goldilocks near_max2{ Goldilocks::mModulus - 20 };
		result = near_max1 + near_max2;
		// Expected: (p-10) + (p-20) = 2p - 30 ≡ p - 30 (mod p)
		ThrowIfNotEqual((u64)result, Goldilocks::mModulus - 30, "Addition where both inputs are near modulus");

		// Test commutativity: a + b = b + a
		Goldilocks res1 = a + b;
		Goldilocks res2 = b + a;
		ThrowIfNotEqual((u64)res1, (u64)res2, "Commutativity property");

		// Test associativity: (a + b) + c = a + (b + c)
		Goldilocks c{ 15 };
		Goldilocks res3 = (a + b) + c;
		Goldilocks res4 = a + (b + c);
		ThrowIfNotEqual((u64)res3, (u64)res4, "Associativity property");

		// Test identity: a + 0 = a
		Goldilocks zero{ 0 };
		result = a + zero;
		ThrowIfNotEqual((u64)result, a_val, "Identity property with canonical zero");

		// Test identity with non-canonical zero (p ≡ 0)
		Goldilocks zero_noncanonical{ Goldilocks::mModulus };
		result = a + zero_noncanonical;
		ThrowIfNotEqual((u64)result, a_val, "Identity property with non-canonical zero");

		// Test addition with max u64 value
		Goldilocks max_u64{ 0xFFFFFFFFFFFFFFFFULL };
		result = max_u64 + one;
		// Max u64 + 1 wraps to 0 in u64 arithmetic, but in the field it should be different
		// Expected: (max_u64 % p) + 1
		ThrowIfNotEqual((u64)result, ((0xFFFFFFFFFFFFFFFFULL % Goldilocks::mModulus) + 1) % Goldilocks::mModulus,
			"Addition with max u64 value");

		// Test canonical representation before and after addition
		Goldilocks val1{ 42 };
		Goldilocks val2{ Goldilocks::mModulus + 42 }; // Non-canonical form of 42

		ThrowIfNotEqual((u64)val1.canonical(), (u64)val2.canonical(),
			"Canonical representation consistency"); // Both should canonicalize to 42

		result = val1 + val2;
		ThrowIfNotEqual((u64)result, 84, "Addition of canonical and non-canonical forms"); // 42 + 42 = 84

		// Test boundary case: p-1 + p-1 = 2p-2 ≡ p-2 (mod p)
		result = p_minus_1 + p_minus_1;
		ThrowIfNotEqual((u64)result, Goldilocks::mModulus - 2, "Boundary case: p-1 + p-1");

		// Test addition with values in different forms that represent the same element
		Goldilocks x1{ 100 };
		Goldilocks x2{ Goldilocks::mModulus + 100 };  // p+100 ≡ 100 (mod p)
		Goldilocks y{ 200 };

		Goldilocks res_x1y = x1 + y;
		Goldilocks res_x2y = x2 + y;

		ThrowIfNotEqual((u64)res_x1y, (u64)res_x2y, "Addition with different forms of the same element"); // Both should give 300
	}

	void Goldilocks_Sub_Test()
	{
		using namespace osuCrypto;

		// Test subtraction with different value representations
		Goldilocks result;

		// Basic tests with small values
		Goldilocks a{ 100 };
		Goldilocks b{ 30 };
		Goldilocks::sub(result, a, b);
		ThrowIfNotEqual((u64)result, 70, "Simple subtraction"); // Simple subtraction works as expected

		// Test with values in canonical range (0 to p-1)
		Goldilocks p_minus_1{ Goldilocks::mModulus - 1 };  // p-1
		Goldilocks one{ 1 };
		Goldilocks::sub(result, p_minus_1, one);
		ThrowIfNotEqual((u64)result, Goldilocks::mModulus - 2, "Subtraction: (p-1) - 1"); // (p-1) - 1 = p-2

		// Subtracting to get zero
		Goldilocks::sub(result, p_minus_1, p_minus_1);
		ThrowIfNotEqual((u64)result, 0, "Subtraction to zero: (p-1) - (p-1)"); // (p-1) - (p-1) = 0

		// Test with values having dual representations
		// i and p+i represent the same field element when 0 <= i < 2^32-1
		for (u64 i = 1; i < 1000; i += 97) { // Sample some values
			// Create two representations of the same field element
			Goldilocks val1{ i };
			Goldilocks val2{ Goldilocks::mModulus + i }; // p+i ≡ i (mod p)

			// Both should behave identically in subtraction
			Goldilocks r1, r2;
			Goldilocks::sub(r1, val1, b);
			Goldilocks::sub(r2, val2, b);
			ThrowIfNotEqual((u64)r1, (u64)r2, "Subtraction with dual representations");
			ThrowIfNotEqual((u64)r1, (i >= 30) ? (i - 30) : (Goldilocks::mModulus - (30 - i)),
				"Subtraction result with dual representations");
		}

		// Test subtraction with values in the range p to 2^64-1
		// These are valid representations of field elements equivalent to (value mod p)
		Goldilocks large1{ Goldilocks::mModulus + 5 };  // Represents 5
		Goldilocks large2{ Goldilocks::mModulus + 10 }; // Represents 10

		Goldilocks::sub(result, large1, large2);
		// Expected: (p+5) - (p+10) ≡ -5 ≡ p-5 (mod p)
		ThrowIfNotEqual((u64)result, Goldilocks::mModulus - 5, "Subtraction with large values");

		// Test subtraction between canonical and non-canonical representations
		Goldilocks can_5{ 5 };  // Canonical representation of 5
		Goldilocks non_can_10{ Goldilocks::mModulus + 10 }; // Non-canonical representation of 10

		Goldilocks::sub(result, can_5, non_can_10);
		ThrowIfNotEqual((u64)result, Goldilocks::mModulus - 5,
			"Subtraction: canonical - non-canonical"); // 5-10 = -5 ≡ p-5 (mod p)

		Goldilocks::sub(result, non_can_10, can_5);
		ThrowIfNotEqual((u64)result, 5, "Subtraction: non-canonical - canonical"); // 10-5 = 5

		// Test with values close to 2^64 (valid but non-canonical representations)
		Goldilocks near_max_u64{ 0xFFFFFFFFFFFFFF00ULL }; // Close to max u64
		Goldilocks small{ 100 };

		// Calculate expected result: we need to determine what field element this represents
		u64 expected_field_element = 0xFFFFFFFFFFFFFF00ULL % Goldilocks::mModulus;
		expected_field_element = (expected_field_element >= 100) ?
			(expected_field_element - 100) :
			(Goldilocks::mModulus - (100 - expected_field_element));

		Goldilocks::sub(result, near_max_u64, small);
		ThrowIfNotEqual((u64)result, expected_field_element, "Subtraction with near-max u64 value");

		// Test with field element zero in different representations
		Goldilocks zero_canonical{ 0 };
		Goldilocks zero_noncanonical{ Goldilocks::mModulus }; // p ≡ 0 (mod p)

		Goldilocks::sub(result, zero_canonical, one);
		ThrowIfNotEqual((u64)result, Goldilocks::mModulus - 1,
			"Subtraction: 0 - 1"); // 0-1 = -1 ≡ p-1 (mod p)

		Goldilocks::sub(result, zero_noncanonical, one);
		ThrowIfNotEqual((u64)result, Goldilocks::mModulus - 1,
			"Subtraction: non-canonical 0 - 1"); // 0-1 = -1 ≡ p-1 (mod p)

		// Both representations of zero should behave the same in all operations
		Goldilocks r1, r2;
		Goldilocks test_val{ 42 };

		Goldilocks::sub(r1, test_val, zero_canonical);
		Goldilocks::sub(r2, test_val, zero_noncanonical);
		ThrowIfNotEqual((u64)r1, (u64)r2, "Subtraction with different zero representations");
		ThrowIfNotEqual((u64)r1, 42, "Subtraction: val - 0");

		Goldilocks::sub(r1, zero_canonical, test_val);
		Goldilocks::sub(r2, zero_noncanonical, test_val);
		ThrowIfNotEqual((u64)r1, (u64)r2, "Subtraction: different zeros - val");
		ThrowIfNotEqual((u64)r1, Goldilocks::mModulus - 42, "Subtraction: 0 - val");
	}

	void Goldilocks_Mult_Test()
	{
		using namespace osuCrypto;

		auto basicMult = [](Goldilocks in0, Goldilocks in1)
			{
				// First ensure we're working with canonical values
				u64 a = in0.canonical().mVal;
				u64 b = in1.canonical().mVal;
				u64 prod = static_cast<u64>((u128(a) * u128(b)) % u128(Goldilocks::mModulus));
				//u64 prod = (__uint128_t(in0.mVal) * in1.mVal) % __uint128_t(Goldilocks::mModulus);
				return Goldilocks{ prod };
			};

		auto testMultiplication = [&](auto mulFn, const std::string& methodName) {
			// Test values to use
			u64 a_val = 3;
			u64 b_val = 9;
			u64 large_val = 0xFFFFFFFF00000000ULL; // Value near modulus

			// Create Goldilocks elements
			Goldilocks a{ a_val };
			Goldilocks b{ b_val };
			Goldilocks large{ large_val };
			Goldilocks result;

			// Test multiplication with small values
			mulFn(result, a, b);
			ThrowIfNotEqual((u64)result, a_val * b_val, methodName + ": Small values multiplication");

			// Test using multiplication operator
			result = a * b;
			ThrowIfNotEqual((u64)result, a_val * b_val, methodName + ": Multiplication operator");

			// Test multiplication with zero
			Goldilocks zero{ 0 };
			mulFn(result, a, zero);
			ThrowIfNotEqual((u64)result, 0, methodName + ": Multiplication with zero");

			// Test multiplication with one (identity)
			Goldilocks one{ 1 };
			mulFn(result, a, one);
			ThrowIfNotEqual((u64)result, a_val, methodName + ": Multiplication with one");

			// Test multiplication near modulus boundary
			u64 expected = basicMult(large, b);
			mulFn(result, large, b);
			ThrowIfNotEqual((u64)result, expected,
				methodName + ": Multiplication near modulus boundary");

			// Test multiplication with modular wrap-around
			Goldilocks p_half{ Goldilocks::mModulus / 2 };
			Goldilocks two{ 2 };
			mulFn(result, p_half, two);
			// Should be mModulus - 2 since (p/2)*2 = p - 2 mod p
			ThrowIfNotEqual((u64)result, (u64)basicMult(p_half, two),
				methodName + ": Multiplication with wrap-around");

			// Test multiplication with values that cause overflow in 64-bit arithmetic
			Goldilocks big1{ 0xF000000000000000ULL };
			Goldilocks big2{ 0xF000000000000000ULL };
			mulFn(result, big1, big2);
			// Expected result is (0xF000000000000000 * 0xF000000000000000) % mModulus
			expected = basicMult(big1, big2);
			ThrowIfNotEqual((u64)result, expected, methodName + ": Multiplication causing 64-bit overflow");

			// Test multiplication with p-1 (should equal -1 mod p)
			Goldilocks p_minus_1{ Goldilocks::mModulus - 1 };

			// (p-1) * 1 = p-1
			mulFn(result, p_minus_1, one);
			ThrowIfNotEqual((u64)result, Goldilocks::mModulus - 1,
				methodName + ": Multiplication (p-1) * 1");

			// (p-1) * (p-1) = 1 (special case in this field)
			mulFn(result, p_minus_1, p_minus_1);
			ThrowIfNotEqual((u64)result, 1, methodName + ": Multiplication (p-1) * (p-1)");

			// (p-1) * 2 = -2 mod p = p-2
			mulFn(result, p_minus_1, two);
			ThrowIfNotEqual((u64)result, Goldilocks::mModulus - 2,
				methodName + ": Multiplication (p-1) * 2");

			// Test non-canonical values (values larger than modulus)
			Goldilocks non_canonical_a{ Goldilocks::mModulus + a_val }; // Represents a_val
			Goldilocks non_canonical_b{ Goldilocks::mModulus + b_val }; // Represents b_val

			// Both should give same result as canonical values
			mulFn(result, non_canonical_a, non_canonical_b);
			ThrowIfNotEqual((u64)result, a_val * b_val,
				methodName + ": Multiplication with non-canonical values");

			// Test multiplication properties on different representations
			Goldilocks canonical_a = non_canonical_a.canonical();
			mulFn(result, canonical_a, b);
			ThrowIfNotEqual((u64)result, a_val * b_val,
				methodName + ": Multiplication with canonical form");

			// Test values that span the entire u64 range
			Goldilocks max_u64{ 0xFFFFFFFFFFFFFFFFULL }; // Maximum u64 value
			mulFn(result, max_u64, two);
			ThrowIfNotEqual((u64)result, (u64)basicMult(max_u64, two),
				methodName + ": Multiplication with max u64 value");

			// Test commutativity: a * b = b * a
			Goldilocks res1, res2;
			mulFn(res1, a, b);
			mulFn(res2, b, a);
			ThrowIfNotEqual((u64)res1, (u64)res2, methodName + ": Commutativity property");

			// Test associativity: (a * b) * c = a * (b * c)
			Goldilocks c{ 15 };
			Goldilocks temp;
			mulFn(temp, a, b);
			mulFn(res1, temp, c);

			mulFn(temp, b, c);
			mulFn(res2, a, temp);
			ThrowIfNotEqual((u64)res1, (u64)res2, methodName + ": Associativity property");

			// Test distributivity: a * (b + c) = a * b + a * c
			Goldilocks b_plus_c;
			Goldilocks::add(b_plus_c, b, c);
			mulFn(res1, a, b_plus_c);

			Goldilocks a_mul_b, a_mul_c;
			mulFn(a_mul_b, a, b);
			mulFn(a_mul_c, a, c);
			Goldilocks::add(res2, a_mul_b, a_mul_c);
			ThrowIfNotEqual((u64)res1, (u64)res2, methodName + ": Distributivity property");

			// Test multiplication by values close to 2^32 (special in Goldilocks field)
			Goldilocks near_2pow32{ (1ULL << 32) - 5 };
			mulFn(result, near_2pow32, large);
			ThrowIfNotEqual((u64)result, (u64)basicMult(near_2pow32, large),
				methodName + ": Multiplication with values close to 2^32");

			// Test increment (simple addition by 1)
			Goldilocks inc_test{ 42 };
			Goldilocks::increment(result, inc_test);
			ThrowIfNotEqual((u64)result, 43, methodName + ": Increment operation");

			// Test increment at modulus boundary
			Goldilocks::increment(result, p_minus_1);
			ThrowIfNotEqual((u64)result, 0, methodName + ": Increment at modulus boundary");

			// Test decrement (simple subtraction by 1)
			Goldilocks dec_test{ 42 };
			Goldilocks::decrement(result, dec_test);
			ThrowIfNotEqual((u64)result, 41, methodName + ": Decrement operation");

			// Test decrement at zero
			Goldilocks::decrement(result, zero);
			ThrowIfNotEqual((u64)result, Goldilocks::mModulus - 1, methodName + ": Decrement at zero");

			// Test with specific values known to be special in Goldilocks field
			Goldilocks pow2_32{ 1ULL << 32 };
			mulFn(result, pow2_32, pow2_32);
			ThrowIfNotEqual((u64)result, (u64)basicMult(pow2_32, pow2_32),
				methodName + ": Multiplication with 2^32");

			// Test squaring behavior (a*a)
			for (u64 i = 1; i < 20; i++) {
				Goldilocks val{ i };
				Goldilocks square_result;
				mulFn(square_result, val, val);
				ThrowIfNotEqual((u64)square_result, i * i,
					methodName + ": Squaring value " + std::to_string(i));
			}

			// Test consecutive multiplications
			Goldilocks running_product{ 1 }; // Start with identity
			Goldilocks factor{ 7 };
			u64 expected_product = 1;

			for (int i = 0; i < 10; i++) {
				expected_product = (expected_product * 7) % Goldilocks::mModulus;
				mulFn(running_product, running_product, factor);
				ThrowIfNotEqual((u64)running_product, expected_product,
					methodName + ": Consecutive multiplication " + std::to_string(i));
			}
			};

		testMultiplication(Goldilocks::mulPzt22, "mulPzt22");
		//testMultiplication(Goldilocks::mulBerrettV1, "mulBerrettV1");
		//testMultiplication(Goldilocks::mulBerrettV2, "mulBerrettV2");
	}



	void Goldilocks_SIMD_Mul_Test()
	{
#if 0

		auto test = [](auto mult) {

			auto check4 = [&](std::array<u64,4> a, std::array<u64,4> b,
				const std::string& msg)
				{
					u64 exp0 =Goldilocks{a[0]} * Goldilocks{b[0]};
					u64 exp1 =Goldilocks{a[1]} * Goldilocks{b[1]};
					u64 exp2 =Goldilocks{a[2]} * Goldilocks{b[2]};
					u64 exp3 =Goldilocks{a[3]} * Goldilocks{b[3]};

					u64 got[4];
					mult(got, a.data(), b.data());

					// Compare canonical representatives
					ThrowIfNotEqual(Goldilocks{got[0]}.integer(), exp0, msg + " lane0");
					ThrowIfNotEqual(Goldilocks{got[1]}.integer(), exp1, msg + " lane1");
					ThrowIfNotEqual(Goldilocks{got[2]}.integer(), exp2, msg + " lane2");
					ThrowIfNotEqual(Goldilocks{got[3]}.integer(), exp3, msg + " lane3");
				};

			// Edge cases
			const u64 P = Goldilocks::mModulus;
			//const u64 ZERO = 0;
			//const u64 ONE = 1;
			//const u64 TWO = 2;
			const u64 MAXU = 0xFFFFFFFFFFFFFFFFull;
			const u64 EPS = (1ull << 32) - 1;     // 2^32 - 1
			const u64 POW2_32 = (1ull << 32);

			// 1) Zeros and ones
			check4({ 0, 1, 2, 3 }, { 0, 1, 2, 3 }, "basic 0..3");
			check4({0, 0, 0, 0}, {5, 0, 7, 1}, "zeros");
			check4({ 1, 1, 1, 1 }, { 1, 2, P - 1, POW2_32 }, "ones*var");

			// 2) p-1 behavior
			check4({ P - 1, P - 1, P - 1, P - 1 }, { 1, 2, P - 1, POW2_32 }, "p-1 cases");

			// 3) Near special 2^32 boundary
			check4({ EPS - 1, EPS, EPS + 1, POW2_32 + 5 },
				{ EPS + 2, POW2_32 - 1, POW2_32, POW2_32 + 7 },
				"near 2^32");

			// 4) Large values and wrap
			check4({ MAXU, MAXU - 1, MAXU - 2, MAXU - 3 },
				{ 2, 3, 5, 7 },
				"large values");

			// 5) Values representing non-canonical elements (>= p)
			// Provide arbitrary u64 which are valid representatives.
			check4({ P, P + 1, P + 12345, MAXU },
				{ 11, 13, 17, 19 },
				"non-canonical inputs");

			// 6) Randomized test vectors
			{
				PRNG prng(CCBlock);
				const size_t iters = 4000;
				for (size_t i = 0; i < iters; ++i)
				{
					u64 a0 = prng.get<u64>(), a1 = prng.get<u64>(), a2 = prng.get<u64>(), a3 = prng.get<u64>();
					u64 b0 = prng.get<u64>(), b1 = prng.get<u64>(), b2 = prng.get<u64>(), b3 = prng.get<u64>();
					check4({ a0, a1, a2, a3 }, { b0, b1, b2, b3 }, "random");
				}
			}
			};

		test(mulPzt22x4<4>);



#endif
	}



	void Goldilocks_Inverse_Test()
	{
		using namespace osuCrypto;

		// Test values to use
		u64 a_val = 5;
		u64 b_val = 7;
		u64 large_val = 0xFFFFFFF000000000ULL; // Value near modulus

		// Create Goldilocks elements
		Goldilocks a{ a_val };
		Goldilocks b{ b_val };
		Goldilocks large{ large_val };
		Goldilocks zero{ 0 };
		Goldilocks one{ 1 };
		Goldilocks result;

		// Test inverse of 1 is 1
		Goldilocks::inv(result, one);
		ThrowIfNotEqual((u64)result, 1, "Inverse of 1");

		// Test a * a^-1 = 1
		Goldilocks inv_a;
		Goldilocks::inv(inv_a, a);
		Goldilocks mul_result;
		Goldilocks::mul(mul_result, a, inv_a);
		ThrowIfNotEqual((u64)mul_result, 1, "a * a^-1 = 1");

		// Test b * b^-1 = 1
		Goldilocks inv_b;
		Goldilocks::inv(inv_b, b);
		Goldilocks::mul(mul_result, b, inv_b);
		ThrowIfNotEqual((u64)mul_result, 1, "b * b^-1 = 1");

		// Test large value inverse
		Goldilocks inv_large;
		Goldilocks::inv(inv_large, large);
		Goldilocks::mul(mul_result, large, inv_large);
		ThrowIfNotEqual((u64)mul_result, 1, "large * large^-1 = 1");

		// Test inverse of value + modulus is the same as the inverse of value
		Goldilocks p_plus_a{ a_val + Goldilocks::mModulus };
		Goldilocks inv_p_plus_a;
		Goldilocks::inv(inv_p_plus_a, p_plus_a);
		ThrowIfNotEqual((u64)inv_a, (u64)inv_p_plus_a, "inv(a + p) = inv(a)");

		// Test that the inv function correctly handles canonical representation
		Goldilocks canonical_a = a.canonical();
		Goldilocks inv_canonical_a;
		Goldilocks::inv(inv_canonical_a, canonical_a);
		ThrowIfNotEqual((u64)inv_a, (u64)inv_canonical_a, "inv(canonical(a)) = inv(a)");

		// Test inverse of zero (we define it to be zero)
		Goldilocks inv_zero;
		Goldilocks::inv(inv_zero, zero);
		ThrowIfNotEqual((u64)inv_zero, 0, "Inverse of zero"); // Inverse of zero should be defined as zero

		// Test inverse of modulus - 1
		Goldilocks p_minus_1{ Goldilocks::mModulus - 1 };
		Goldilocks inv_p_minus_1;
		Goldilocks::inv(inv_p_minus_1, p_minus_1);
		ThrowIfNotEqual((u64)inv_p_minus_1, p_minus_1.canonical().mVal, "inv(p-1) = p-1"); // Inverse of p-1 is p-1
	}

	void Goldilocks_Exp_Test()
	{
		using namespace osuCrypto;

		// Test values
		Goldilocks base{ 2 };        // Base value 2
		Goldilocks result;           // Result of exponentiation

		// Test basic exponentiation cases

		// Test x^0 = 1 for any x ≠ 0
		Goldilocks::pow(result, base, 0);
		ThrowIfNotEqual((u64)result, 1, "x^0 = 1");

		// Test x^1 = x
		Goldilocks::pow(result, base, 1);
		ThrowIfNotEqual((u64)result, 2, "x^1 = x");

		// Test x^2 = x*x
		Goldilocks::pow(result, base, 2);
		ThrowIfNotEqual((u64)result, 4, "x^2 = x*x");

		// Test x^3 = x*x*x
		Goldilocks::pow(result, base, 3);
		ThrowIfNotEqual((u64)result, 8, "x^3 = x*x*x");

		// Test larger exponents
		Goldilocks::pow(result, base, 10);
		ThrowIfNotEqual((u64)result, 1024, "2^10 = 1024"); // 2^10 = 1024

		// Test exponentiation with a different base
		Goldilocks base3{ 3 };

		// 3^0 = 1
		Goldilocks::pow(result, base3, 0);
		ThrowIfNotEqual((u64)result, 1, "3^0 = 1");

		// 3^1 = 3
		Goldilocks::pow(result, base3, 1);
		ThrowIfNotEqual((u64)result, 3, "3^1 = 3");

		// 3^2 = 9
		Goldilocks::pow(result, base3, 2);
		ThrowIfNotEqual((u64)result, 9, "3^2 = 9");

		// 3^3 = 27
		Goldilocks::pow(result, base3, 3);
		ThrowIfNotEqual((u64)result, 27, "3^3 = 27");

		// Test modular behavior with large values that would overflow normal arithmetic

		// Test 2^63 which would be too large for normal 64-bit integers
		Goldilocks::pow(result, base, 63);
		// Expected: (2^63) mod p
		// Should be 9223372036854775808 (2^63)
		ThrowIfNotEqual((u64)result, 9223372036854775808ULL, "2^63 in Goldilocks field");

		// Test that exponentiation handles the modular reduction correctly
		Goldilocks big_base{ Goldilocks::mModulus - 1 }; // Using p-1 as base

		// (p-1)^1 = p-1
		Goldilocks::pow(result, big_base, 1);
		ThrowIfNotEqual((u64)result, Goldilocks::mModulus - 1, "(p-1)^1 = p-1");

		// (p-1)^2 = 1 in the field (by Fermat's little theorem)
		Goldilocks::pow(result, big_base, 2);
		ThrowIfNotEqual((u64)result, 1, "(p-1)^2 = 1");

		// Test 0^exp = 0 for any exp > 0
		Goldilocks zero{ 0 };
		Goldilocks::pow(result, zero, 10);
		ThrowIfNotEqual((u64)result, 0, "0^10 = 0");

		// Test 0^0 = 1 (mathematical convention)
		Goldilocks::pow(result, zero, 0);
		ThrowIfNotEqual((u64)result, 1, "0^0 = 1");

		// Test large exponents
		// We know that for any element x in the field, x^(p-1) = 1
		// So 2^(p-1) = 1
		Goldilocks::pow(result, base, Goldilocks::mModulus - 1);
		ThrowIfNotEqual((u64)result, 1, "2^(p-1) = 1 (Fermat's Little Theorem)");

		// Test exp using multiplication (verify implementation correctness)
		Goldilocks manual_result{ 1 };
		u64 exponent = 20; // Use a moderate exponent to avoid excessive computation

		// Calculate 2^20 manually
		for (u64 i = 0; i < exponent; i++) {
			Goldilocks::mul(manual_result, manual_result, base);
		}

		// Compare with exp function
		Goldilocks::pow(result, base, exponent);
		ThrowIfNotEqual((u64)result, (u64)manual_result,
			"Exponential calculation consistency check with manual multiplication");
	}
}