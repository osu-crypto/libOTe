#include <iostream>
#include <sstream>
#include <stdexcept>
#include "libOTe/Tools/Field/UInt.h"

using namespace osuCrypto;

using u256 = UInt<256>;
using u512 = UInt<512>;

void fail(const std::string& msg) {
    throw std::runtime_error(msg);
}

#define ASSERT_TRUE(expr) do { if(!(expr)) fail(std::string("ASSERT_TRUE failed: " #expr " at ")+__FILE__+":"+std::to_string(__LINE__)); } while(0)
#define ASSERT_EQ(a,b) do { auto _av=(a); auto _bv=(b); if(!((_av)==(_bv))) { \
    std::ostringstream _oss; _oss<<"ASSERT_EQ failed at "<<__FILE__<<":"<<__LINE__<<": left="<<_av<<" right="<<_bv; \
    fail(_oss.str()); } } while(0)

// Helpers
template<std::size_t W>
UInt<W> limbs(std::initializer_list<u64> L) {
    UInt<W> x;
    x.v.fill(0);
    std::size_t i = 0;
    for (auto w : L) {
        if (i >= UInt<W>::limbs) fail("too many limbs in helper");
        x.v[i++] = w;
    }
    return x;
}

template<std::size_t W>
UInt<W> pow2(std::size_t k) {
    if (k >= W) fail("pow2 overflow");
    UInt<W> x;
    x.v.fill(0);
    x.v[k / 64] = (u64(1) << (k % 64));
    return x;
}

template<std::size_t W>
UInt<W> all_ones() {
    UInt<W> x;
    for (std::size_t i = 0; i < UInt<W>::limbs; ++i) x.v[i] = ~u64(0);
    return x;
}

void UInt_Basics_Test() {
    {
        u128 z; // zero
        ASSERT_TRUE(z.is_zero());
        u128 o = u128::one();
        ASSERT_TRUE(!o.is_zero());
        ASSERT_TRUE(static_cast<bool>(o));
        ASSERT_EQ(static_cast<u64>(o), u64(1));
    }
    {
        u256 a(5), b(7);
        ASSERT_TRUE(a < b);
        ASSERT_TRUE(b > a);
        ASSERT_TRUE(a != b);
        ASSERT_TRUE(!(a == b));
        ASSERT_TRUE((a + u256::zero()) == a);
        ASSERT_TRUE((a - u256::zero()) == a);
    }
}

void UInt_Bitwise_Test() {
    u128 a = limbs<128>({ 0xF0F0F0F0F0F0F0F0ull, 0xAAAAAAAAAAAAAAAAull });
    u128 b = limbs<128>({ 0x0F0F0F0F0F0F0F0Full, 0x5555555555555555ull });
    ASSERT_EQ((a & b), u128::zero());
    ASSERT_EQ((a | b), all_ones<128>());
    ASSERT_EQ((a ^ b), all_ones<128>());
    ASSERT_EQ((~a & all_ones<128>()), b);
}

void UInt_Shifts_Test() {
    // Start with 0x...0001
    u256 x = u256::one();

    // << small
    u256 y = x << 1;
    ASSERT_EQ(y, limbs<256>({ 2,0,0,0 }));

    // << across limb
    y = x << 64;
    ASSERT_EQ(y, limbs<256>({ 0,1,0,0 }));

    // << across limb + bits
    y = x << 65;
    ASSERT_EQ(y, limbs<256>({ 0,2,0,0 }));

    // >> back
    ASSERT_EQ((y >> 65), x);

    // shift by 0
    ASSERT_EQ((x << 0), x);
    ASSERT_EQ((x >> 0), x);

    // shift by max-1 bit
    u256 z = x << (u256::bits - 1);
    ASSERT_EQ(z.v[3], (1ull << 63));
    ASSERT_EQ((z >> (u256::bits - 1)), x);

    // shift >= bit width => zero
    ASSERT_EQ((x << u256::bits), u256::zero());
    ASSERT_EQ((x >> u256::bits), u256::zero());
}

void UInt_AddSub_Test() {
    // (all ones) + 1 == 0 (mod 2^W)
    u128 max = all_ones<128>();
    u128 z = max + u128::one();
    ASSERT_TRUE(z.is_zero());

    // borrow: 0 - 1 == (all ones)
    u128 z2 = u128::zero() - u128::one();
    ASSERT_EQ(z2, max);

    // carries across multiple limbs
    u256 a = limbs<256>({ ~u64(0), ~u64(0), 0, 0 });
    u256 b(1);
    u256 c = a + b;
    ASSERT_EQ(c, limbs<256>({ 0,0,1,0 }));

    // subtraction borrow across limbs
    u256 d = c - b;
    ASSERT_EQ(d, a);
}

void UInt_MulU64_Test() {
    // Single-limb * scalar
    u256 a = limbs<256>({ 0xFFFFFFFFFFFFFFFFull, 0,0,0 });
    u256 b = a * u64(2);
    ASSERT_EQ(b, limbs<256>({ 0xFFFFFFFFFFFFFFFEull, 1,0,0 }));

    // Multi-limb * scalar with carries chaining
    u256 x = limbs<256>({ 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull, 0, 0 });
    u256 y = x * u64(2);
    ASSERT_EQ(y, limbs<256>({ 0xFFFFFFFFFFFFFFFEull, 0xFFFFFFFFFFFFFFFFull, 1, 0 }));
}

void UInt_MulFull_Test() {
    // (2^64 - 1) * (2^64 - 1) = 2^128 - 2^65 + 1
    u128 a = limbs<128>({ 0xFFFFFFFFFFFFFFFFull, 0 });
    u128 b = a;
    u128 p = a * b;

    // expected:
    // low limb: 1
    // high limb: (2^64 - 2) = 0xFFFFFFFFFFFFFFFE
    ASSERT_EQ(p, limbs<128>({ 1ull, 0xFFFFFFFFFFFFFFFEull }));

    // cross-check multi-limb accumulation
    u256 m = limbs<256>({ 0x1111111111111111ull, 0x2222222222222222ull, 0, 0 });
    u256 n = limbs<256>({ 0x3333333333333333ull, 0x4444444444444444ull, 0, 0 });
    u256 prod = m * n; // correctness smoke test via identities
    // Check simple identities: (m*n) == ( (m<<64)* (n>>64) + ... ) is complicated,
    // so just verify distributivity with scalars as a light check:
    u256 m2 = m + m; // 2m
    u256 n2 = n + n; // 2n
    ASSERT_EQ(prod + prod, m2 * n); // (m*n)*2 == (2m)*n
    ASSERT_EQ(prod + prod, m * n2); // == m*(2n)
}

void UInt_DivBasic_Test() {
    // small within single limb
    u128 a(100);
    u128 b(7);
    u128 q, r;
    UInt<128>::div(a, b, q, r);
    ASSERT_EQ(q, u128(14));
    ASSERT_EQ(r, u128(2));

    // numerator < denominator
    u128 q2, r2;
    UInt<128>::div(u128(5), u128(10), q2, r2);
    ASSERT_TRUE(q2.is_zero());
    ASSERT_EQ(r2, u128(5));

    // exact division
    u256 N = limbs<256>({ 0,0,0,1 });         // 2^192
    u256 D = limbs<256>({ 0,0,0,1 });         // 2^192
    u256 Q, R;
    UInt<256>::div(N, D, Q, R);
    ASSERT_EQ(Q, u256::one());
    ASSERT_TRUE(R.is_zero());
}

void UInt_DivMultilimb_Test() {
    // Construct a 256-bit number: N = (2^255 + 2^129 + 2^65 + 12345)
    u256 N = pow2<256>(255) + pow2<256>(129) + pow2<256>(65) + u256(12345);

    // D = (2^200 + 2^130 + 9)
    u256 D = pow2<256>(200) + pow2<256>(130) + u256(9);

    u256 Q, R;
    UInt<256>::div(N, D, Q, R);

    // Validate: N = Q*D + R  and  R < D
    u256 recon = (Q * D) + R;
    ASSERT_EQ(recon, N);
    ASSERT_TRUE(R < D);

    // Spot-check dividing by power of two: D = 2^k
    for (int k : {1, 63, 64, 65, 127, 128, 191, 192}) {
        u256 DD = pow2<256>(k);
        u256 QQ, RR;
        UInt<256>::div(N, DD, QQ, RR);

        // Expect QQ = N >> k, RR = N & ((1<<k)-1)
        u256 expectQ = N >> k;

        // Mask for k bits
        u256 mask;
        if (k == 256) {
            mask = u256::zero();
        }
        else {
            if (k == 0) mask = all_ones<256>();
            else mask = (pow2<256>(k) - u256::one());
        }
        u256 expectR = N & mask;

        ASSERT_EQ(QQ, expectQ);
        ASSERT_EQ(RR, expectR);
    }
}

void UInt_Stream_Test() {
    u128 a = limbs<128>({ 0, 0x1234 });
    std::ostringstream oss;
    oss << a;
    // Highest limb printed without zero-padding, lower with width=16
    ASSERT_EQ(oss.str(), std::string("0x12340000000000000000"));
}

void UInt_Conversions_Test() {
    u128 a(0);
    ASSERT_TRUE(!static_cast<bool>(a));
    u128 b(42);
    ASSERT_TRUE(static_cast<bool>(b));
    ASSERT_EQ(static_cast<u64>(b), u64(42));

    // truncation to u64: take least-significant limb
    u256 x = limbs<256>({ 0x9988776655443322ull, 0xAAAAAAAAAAAAAAAAull, 0, 0 });
    ASSERT_EQ(static_cast<u64>(x), 0x9988776655443322ull);
}
//
//int main() {
//    try {
//        // Basic sanity about template constants
//        static_assert(u128::bits == 128);
//        static_assert(u128::limbs == 2);
//        static_assert(u256::limbs == 4);
//        static_assert(u512::limbs == 8);
//
//        UInt_Basics_Test();
//        UInt_Bitwise_Test();
//        UInt_Shifts_Test();
//        UInt_AddSub_Test();
//        UInt_MulU64_Test();
//        UInt_MulFull_Test();
//        UInt_DivBasic_Test();
//        UInt_DivMultilimb_Test();
//        UInt_Stream_Test();
//        UInt_Conversions_Test();
//
//        std::cout << "[OK] All tests passed.\n";
//        return 0;
//    }
//    catch (const std::exception& e) {
//        std::cerr << "[FAIL] " << e.what() << "\n";
//        return 1;
//    }
//}