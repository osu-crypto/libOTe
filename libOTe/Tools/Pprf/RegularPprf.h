#pragma once
#include "libOTe/config.h"

#ifdef ENABLE_PPRF
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/Coproto.h"
#include "libOTe/Tools/CompilerHints.h"
#include <array>
#include <cstring>
#include <iterator>
#include <memory>
#include "libOTe/Tools/CoeffCtx.h"
#include "PprfUtil.h"

namespace osuCrypto
{

#define REGULAR_PPRF_SIMD8(VAR, STATEMENT) do { \
	{ constexpr u64 VAR = 0; STATEMENT; } \
	{ constexpr u64 VAR = 1; STATEMENT; } \
	{ constexpr u64 VAR = 2; STATEMENT; } \
	{ constexpr u64 VAR = 3; STATEMENT; } \
	{ constexpr u64 VAR = 4; STATEMENT; } \
	{ constexpr u64 VAR = 5; STATEMENT; } \
	{ constexpr u64 VAR = 6; STATEMENT; } \
	{ constexpr u64 VAR = 7; STATEMENT; } \
} while (0)

#if defined(_MSC_VER) && defined(_M_X64)
// MSVC otherwise serializes the eight independent AES-NI chains. This is a
// compiler barrier only; it emits no machine instruction.
#define REGULAR_PPRF_ROUND_BARRIER() _ReadWriteBarrier()
#else
#define REGULAR_PPRF_ROUND_BARRIER() do {} while (0)
#endif

	extern const std::array<AES, 2> gGgmAes;

#ifdef OC_ENABLE_VAES
	namespace pprfVaes
	{
		// AES-128 round keys broadcast to both YMM lanes.
		struct alignas(32) YmmKey
		{
			__m256i k[11];
			explicit YmmKey(const AES& aes)
			{
				for (u64 r = 0; r < 11; ++r)
					k[r] = _mm256_broadcastsi128_si256(aes.mRoundKey[r].mData);
			}
		};

#define OC_PPRF_LANES(OP) OP(0); OP(1); OP(2); OP(3)
#define OC_PPRF_LD(p, j) _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p) + (j))
#define OC_PPRF_ST(p, j, v) _mm256_storeu_si256(reinterpret_cast<__m256i*>(p) + (j), v)

		// One internal GGM level, 8 lanes per parent (4 YMM): parent p gives
		// children 16p..16p+7 (left) and 16p+8..16p+15 (right).
		// Same values as the scalar loop:
		//   a = AES(x),  child0 = AESENC(a, x) = R(a) ^ x,  child1 = a + x (64-bit lanes).
		// The level sums stay in registers; sum0/sum1 (8 blocks each) are
		// read on entry and written on exit.
		OC_FORCEINLINE void internalLevel(const YmmKey& key,
			const AlignedArray<block, 8>* parents, AlignedArray<block, 8>* children,
			u64 width, block* sum0, block* sum1)
		{
#define OC_PPRF_SUM_IN(j) __m256i s0##j = OC_PPRF_LD(sum0, j), s1##j = OC_PPRF_LD(sum1, j)
			OC_PPRF_LANES(OC_PPRF_SUM_IN);
#undef OC_PPRF_SUM_IN
			for (u64 p = 0; p < width; ++p)
			{
				const block* in = parents[p].data();
				block* left = children[2 * p].data();
				block* right = children[2 * p + 1].data();
#define OC_PPRF_IN(j) const __m256i x##j = OC_PPRF_LD(in, j); __m256i a##j = _mm256_xor_si256(x##j, key.k[0])
				OC_PPRF_LANES(OC_PPRF_IN);
#undef OC_PPRF_IN
				for (u64 r = 1; r < 10; ++r)
				{
#define OC_PPRF_RND(j) a##j = _mm256_aesenc_epi128(a##j, key.k[r])
					OC_PPRF_LANES(OC_PPRF_RND);
#undef OC_PPRF_RND
				}
#define OC_PPRF_OUT(j) \
				a##j = _mm256_aesenclast_epi128(a##j, key.k[10]); \
				{ \
					const __m256i c0 = _mm256_aesenc_epi128(a##j, x##j); \
					const __m256i c1 = _mm256_add_epi64(a##j, x##j); \
					OC_PPRF_ST(left, j, c0); \
					OC_PPRF_ST(right, j, c1); \
					s0##j = _mm256_xor_si256(s0##j, c0); \
					s1##j = _mm256_xor_si256(s1##j, c1); \
				}
				OC_PPRF_LANES(OC_PPRF_OUT);
#undef OC_PPRF_OUT
			}
#define OC_PPRF_SUM_OUT(j) OC_PPRF_ST(sum0, j, s0##j); OC_PPRF_ST(sum1, j, s1##j)
			OC_PPRF_LANES(OC_PPRF_SUM_OUT);
#undef OC_PPRF_SUM_OUT
		}

		// The leaf GGM level, 8 lanes per parent: out[16p + 8*keep + t] =
		// AES_keep(x) ^ x under gGgmAes[keep], the same layout and values as
		// gGgmAes[keep].hashBlocks<8>. Both keys run interleaved so 8 YMM AES
		// chains are in flight. sum0/sum1 (8 blocks each) are XOR-accumulated.
		OC_FORCEINLINE void leafLevel(const YmmKey& k0, const YmmKey& k1,
			const AlignedArray<block, 8>* parents, block* out, u64 width, block* sum0, block* sum1)
		{
#define OC_PPRF_SUM_IN(j) __m256i s0##j = OC_PPRF_LD(sum0, j), s1##j = OC_PPRF_LD(sum1, j)
			OC_PPRF_LANES(OC_PPRF_SUM_IN);
#undef OC_PPRF_SUM_IN
			for (u64 p = 0; p < width; ++p)
			{
				const block* in = parents[p].data();
				block* o = out + 16 * p;
#define OC_PPRF_IN(j) \
				const __m256i x##j = OC_PPRF_LD(in, j); \
				__m256i a##j = _mm256_xor_si256(x##j, k0.k[0]); \
				__m256i b##j = _mm256_xor_si256(x##j, k1.k[0])
				OC_PPRF_LANES(OC_PPRF_IN);
#undef OC_PPRF_IN
				for (u64 r = 1; r < 10; ++r)
				{
#define OC_PPRF_RND(j) a##j = _mm256_aesenc_epi128(a##j, k0.k[r]); b##j = _mm256_aesenc_epi128(b##j, k1.k[r])
					OC_PPRF_LANES(OC_PPRF_RND);
#undef OC_PPRF_RND
				}
#define OC_PPRF_OUT(j) \
				a##j = _mm256_xor_si256(_mm256_aesenclast_epi128(a##j, k0.k[10]), x##j); \
				b##j = _mm256_xor_si256(_mm256_aesenclast_epi128(b##j, k1.k[10]), x##j); \
				OC_PPRF_ST(o, j, a##j); \
				OC_PPRF_ST(o + 8, j, b##j); \
				s0##j = _mm256_xor_si256(s0##j, a##j); \
				s1##j = _mm256_xor_si256(s1##j, b##j)
				OC_PPRF_LANES(OC_PPRF_OUT);
#undef OC_PPRF_OUT
			}
#define OC_PPRF_SUM_OUT(j) OC_PPRF_ST(sum0, j, s0##j); OC_PPRF_ST(sum1, j, s1##j)
			OC_PPRF_LANES(OC_PPRF_SUM_OUT);
#undef OC_PPRF_SUM_OUT
		}
#undef OC_PPRF_ST
#undef OC_PPRF_LD
#undef OC_PPRF_LANES

#ifdef ENABLE_AVX512
		// 512-bit versions: same values and layout, half the instructions.
		// A parent (8 lanes) is 2 ZMM; two parents per step keep 4 (internal)
		// or 8 (leaf) AES chains in flight, enough to fill both AES units.
		struct alignas(64) ZmmKey
		{
			__m512i k[11];
			explicit ZmmKey(const AES& aes)
			{
				for (u64 r = 0; r < 11; ++r)
					k[r] = _mm512_broadcast_i32x4(aes.mRoundKey[r].mData);
			}
		};

		template<u64 NP>
		OC_FORCEINLINE void internalStep(const ZmmKey& key,
			const AlignedArray<block, 8>* parents, AlignedArray<block, 8>* children,
			__m512i (&s0)[2], __m512i (&s1)[2])
		{
			constexpr u64 C = 2 * NP;
			__m512i x[C], a[C];
			for (u64 c = 0; c < C; ++c)
			{
				x[c] = _mm512_loadu_si512(parents[c / 2].data() + 4 * (c % 2));
				a[c] = _mm512_xor_si512(x[c], key.k[0]);
			}
			for (u64 r = 1; r < 10; ++r)
				for (u64 c = 0; c < C; ++c)
					a[c] = _mm512_aesenc_epi128(a[c], key.k[r]);
			for (u64 c = 0; c < C; ++c)
			{
				a[c] = _mm512_aesenclast_epi128(a[c], key.k[10]);
				const __m512i c0 = _mm512_aesenc_epi128(a[c], x[c]);
				const __m512i c1 = _mm512_add_epi64(a[c], x[c]);
				const u64 q = c / 2, v = c % 2; // parent q, lanes 4v..4v+3
				_mm512_storeu_si512(children[2 * q].data() + 4 * v, c0);
				_mm512_storeu_si512(children[2 * q + 1].data() + 4 * v, c1);
				s0[v] = _mm512_xor_si512(s0[v], c0);
				s1[v] = _mm512_xor_si512(s1[v], c1);
			}
		}

		OC_FORCEINLINE void internalLevel(const ZmmKey& key,
			const AlignedArray<block, 8>* parents, AlignedArray<block, 8>* children,
			u64 width, block* sum0, block* sum1)
		{
			__m512i s0[2] = { _mm512_loadu_si512(sum0), _mm512_loadu_si512(sum0 + 4) };
			__m512i s1[2] = { _mm512_loadu_si512(sum1), _mm512_loadu_si512(sum1 + 4) };
			u64 p = 0;
			for (; p + 2 <= width; p += 2)
				internalStep<2>(key, parents + p, children + 2 * p, s0, s1);
			if (p < width)
				internalStep<1>(key, parents + p, children + 2 * p, s0, s1);
			_mm512_storeu_si512(sum0, s0[0]); _mm512_storeu_si512(sum0 + 4, s0[1]);
			_mm512_storeu_si512(sum1, s1[0]); _mm512_storeu_si512(sum1 + 4, s1[1]);
		}

		// Each input is four independent parents. Advance both leaf keys together.
		template<std::size_t C>
		OC_FORCEINLINE void hashLeafChains(const ZmmKey& k0, const ZmmKey& k1,
			const __m512i (&x)[C], __m512i (&a)[C], __m512i (&b)[C])
		{
			for (u64 c = 0; c < C; ++c)
			{
				a[c] = _mm512_xor_si512(x[c], k0.k[0]);
				b[c] = _mm512_xor_si512(x[c], k1.k[0]);
			}
			for (u64 r = 1; r < 10; ++r)
				for (u64 c = 0; c < C; ++c)
				{
					a[c] = _mm512_aesenc_epi128(a[c], k0.k[r]);
					b[c] = _mm512_aesenc_epi128(b[c], k1.k[r]);
				}
			for (u64 c = 0; c < C; ++c)
			{
				a[c] = _mm512_xor_si512(_mm512_aesenclast_epi128(a[c], k0.k[10]), x[c]);
				b[c] = _mm512_xor_si512(_mm512_aesenclast_epi128(b[c], k1.k[10]), x[c]);
			}
		}

		template<u64 NP>
		OC_FORCEINLINE void leafStep(const ZmmKey& k0, const ZmmKey& k1,
			const AlignedArray<block, 8>* parents, block* o,
			__m512i (&s0)[2], __m512i (&s1)[2])
		{
			constexpr u64 C = 2 * NP;
			__m512i x[C], a[C], b[C];
			for (u64 c = 0; c < C; ++c)
				x[c] = _mm512_loadu_si512(parents[c / 2].data() + 4 * (c % 2));
			hashLeafChains(k0, k1, x, a, b);
			for (u64 c = 0; c < C; ++c)
			{
				const u64 q = c / 2, v = c % 2;
				_mm512_storeu_si512(o + 16 * q + 4 * v, a[c]);
				_mm512_storeu_si512(o + 16 * q + 8 + 4 * v, b[c]);
				s0[v] = _mm512_xor_si512(s0[v], a[c]);
				s1[v] = _mm512_xor_si512(s1[v], b[c]);
			}
		}

		OC_FORCEINLINE void leafLevel(const ZmmKey& k0, const ZmmKey& k1,
			const AlignedArray<block, 8>* parents, block* out, u64 width, block* sum0, block* sum1)
		{
			__m512i s0[2] = { _mm512_loadu_si512(sum0), _mm512_loadu_si512(sum0 + 4) };
			__m512i s1[2] = { _mm512_loadu_si512(sum1), _mm512_loadu_si512(sum1 + 4) };
			u64 p = 0;
			for (; p + 2 <= width; p += 2)
				leafStep<2>(k0, k1, parents + p, out + 16 * p, s0, s1);
			if (p < width)
				leafStep<1>(k0, k1, parents + p, out + 16 * p, s0, s1);
			_mm512_storeu_si512(sum0, s0[0]); _mm512_storeu_si512(sum0 + 4, s0[1]);
			_mm512_storeu_si512(sum1, s1[0]); _mm512_storeu_si512(sum1 + 4, s1[1]);
		}

		// Both children of a parent have the same live width because the domain is even.
		// Hash all eight lanes for each correction, then store only the live leaves.
		template<u64 NP>
		OC_FORCEINLINE void compactLeafStep(const ZmmKey& k0, const ZmmKey& k1,
			const AlignedArray<block, 8>* parents, block*& out, u64 firstParent,
			u64 fullLanes, u64 extraParents, __m512i& sum0, __m512i& sum1)
		{
			__m512i x[2 * NP], left[2 * NP], right[2 * NP];
			for (u64 c = 0; c < 2 * NP; ++c)
				x[c] = _mm512_loadu_si512(parents[c / 2].data() + 4 * (c % 2));
			hashLeafChains(k0, k1, x, left, right);
			for (u64 q = 0; q < NP; ++q)
			{
				const u64 live = fullLanes + (firstParent + q < extraParents);
				assert(live >= 4 && live <= 8);
				const __mmask8 mask = static_cast<__mmask8>((1u << (2 * (live - 4))) - 1);
				sum0 = _mm512_ternarylogic_epi64(sum0, left[2 * q], left[2 * q + 1], 0x96);
				sum1 = _mm512_ternarylogic_epi64(sum1, right[2 * q], right[2 * q + 1], 0x96);
				_mm512_storeu_si512(out, left[2 * q]);
				_mm512_mask_storeu_epi64(out + 4, mask, left[2 * q + 1]);
				out += live;
				_mm512_storeu_si512(out, right[2 * q]);
				_mm512_mask_storeu_epi64(out + 4, mask, right[2 * q + 1]);
				out += live;
			}
		}

		OC_FORCEINLINE block fold4(__m512i sum)
		{
			const auto pair = _mm256_xor_si256(_mm512_castsi512_si256(sum), _mm512_extracti64x4_epi64(sum, 1));
			return _mm_xor_si128(_mm256_castsi256_si128(pair), _mm256_extracti128_si256(pair, 1));
		}

		using Key = ZmmKey;
#else
		using Key = YmmKey;

		OC_FORCEINLINE void storeCompactRow(block* out, u64 live, const __m256i (&row)[4])
		{
			assert(live >= 4 && live <= 8);
			_mm256_storeu_si256(reinterpret_cast<__m256i*>(out), row[0]);
			_mm256_storeu_si256(reinterpret_cast<__m256i*>(out + 2), row[1]);
			if (live >= 6)
			{
				_mm256_storeu_si256(reinterpret_cast<__m256i*>(out + 4), row[2]);
				if (live == 8)
					_mm256_storeu_si256(reinterpret_cast<__m256i*>(out + 6), row[3]);
				else if (live == 7)
					_mm_storeu_si128(reinterpret_cast<__m128i*>(out + 6), _mm256_castsi256_si128(row[3]));
			}
			else if (live == 5)
				_mm_storeu_si128(reinterpret_cast<__m128i*>(out + 4), _mm256_castsi256_si128(row[2]));
		}

		// Eight independent AES chains cover both children of one eight-lane row.
		// All lanes contribute to the correction, including those outside the domain.
		OC_FORCEINLINE void compactLeafStep(const YmmKey& k0, const YmmKey& k1,
			const block* parents, block*& out, u64 live, __m256i& sum0, __m256i& sum1)
		{
			__m256i x[4], left[4], right[4];
			for (u64 c = 0; c < 4; ++c)
			{
				x[c] = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(parents + 2 * c));
				left[c] = _mm256_xor_si256(x[c], k0.k[0]);
				right[c] = _mm256_xor_si256(x[c], k1.k[0]);
			}
			for (u64 r = 1; r < 10; ++r)
				for (u64 c = 0; c < 4; ++c)
				{
					left[c] = _mm256_aesenc_epi128(left[c], k0.k[r]);
					right[c] = _mm256_aesenc_epi128(right[c], k1.k[r]);
				}
			for (u64 c = 0; c < 4; ++c)
			{
				left[c] = _mm256_xor_si256(_mm256_aesenclast_epi128(left[c], k0.k[10]), x[c]);
				right[c] = _mm256_xor_si256(_mm256_aesenclast_epi128(right[c], k1.k[10]), x[c]);
			}
			auto fold = [](const __m256i (&v)[4]) {
				return _mm256_xor_si256(_mm256_xor_si256(v[0], v[1]), _mm256_xor_si256(v[2], v[3]));
			};
			sum0 = _mm256_xor_si256(sum0, fold(left));
			sum1 = _mm256_xor_si256(sum1, fold(right));
			storeCompactRow(out, live, left);
			storeCompactRow(out + live, live, right);
			out += 2 * live;
		}

		OC_FORCEINLINE block fold2(__m256i sum)
		{
			return _mm_xor_si128(_mm256_castsi256_si128(sum), _mm256_extracti128_si256(sum, 1));
		}
#endif

		// Broadcast the two public leaf keys once on paths that reuse their schedules.
		template<unsigned Side, bool Cache>
		OC_FORCEINLINE decltype(auto) leafKey()
		{
			if constexpr (Cache)
			{
				static const Key key(gGgmAes[Side]);
				return (key);
			}
			else
				return Key(gGgmAes[Side]);
		}

		template<bool TwoBlocks, bool Last = false>
		OC_FORCEINLINE void leafMaskRound(int rc, __m256i& key, __m256i& pad0, __m256i& pad1)
		{
			// Repeat RotWord(w3) in every column. ShiftRows then preserves
			// the repeated word while AESENCLAST applies the AES S-box.
			const auto word = _mm256_shuffle_epi8(key, _mm256_set1_epi32(0x0c0f0e0d));
			const auto subWord = _mm256_aesenclast_epi128(word, _mm256_set1_epi32(rc));
			// Inclusive XOR prefix of the four key words, then add the schedule word.
			key = _mm256_xor_si256(key, _mm256_slli_si256(key, 4));
			key = _mm256_xor_si256(subWord, _mm256_xor_si256(key, _mm256_slli_si256(key, 8)));
			if constexpr (Last)
			{
				pad0 = _mm256_aesenclast_epi128(pad0, key);
				if constexpr (TwoBlocks)
					pad1 = _mm256_aesenclast_epi128(pad1, key);
			}
			else
			{
				pad0 = _mm256_aesenc_epi128(pad0, key);
				if constexpr (TwoBlocks)
					pad1 = _mm256_aesenc_epi128(pad1, key);
			}
		}

		// One OT mask key per 128-bit lane. Encrypt counters 0 and, for a
		// two-block message, 1 while advancing both AES-128 key schedules.
		template<bool TwoBlocks>
		OC_FORCEINLINE void xorLeafMaskPair(u8* messages, const std::array<block, 2>& keys)
		{
			auto key = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(keys.data()));
			auto pad0 = key;
			auto pad1 = _mm256_xor_si256(key, _mm256_setr_epi64x(1, 0, 1, 0));
			leafMaskRound<TwoBlocks>(0x01, key, pad0, pad1);
			leafMaskRound<TwoBlocks>(0x02, key, pad0, pad1);
			leafMaskRound<TwoBlocks>(0x04, key, pad0, pad1);
			leafMaskRound<TwoBlocks>(0x08, key, pad0, pad1);
			leafMaskRound<TwoBlocks>(0x10, key, pad0, pad1);
			leafMaskRound<TwoBlocks>(0x20, key, pad0, pad1);
			leafMaskRound<TwoBlocks>(0x40, key, pad0, pad1);
			leafMaskRound<TwoBlocks>(0x80, key, pad0, pad1);
			leafMaskRound<TwoBlocks>(0x1b, key, pad0, pad1);
			leafMaskRound<TwoBlocks, true>(0x36, key, pad0, pad1);

			// Choice zero uses key one. Store counters in order within each choice.
			auto dest = reinterpret_cast<__m256i*>(messages);
			if constexpr (TwoBlocks)
			{
				const auto first = _mm256_permute2x128_si256(pad0, pad1, 0x31);
				const auto second = _mm256_permute2x128_si256(pad0, pad1, 0x20);
				_mm256_storeu_si256(dest, _mm256_xor_si256(_mm256_loadu_si256(dest), first));
				_mm256_storeu_si256(dest + 1, _mm256_xor_si256(_mm256_loadu_si256(dest + 1), second));
			}
			else
			{
				const auto pads = _mm256_permute2x128_si256(pad0, pad0, 0x01);
				_mm256_storeu_si256(dest, _mm256_xor_si256(_mm256_loadu_si256(dest), pads));
			}
		}

		// The kernels keep one sum per lane (the 8 subtrees of one tree); the
		// tree's level sum is their XOR.
		OC_FORCEINLINE block fold8(const block* s)
		{
#ifdef ENABLE_AVX512
			return fold4(_mm512_xor_si512(_mm512_loadu_si512(s), _mm512_loadu_si512(s + 4)));
#else
			return ((s[0] ^ s[1]) ^ (s[2] ^ s[3])) ^ ((s[4] ^ s[5]) ^ (s[6] ^ s[7]));
#endif
		}
		// Keep the full leaf kernel out of the sender and receiver expansion loops.
		OC_NOINLINE inline std::array<block, 2> fullLeafLevel(
			span<const AlignedArray<block, 8>> parents, block* dest)
		{
			alignas(64) std::array<block, 8> left{}, right{};
			leafLevel(leafKey<0, true>(), leafKey<1, true>(), parents.data(), dest,
				parents.size(), left.data(), right.data());
			return { fold8(left.data()), fold8(right.data()) };
		}

	}
#endif

	namespace pprf
	{
		// Expand eight GGM parents while keeping the raw AES outputs in
		// registers. Calling ecbEncBlocks followed by the two child transforms
		// makes MSVC store and reload every raw AES output.
		OC_FORCEINLINE void expandGgm8(
			const AES& aes,
			const block* parents,
			block* left,
			block* right,
			block& leftAccumulator,
			block& rightAccumulator)
		{
			const auto& k = aes.mRoundKey;
			block x0 = AES::firstFn(parents[0], k[0]);
			block x1 = AES::firstFn(parents[1], k[0]);
			block x2 = AES::firstFn(parents[2], k[0]);
			block x3 = AES::firstFn(parents[3], k[0]);
			block x4 = AES::firstFn(parents[4], k[0]);
			block x5 = AES::firstFn(parents[5], k[0]);
			block x6 = AES::firstFn(parents[6], k[0]);
			block x7 = AES::firstFn(parents[7], k[0]);
			REGULAR_PPRF_ROUND_BARRIER();

#define REGULAR_PPRF_AES_ROUND(R, FN) do { \
			x0 = AES::FN(x0, k[R]); \
			x1 = AES::FN(x1, k[R]); \
			x2 = AES::FN(x2, k[R]); \
			x3 = AES::FN(x3, k[R]); \
			x4 = AES::FN(x4, k[R]); \
			x5 = AES::FN(x5, k[R]); \
			x6 = AES::FN(x6, k[R]); \
			x7 = AES::FN(x7, k[R]); \
		} while (0)

			REGULAR_PPRF_AES_ROUND(1, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_AES_ROUND(2, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_AES_ROUND(3, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_AES_ROUND(4, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_AES_ROUND(5, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_AES_ROUND(6, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_AES_ROUND(7, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_AES_ROUND(8, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_AES_ROUND(9, penultimateFn);
			REGULAR_PPRF_ROUND_BARRIER();

#undef REGULAR_PPRF_AES_ROUND

#define REGULAR_PPRF_STORE_CHILD(I) do { \
			const auto encrypted = AES::finalFn(x##I, k[10]); \
			const auto leftChild = AES::roundEnc(encrypted, parents[I]); \
			const auto rightChild = encrypted.add_epi64(parents[I]); \
			left[I] = leftChild; \
			right[I] = rightChild; \
			leftAccumulator = leftAccumulator ^ leftChild; \
			rightAccumulator = rightAccumulator ^ rightChild; \
		} while (0)

			REGULAR_PPRF_STORE_CHILD(0);
			REGULAR_PPRF_STORE_CHILD(1);
			REGULAR_PPRF_STORE_CHILD(2);
			REGULAR_PPRF_STORE_CHILD(3);
			REGULAR_PPRF_STORE_CHILD(4);
			REGULAR_PPRF_STORE_CHILD(5);
			REGULAR_PPRF_STORE_CHILD(6);
			REGULAR_PPRF_STORE_CHILD(7);

#undef REGULAR_PPRF_STORE_CHILD
		}

		OC_FORCEINLINE void hashGgmLeaves8(
			const AES& aes,
			const block* parents,
			block* output,
			block& accumulator)
		{
			const auto& k = aes.mRoundKey;
			block x0 = AES::firstFn(parents[0], k[0]);
			block x1 = AES::firstFn(parents[1], k[0]);
			block x2 = AES::firstFn(parents[2], k[0]);
			block x3 = AES::firstFn(parents[3], k[0]);
			block x4 = AES::firstFn(parents[4], k[0]);
			block x5 = AES::firstFn(parents[5], k[0]);
			block x6 = AES::firstFn(parents[6], k[0]);
			block x7 = AES::firstFn(parents[7], k[0]);
			REGULAR_PPRF_ROUND_BARRIER();

#define REGULAR_PPRF_HASH_ROUND(R, FN) do { \
			x0 = AES::FN(x0, k[R]); \
			x1 = AES::FN(x1, k[R]); \
			x2 = AES::FN(x2, k[R]); \
			x3 = AES::FN(x3, k[R]); \
			x4 = AES::FN(x4, k[R]); \
			x5 = AES::FN(x5, k[R]); \
			x6 = AES::FN(x6, k[R]); \
			x7 = AES::FN(x7, k[R]); \
		} while (0)

			REGULAR_PPRF_HASH_ROUND(1, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_HASH_ROUND(2, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_HASH_ROUND(3, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_HASH_ROUND(4, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_HASH_ROUND(5, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_HASH_ROUND(6, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_HASH_ROUND(7, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_HASH_ROUND(8, roundFn);
			REGULAR_PPRF_ROUND_BARRIER();
			REGULAR_PPRF_HASH_ROUND(9, penultimateFn);
			REGULAR_PPRF_ROUND_BARRIER();

#undef REGULAR_PPRF_HASH_ROUND

#define REGULAR_PPRF_STORE_HASH(I) do { \
			const auto hash = AES::finalFn(x##I, k[10]) ^ parents[I]; \
			output[I] = hash; \
			accumulator = accumulator ^ hash; \
		} while (0)

			REGULAR_PPRF_STORE_HASH(0);
			REGULAR_PPRF_STORE_HASH(1);
			REGULAR_PPRF_STORE_HASH(2);
			REGULAR_PPRF_STORE_HASH(3);
			REGULAR_PPRF_STORE_HASH(4);
			REGULAR_PPRF_STORE_HASH(5);
			REGULAR_PPRF_STORE_HASH(6);
			REGULAR_PPRF_STORE_HASH(7);

#undef REGULAR_PPRF_STORE_HASH
		}

		template<bool CacheLeafKeys = false, typename Iter, typename Sums, typename CoeffCtx>
		OC_FORCEINLINE u64 hashPhysicalBlockLeaves(span<AlignedArray<block, 8>> parents,
			u64 domain, Iter output, Sums& leafSums, CoeffCtx& ctx)
		{
			const u64 subtreeDomain = 2 * parents.size();
			const u64 fullLanes = domain / subtreeDomain;
			const u64 partialSize = domain % subtreeDomain;
#ifdef OC_ENABLE_VAES
			// A context can opt in when block copy is assignment and addition is bitwise XOR.
			if constexpr (std::contiguous_iterator<Iter> &&
				requires { requires CoeffCtx::blockCopyIsTrivialAndAdditionIsXor; })
			{
				const auto& k0 = pprfVaes::leafKey<0, CacheLeafKeys>();
				const auto& k1 = pprfVaes::leafKey<1, CacheLeafKeys>();
				block* dest = std::to_address(output);
#ifdef ENABLE_AVX512
				__m512i sum0 = _mm512_setzero_si512(), sum1 = _mm512_setzero_si512();
				u64 p = 0;
				for (; p + 2 <= parents.size(); p += 2)
					pprfVaes::compactLeafStep<2>(k0, k1, parents.data() + p, dest,
						p, fullLanes, partialSize / 2, sum0, sum1);
				if (p < parents.size())
					pprfVaes::compactLeafStep<1>(k0, k1, parents.data() + p, dest,
						p, fullLanes, partialSize / 2, sum0, sum1);
				leafSums[0] ^= pprfVaes::fold4(sum0);
				leafSums[1] ^= pprfVaes::fold4(sum1);
#else
				__m256i sum0 = _mm256_setzero_si256(), sum1 = _mm256_setzero_si256();
				for (u64 p = 0; p < parents.size(); ++p)
					pprfVaes::compactLeafStep(k0, k1, parents[p].data(), dest,
						fullLanes + (p < partialSize / 2), sum0, sum1);
				leafSums[0] ^= pprfVaes::fold2(sum0);
				leafSums[1] ^= pprfVaes::fold2(sum1);
#endif
				return dest - std::to_address(output);
			}
#endif
			alignas(64) std::array<block, 8> hashed;
			u64 written = 0;
			for (u64 p = 0; p < parents.size(); ++p)
			{
				for (u64 side = 0; side < 2; ++side)
				{
					gGgmAes[side].hashBlocks<8>(parents[p].data(), hashed.data());
					// All eight subtrees enter the correction sum. Only the live
					// prefix of this row belongs in the compact physical output.
					auto& sum = leafSums[side];
					REGULAR_PPRF_SIMD8(lane, { ctx.plus(sum, sum, hashed[lane]); });
					const u64 live = fullLanes + (2 * p + side < partialSize);
					// The domain fills more than half of its padded tree, so each
					// row has at least four live lanes. Keep these short stores inline.
					assert(live >= 4 && live <= 8);
					REGULAR_PPRF_SIMD8(lane, {
						if (lane < 4 || lane < live)
							ctx.copy(output[written + lane], hashed[lane]);
					});
					written += live;
				}
			}
			return written;
		}

		template<typename F, typename CoeffCtx>
		OC_FORCEINLINE auto leafBuffer(CoeffCtx& ctx, span<block> storage)
		{
			using VecF = typename CoeffCtx::template Vec<F>;
			if constexpr (std::is_same_v<F, block> && std::is_same_v<VecF, AlignedUnVector<block>>)
				return storage;
			else
				return ctx.template makeVec<F>(storage.size());
		}

		OC_FORCEINLINE void xorLeafMask(span<u8> msg, block key, PRNG& otMasker)
		{
			if (msg.size() == sizeof(block) || msg.size() == 2 * sizeof(block))
			{
				// These are the first one or two counter blocks of the OT masker's stream.
				const AES aes(key);
				const block counters[2]{block(0, 0), block(0, 1)};
				block pads[2];
				if (msg.size() == 2 * sizeof(block))
					aes.ecbEncBlocks<2>(counters, pads);
				else
					pads[0] = aes.ecbEncBlock(counters[0]);
				for (u64 i = 0; i < msg.size() / sizeof(block); ++i)
				{
					block value;
					std::memcpy(&value, msg.data() + i * sizeof(block), sizeof(block));
					value ^= pads[i];
					std::memcpy(msg.data() + i * sizeof(block), &value, sizeof(block));
				}
				return;
			}
			otMasker.SetSeed(key, divCeil(msg.size(), sizeof(block)));
			for (u64 i = 0; i < msg.size(); ++i)
				msg[i] ^= otMasker.get<u8>();
		}

		OC_FORCEINLINE void xorSenderLeafMasks(span<u8> msgs, u64 messageBytes, const std::array<block, 2>& keys)
		{
			assert(msgs.size() == 2 * messageBytes);
#ifdef OC_ENABLE_VAES
			if (messageBytes == sizeof(block))
				return pprfVaes::xorLeafMaskPair<false>(msgs.data(), keys);
			if (messageBytes == 2 * sizeof(block))
				return pprfVaes::xorLeafMaskPair<true>(msgs.data(), keys);
#endif
			PRNG otMasker;
			xorLeafMask(msgs.subspan(0, messageBytes), keys[1], otMasker);
			xorLeafMask(msgs.subspan(messageBytes, messageBytes), keys[0], otMasker);
		}
	}


	template<
		typename F,
		typename CoeffCtx = DefaultCoeffCtx<F>
	>
	class RegularPprfSender : public PprfSender<F, CoeffCtx> {
	public:

		// the number of leaves in a single tree.
		u64 mDomain = 0;

		// the depth of each tree.
		u64 mDepth = 0;

		// the number of trees.
		u64 mPntCount = 0;

		// the values that should be programmed at the punctured points.
		std::vector<F> mValue;

		// the base OTs that should be set.
		Matrix<std::array<block, 2>> mBaseOTs;

		// if true, tree OT messages are eagerly sent in batches of 8.
		// otherwise, the OT messages are sent in a single batch.
		bool mEagerSend = true;

		using VecF = typename CoeffCtx::template Vec<F>;

		// a function that can be used to output the result of the PPRF.
		std::function<void(u64 treeIdx, VecF& leaf)> mOutputFn;

		// Compact two-level scratch reused one tree at a time.
		pprf::ExpandTreeBuffer mTempBuffer;

		RegularPprfSender() = default;

		RegularPprfSender(const RegularPprfSender&) = delete;

		RegularPprfSender(RegularPprfSender&&) = delete;

		RegularPprfSender(u64 domainSize, u64 pointCount) {
			configure(domainSize, pointCount);
		}

		void configure(u64 domainSize, u64 pointCount) override
		{
			auto depth = pprf::validateConfigure(domainSize, pointCount);
			mDomain = domainSize;
			mDepth = depth;
			mPntCount = pointCount;

			mBaseOTs.resize(0, 0);
			mValue.clear();
		}


		// the number of base OTs that should be set.
		u64 baseOtCount() const override {
			return mDepth * mPntCount;
		}

		// returns true if the base OTs are currently set.
		bool hasBaseOts() const override {
			return mBaseOTs.rows() == mPntCount &&
				mBaseOTs.cols() == mDepth && mBaseOTs.size();
		}


		void setBase(span<const std::array<block, 2>> baseMessages) override {
			if (mDomain == 0 || mPntCount == 0)
				throw std::runtime_error("PPRF must be configured before setting base OTs. " LOCATION);
			if (baseOtCount() != static_cast<u64>(baseMessages.size()))
				throw RTE_LOC;

			mBaseOTs.resize(mPntCount, mDepth);
			for (u64 i = 0; i < static_cast<u64>(mBaseOTs.size()); ++i)
				mBaseOTs(i) = baseMessages[i];
		}

		task<> expand(
			Socket& chl,
			const VecF& value,
			block seed,
			VecF& output,
			PprfOutputFormat oFormat,
			bool programPuncturedPoint,
			u64 numThreads,
			CoeffCtx ctx = {}) override
		{
			(void)numThreads;
			auto consumeBaseOts = false;
			MACORO_TRY {
				pprf::validateExpandFormat(oFormat, output, mDomain, mPntCount);
				if (!hasBaseOts())
					throw std::runtime_error("PPRF sender base OTs are not set. " LOCATION);
				if (oFormat == PprfOutputFormat::Callback && !mOutputFn)
					throw std::runtime_error("PPRF callback output requires a callback. " LOCATION);
				if (programPuncturedPoint)
					setValue(value);

				this->setTimePoint("SilentMultiPprfSender.start");
				consumeBaseOts = true;

				std::vector<span<AlignedArray<block, 8>>> levels;
				if (mDepth > 3)
				{
					const auto parentDomain = pprf::paddedDomain(mDomain) / 16;
					pprf::allocateExpandTree(parentDomain, mTempBuffer, levels);
				}

				VecF callbackLeaves;
				if (oFormat == PprfOutputFormat::Callback)
					ctx.resize(callbackLeaves, mDomain);

				auto buff = std::vector<u8>{};
				auto encSums = span<std::array<block, 2>>{};
				auto leafMsgs = span<u8>{};
				const auto encPerTree = mDepth - 1;
				const auto leafPerTree =
					ctx.template byteSize<F>() * (2 + 2 * u64(programPuncturedPoint));

				for (u64 batch = 0; batch < mPntCount;)
				{
					const auto count = mEagerSend ?
						std::min<u64>(8, mPntCount - batch) :
						mPntCount;
					pprf::allocateExpandBuffer<F>(
						encPerTree, count, programPuncturedPoint,
						buff, encSums, leafMsgs, ctx);

					for (u64 j = 0; j < count; ++j)
					{
						const auto tree = batch + j;
						const auto root = mAesFixedKey.ecbEncBlock(seed ^ block(tree));
						auto treeSums = encSums.subspan(j * encPerTree, encPerTree);
						auto treeLeaves = leafMsgs.subspan(j * leafPerTree, leafPerTree);
						auto levelSpan = span<span<AlignedArray<block, 8>>>(levels);

						switch (oFormat)
						{
						case PprfOutputFormat::ByLeafIndex:
							expandOne<PprfOutputFormat::ByLeafIndex>(
								root, tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves, ctx);
							break;
						case PprfOutputFormat::ByTreeIndex:
							expandOne<PprfOutputFormat::ByTreeIndex>(
								root, tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves, ctx);
							break;
						case PprfOutputFormat::ByPhysicalIndex:
							expandOne<PprfOutputFormat::ByPhysicalIndex>(
								root, tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves, ctx);
							break;
						case PprfOutputFormat::Callback:
							expandOne<PprfOutputFormat::Callback>(
								root, tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves, ctx);
							mOutputFn(tree, callbackLeaves);
							break;
						default:
							throw RTE_LOC;
						}
					}

					co_await chl.send(std::move(buff));
					batch += count;
					if (!mEagerSend)
						break;
				}

				mBaseOTs = {};
				consumeBaseOts = false;
				this->setTimePoint("SilentMultiPprfSender.de-alloc");
			}
			MACORO_CATCH(eptr) {
				if (consumeBaseOts)
					mBaseOTs = {};
				if (!chl.closed())
					co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}

		void setValue(span<const F> value) {

			mValue.resize(mPntCount);

			if (value.size() == 1) {
				std::fill(mValue.begin(), mValue.end(), value[0]);
			}
			else {
				if ((u64)value.size() != mPntCount)
					throw RTE_LOC;

				std::copy(value.begin(), value.end(), mValue.begin());
			}
		}

		void clear() override {
			mBaseOTs.resize(0, 0);
			mValue.clear();
			mTempBuffer.clear();
			mDomain = 0;
			mDepth = 0;
			mPntCount = 0;
		}

		// Keep the aligned tree and leaf scratch out of the calling coroutine.
		template<PprfOutputFormat Format>
		OC_NOINLINE void expandOne(
			block root,
			u64 treeIdx,
			bool programPuncturedPoint,
			span<span<AlignedArray<block, 8>>> levels,
			VecF& output,
			VecF& callbackLeaves,
			span<std::array<block, 2>> encSums,
			span<u8> leafMsgs,
			CoeffCtx& ctx)
		{
			assert(encSums.size() == mDepth - 1);
			auto encSumIter = encSums.begin();
			std::array<block, 8> current{};
			std::array<block, 8> next{};
			current[0] = root;

			const auto topInternalDepth = std::min<u64>(3, mDepth - 1);
			for (u64 d = 0; d < topInternalDepth; ++d)
			{
				block leftAccumulator = ZeroBlock;
				block rightAccumulator = ZeroBlock;
				const auto width = u64{ 1 } << d;
				for (u64 parentIdx = 0; parentIdx < width; ++parentIdx)
				{
					const auto parent = current[parentIdx];
					const auto aes = mAesFixedKey.ecbEncBlock(parent);
					const auto left = AES::roundEnc(aes, parent);
					const auto right = aes.add_epi64(parent);
					next[2 * parentIdx] = left;
					next[2 * parentIdx + 1] = right;
					leftAccumulator = leftAccumulator ^ left;
					rightAccumulator = rightAccumulator ^ right;
				}
				(*encSumIter)[0] = leftAccumulator ^
					mBaseOTs(treeIdx, mDepth - 1 - d)[1];
				(*encSumIter)[1] = rightAccumulator ^
					mBaseOTs(treeIdx, mDepth - 1 - d)[0];
				++encSumIter;
				current = next;
			}

			if (mDepth > 3)
			{
				assert(levels.size() == mDepth - 3);
				REGULAR_PPRF_SIMD8(lane, {
					levels[0][0][lane] = current[lane];
				});
#ifdef OC_ENABLE_VAES
				const pprfVaes::Key internalKey(mAesFixedKey);
#endif

				for (u64 localDepth = 0; localDepth + 1 < levels.size(); ++localDepth)
				{
					block leftAccumulator = ZeroBlock;
					block rightAccumulator = ZeroBlock;
					auto parents = levels[localDepth];
					auto children = levels[localDepth + 1];
					const auto width = u64{ 1 } << localDepth;
#ifdef OC_ENABLE_VAES
					{
						alignas(64) std::array<block, 8> laneSums0{}, laneSums1{};
						pprfVaes::internalLevel(internalKey, parents.data(), children.data(),
							width, laneSums0.data(), laneSums1.data());
						leftAccumulator = leftAccumulator ^ pprfVaes::fold8(laneSums0.data());
						rightAccumulator = rightAccumulator ^ pprfVaes::fold8(laneSums1.data());
					}
#else
					for (u64 parentIdx = 0; parentIdx < width; ++parentIdx)
					{
						auto& parent = parents[parentIdx];
						auto& left = children[2 * parentIdx];
						auto& right = children[2 * parentIdx + 1];
						pprf::expandGgm8(
							mAesFixedKey, parent.data(), left.data(), right.data(),
							leftAccumulator, rightAccumulator);
					}
#endif

					const auto globalDepth = 3 + localDepth;
					(*encSumIter)[0] = leftAccumulator ^
						mBaseOTs(treeIdx, mDepth - 1 - globalDepth)[1];
					(*encSumIter)[1] = rightAccumulator ^
						mBaseOTs(treeIdx, mDepth - 1 - globalDepth)[0];
					++encSumIter;
				}
			}
			assert(encSumIter == encSums.end());

			AlignedArray<block, 2> sumStorage;
			auto leafSums = pprf::leafBuffer<F>(ctx, sumStorage);
			ctx.zero(leafSums.begin(), leafSums.end());
			const auto padded = pprf::paddedDomain(mDomain);
			const auto subtreeDomain = mDepth > 3 ? padded / 8 : padded;
			u64 nativeLeaf = 0;

			auto storeLeaf = [&](u64 logicalLeaf, u64 physicalLeaf, const F& value) {
				if constexpr (Format == PprfOutputFormat::ByLeafIndex)
					ctx.copy(output[logicalLeaf * mPntCount + treeIdx], value);
				else if constexpr (Format == PprfOutputFormat::ByTreeIndex)
					ctx.copy(output[treeIdx * mDomain + logicalLeaf], value);
				else if constexpr (Format == PprfOutputFormat::ByPhysicalIndex)
					ctx.copy(output[treeIdx * mDomain + physicalLeaf], value);
				else
					ctx.copy(callbackLeaves[physicalLeaf], value);
			};

			auto addLeaf = [&](u64 side, const block& hashed, u64 logicalLeaf) {
				F value;
				if constexpr (std::is_same_v<F, block>)
					value = hashed;
				else
					ctx.fromBlock(value, hashed);
				ctx.plus(leafSums[side], leafSums[side], value);
				if (logicalLeaf < mDomain)
					storeLeaf(logicalLeaf, nativeLeaf++, value);
			};

			if (mDepth <= 3)
			{
				const auto parentWidth = padded / 2;
				for (u64 parentIdx = 0; parentIdx < parentWidth; ++parentIdx)
				{
					const auto parent = current[parentIdx];
					addLeaf(0, gGgmAes[0].hashBlock(parent), 2 * parentIdx);
					addLeaf(1, gGgmAes[1].hashBlock(parent), 2 * parentIdx + 1);
				}
			}
			else
			{
				auto parents = levels.back();
				auto generateGeneric = [&] {
					if constexpr (std::is_same_v<F, block> && Format == PprfOutputFormat::ByPhysicalIndex)
					{
						// Reuse the public broadcast schedules across sender trees.
						nativeLeaf = pprf::hashPhysicalBlockLeaves<true>(parents, mDomain,
							output.begin() + treeIdx * mDomain, leafSums, ctx);
						return;
					}
					alignas(64) std::array<block, 8> hashed;
					for (u64 parentIdx = 0; parentIdx < parents.size(); ++parentIdx)
					{
						for (u64 side = 0; side < 2; ++side)
						{
							gGgmAes[side].hashBlocks<8>(
								parents[parentIdx].data(), hashed.data());
							const auto localLeaf = 2 * parentIdx + side;
							REGULAR_PPRF_SIMD8(lane, {
								addLeaf(
									side, hashed[lane],
									lane * subtreeDomain + localLeaf);
							});
						}
					}
				};

				if constexpr (
					std::is_same_v<F, block> &&
					std::is_base_of_v<CoeffCtxGF2, CoeffCtx> &&
					(Format == PprfOutputFormat::ByPhysicalIndex ||
						Format == PprfOutputFormat::Callback))
				{
					if (mDomain == padded)
					{
						block* dest;
						if constexpr (Format == PprfOutputFormat::ByPhysicalIndex)
							dest = output.data() + treeIdx * mDomain;
						else
							dest = callbackLeaves.data();

						block leftAccumulator = ZeroBlock;
						block rightAccumulator = ZeroBlock;
#ifdef OC_ENABLE_VAES
						const auto sums = pprfVaes::fullLeafLevel(parents, dest);
						leftAccumulator ^= sums[0];
						rightAccumulator ^= sums[1];
						nativeLeaf += 16 * parents.size();
#else
						for (u64 parentIdx = 0; parentIdx < parents.size(); ++parentIdx)
						{
							pprf::hashGgmLeaves8(gGgmAes[0],
								parents[parentIdx].data(), dest + nativeLeaf,
								leftAccumulator);
							nativeLeaf += 8;
							pprf::hashGgmLeaves8(gGgmAes[1],
								parents[parentIdx].data(), dest + nativeLeaf,
								rightAccumulator);
							nativeLeaf += 8;
						}
#endif
						leafSums[0] = leftAccumulator;
						leafSums[1] = rightAccumulator;
					}
					else
					{
						generateGeneric();
					}
				}
				else
				{
					generateGeneric();
				}
			}
			assert(nativeLeaf == mDomain);

			AlignedArray<block, 2> otStorage;
			auto leafOts = pprf::leafBuffer<F>(ctx, otStorage);
			const auto count = 1 + u64(programPuncturedPoint);
			const auto messageBytes = count * ctx.template byteSize<F>();
			for (u64 choice = 0; choice < 2; ++choice)
			{
				if (programPuncturedPoint)
				{
					if (choice == 0)
					{
						ctx.copy(leafOts[0], leafSums[0]);
						ctx.plus(leafOts[1], leafSums[1], mValue[treeIdx]);
					}
					else
					{
						ctx.plus(leafOts[0], leafSums[0], mValue[treeIdx]);
						ctx.copy(leafOts[1], leafSums[1]);
					}
				}
				else
				{
					ctx.copy(leafOts[0], leafSums[choice]);
				}

				auto msg = leafMsgs.subspan(choice * messageBytes, messageBytes);
				ctx.serialize(leafOts.begin(), leafOts.begin() + count, msg.begin());
			}
			pprf::xorSenderLeafMasks(leafMsgs, messageBytes, mBaseOTs(treeIdx, 0));
		}


	};


	template<
		typename F,
		typename CoeffCtx = DefaultCoeffCtx<F>
	>
	class RegularPprfReceiver : public PprfReceiver<F, CoeffCtx>
	{
	public:

		// the number of leaves in a single tree.
		u64 mDomain = 0;

		// the depth of each tree.
		u64 mDepth = 0;

		// the number of trees.
		u64 mPntCount = 0;

		using VecF = typename CoeffCtx::template Vec<F>;

		// base ots that will be used to expand the tree.
		Matrix<block> mBaseOTs;

		// the choice bits, each row should be the bit decomposition of the active path.
		Matrix<u8> mBaseChoices;

		// if true, tree OT messages are eagerly sent in batches of 8.
		// otherwise, the OT messages are sent in a single batch.
		bool mEagerSend = true;

		// a function that can be used to output the result of the PPRF.
		std::function<void(u64 treeIdx, VecF& leafs)> mOutputFn;

		// Compact two-level scratch reused one tree at a time.
		pprf::ExpandTreeBuffer mTempBuffer;

		RegularPprfReceiver() = default;
		RegularPprfReceiver(const RegularPprfReceiver&) = delete;
		RegularPprfReceiver(RegularPprfReceiver&&) = delete;

		void configure(u64 domainSize, u64 pointCount) override
		{
			auto depth = pprf::validateConfigure(domainSize, pointCount);
			mDomain = domainSize;
			mDepth = depth;
			mPntCount = pointCount;

			mBaseOTs.resize(0, 0);
			mBaseChoices.resize(0, 0);
		}


		// this function sample mPntCount integers in the range
		// [0,domain) and returns these as the choice bits.
		BitVector sampleChoiceBits(PRNG& prng)override
		{
			if (mDomain == 0 || mPntCount == 0)
				throw std::runtime_error("PPRF must be configured before sampling choices. " LOCATION);
			BitVector choices(mPntCount * mDepth);

			mBaseChoices.resize(mPntCount, mDepth);
			for (u64 i = 0; i < mPntCount; ++i)
			{
				u64 idx = pprf::sampleMod(prng, mDomain);
				for (u64 j = 0; j < mDepth; ++j)
					mBaseChoices(i, j) = *BitIterator((u8*)&idx, j);
			}

			for (u64 i = 0; i < mBaseChoices.size(); ++i)
			{
				choices[i] = mBaseChoices(i);
			}

			return choices;
		}

		// choices is in the same format as the output from sampleChoiceBits.
		void setChoiceBits(const BitVector& choices)override
		{
			if (mDomain == 0 || mPntCount == 0)
				throw std::runtime_error("PPRF must be configured before setting choices. " LOCATION);
			// Make sure we're given the right number of OTs.
			if (choices.size() != baseOtCount())
				throw RTE_LOC;

			// Validate every encoded point before changing the active paths.
			for (u64 i = 0; i < mPntCount; ++i)
			{
				u64 idx = 0;
				for (u64 j = 0; j < mDepth; ++j)
					idx |= u64(choices[mDepth * i + j]) << j;

				if (idx >= mDomain)
					throw std::runtime_error("provided choice bits index outside of the domain." LOCATION);
			}

			mBaseChoices.resize(mPntCount, mDepth);
			for (u64 i = 0; i < mBaseChoices.size(); ++i)
				mBaseChoices(i) = choices[i];
		}


		// the number of base OTs that should be set.
		u64 baseOtCount() const override
		{
			return mDepth * mPntCount;
		}

		// returns true if the base OTs are currently set.
		bool hasBaseOts() const override
		{
			return mBaseOTs.rows() == mPntCount &&
				mBaseOTs.cols() == mDepth && mBaseOTs.size();
		}

		bool hasChoiceBits() const
		{
			return mBaseChoices.rows() == mPntCount &&
				mBaseChoices.cols() == mDepth && mBaseChoices.size();
		}


		void setBase(span<const block> baseMessages) override
		{
			if (mDomain == 0 || mPntCount == 0)
				throw std::runtime_error("PPRF must be configured before setting base OTs. " LOCATION);
			if (baseOtCount() != static_cast<u64>(baseMessages.size()))
				throw RTE_LOC;

			mBaseOTs.resize(mPntCount, mDepth);
			memcpy(mBaseOTs.data(), baseMessages.data(), baseMessages.size() * sizeof(block));
		}


		std::vector<u64> getPoints(PprfOutputFormat format) const override
		{
			std::vector<u64> pnts(mPntCount);
			getPoints(pnts, format);
			return pnts;
		}

		void getPoints(span<u64> points, PprfOutputFormat format) const  override
		{
			if ((u64)points.size() != mPntCount)
				throw RTE_LOC;
			if (!hasChoiceBits())
				throw std::runtime_error("PPRF receiver choices are not set. " LOCATION);

			switch (format)
			{
			case PprfOutputFormat::ByLeafIndex:
			case PprfOutputFormat::ByTreeIndex:

				memset(points.data(), 0, points.size() * sizeof(u64));
				for (u64 j = 0; j < mPntCount; ++j)
				{
					for (u64 k = 0; k < mDepth; ++k)
						points[j] |= u64(mBaseChoices(j, k)) << k;

					if (points[j] >= mDomain)
						throw std::runtime_error("PPRF receiver choice is outside the domain. " LOCATION);
				}


				break;
			case PprfOutputFormat::ByPhysicalIndex:
			case PprfOutputFormat::Callback:

				getPoints(points, PprfOutputFormat::ByLeafIndex);
				for (u64 j = 0; j < points.size(); ++j)
					points[j] = j * mDomain +
						pprf::physicalLeafIndex(mDomain, points[j]);

				break;
			default:
				throw RTE_LOC;
				break;
			}
		}


		// programPuncturedPoint says whether the sender is trying to program the
		// active child to be its correct value XOR delta. If it is not, the
		// active child will just take a random value.
		task<> expand(
			Socket& chl,
			VecF& output,
			PprfOutputFormat oFormat,
			bool programPuncturedPoint,
			u64 numThreads,
			CoeffCtx ctx = {}) override
		{
			(void)numThreads;
			auto consumeBaseOts = false;
			MACORO_TRY {
				pprf::validateExpandFormat(oFormat, output, mDomain, mPntCount);
				if (!hasBaseOts())
					throw std::runtime_error("PPRF receiver base OTs are not set. " LOCATION);
				if (!hasChoiceBits())
					throw std::runtime_error("PPRF receiver choices are not set. " LOCATION);
				if (oFormat == PprfOutputFormat::Callback && !mOutputFn)
					throw std::runtime_error("PPRF callback output requires a callback. " LOCATION);

				this->setTimePoint("SilentMultiPprfReceiver.start");
				consumeBaseOts = true;

				auto points = getPoints(PprfOutputFormat::ByTreeIndex);
				std::vector<span<AlignedArray<block, 8>>> levels;
				if (mDepth > 3)
				{
					const auto parentDomain = pprf::paddedDomain(mDomain) / 16;
					pprf::allocateExpandTree(parentDomain, mTempBuffer, levels);
				}

				VecF callbackLeaves;
				if (oFormat == PprfOutputFormat::Callback)
					ctx.resize(callbackLeaves, mDomain);

				auto buff = std::vector<u8>{};
				auto theirSums = span<std::array<block, 2>>{};
				auto leafMsgs = span<u8>{};
				const auto sumsPerTree = mDepth - 1;
				const auto leafPerTree =
					ctx.template byteSize<F>() * (2 + 2 * u64(programPuncturedPoint));

				for (u64 batch = 0; batch < mPntCount;)
				{
					const auto count = mEagerSend ?
						std::min<u64>(8, mPntCount - batch) :
						mPntCount;
					pprf::allocateExpandBuffer<F>(
						sumsPerTree, count, programPuncturedPoint,
						buff, theirSums, leafMsgs, ctx);
					co_await chl.recv(buff);

					for (u64 j = 0; j < count; ++j)
					{
						const auto tree = batch + j;
						auto treeSums = theirSums.subspan(j * sumsPerTree, sumsPerTree);
						auto treeLeaves = leafMsgs.subspan(j * leafPerTree, leafPerTree);
						auto levelSpan = span<span<AlignedArray<block, 8>>>(levels);

						switch (oFormat)
						{
						case PprfOutputFormat::ByLeafIndex:
							expandOne<PprfOutputFormat::ByLeafIndex>(
								tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves,
								points[tree], ctx);
							break;
						case PprfOutputFormat::ByTreeIndex:
							expandOne<PprfOutputFormat::ByTreeIndex>(
								tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves,
								points[tree], ctx);
							break;
						case PprfOutputFormat::ByPhysicalIndex:
							expandOne<PprfOutputFormat::ByPhysicalIndex>(
								tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves,
								points[tree], ctx);
							break;
						case PprfOutputFormat::Callback:
							expandOne<PprfOutputFormat::Callback>(
								tree, programPuncturedPoint, levelSpan,
								output, callbackLeaves, treeSums, treeLeaves,
								points[tree], ctx);
							mOutputFn(tree, callbackLeaves);
							break;
						default:
							throw RTE_LOC;
						}
					}

					batch += count;
					if (!mEagerSend)
						break;
				}

				this->setTimePoint("SilentMultiPprfReceiver.join");
				mBaseOTs = {};
				consumeBaseOts = false;
				this->setTimePoint("SilentMultiPprfReceiver.de-alloc");
			}
			MACORO_CATCH(eptr) {
				if (consumeBaseOts)
					mBaseOTs = {};
				if (!chl.closed())
					co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}

		void clear() override
		{
			mBaseOTs.resize(0, 0);
			mBaseChoices.resize(0, 0);
			mTempBuffer.clear();
			mDomain = 0;
			mDepth = 0;
			mPntCount = 0;
		}

		template<PprfOutputFormat Format>
		void expandOne(
			u64 treeIdx,
			bool programPuncturedPoint,
			span<span<AlignedArray<block, 8>>> levels,
			VecF& output,
			VecF& callbackLeaves,
			span<std::array<block, 2>> theirSums,
			span<u8> leafMsgs,
			u64 point,
			CoeffCtx& ctx)
		{
			assert(theirSums.size() == mDepth - 1);
			auto theirSumsIter = theirSums.begin();
			std::array<block, 8> current{};
			std::array<block, 8> next{};

			const auto zeroAes = mAesFixedKey.ecbEncBlock(ZeroBlock);
			const std::array<block, 2> inactiveInternal{
				AES::roundEnc(zeroAes, ZeroBlock),
				zeroAes.add_epi64(ZeroBlock)
			};

			// The root is the missing parent. Its two generated children cancel
			// the inactive offsets, leaving the OT correction as the sibling seed.
			if (mDepth > 1)
			{
				const auto sibling = (point >> (mDepth - 1)) ^ 1;
				current[sibling] = (*theirSumsIter)[sibling] ^ mBaseOTs(treeIdx, mDepth - 1);
				++theirSumsIter;
			}

			const auto topInternalDepth = std::min<u64>(3, mDepth - 1);
			for (u64 d = 1; d < topInternalDepth; ++d)
			{
				block leftAccumulator = inactiveInternal[0];
				block rightAccumulator = inactiveInternal[1];
				const auto width = u64{ 1 } << d;
				for (u64 parentIdx = 0; parentIdx < width; ++parentIdx)
				{
					const auto parent = current[parentIdx];
					const auto aes = mAesFixedKey.ecbEncBlock(parent);
					const auto left = AES::roundEnc(aes, parent);
					const auto right = aes.add_epi64(parent);
					next[2 * parentIdx] = left;
					next[2 * parentIdx + 1] = right;
					leftAccumulator = leftAccumulator ^ left;
					rightAccumulator = rightAccumulator ^ right;
				}

				const auto missing = point >> (mDepth - 1 - d);
				const auto sibling = missing ^ 1;
				const auto branch = sibling & 1;
				const std::array<block, 2> sums{
					leftAccumulator, rightAccumulator
				};
				next[sibling] = (*theirSumsIter)[branch] ^ sums[branch] ^
					mBaseOTs(treeIdx, mDepth - 1 - d);
				next[missing] = ZeroBlock;
				++theirSumsIter;
				current = next;
			}

			if (mDepth > 3)
			{
				assert(levels.size() == mDepth - 3);
				REGULAR_PPRF_SIMD8(lane, {
					levels[0][0][lane] = current[lane];
				});
#ifdef OC_ENABLE_VAES
				const pprfVaes::Key internalKey(mAesFixedKey);
#endif

				for (u64 localDepth = 0; localDepth + 1 < levels.size(); ++localDepth)
				{
					block leftAccumulator = inactiveInternal[0];
					block rightAccumulator = inactiveInternal[1];
					auto parents = levels[localDepth];
					auto children = levels[localDepth + 1];
					const auto width = u64{ 1 } << localDepth;
#ifdef OC_ENABLE_VAES
					{
						alignas(64) std::array<block, 8> laneSums0{}, laneSums1{};
						pprfVaes::internalLevel(internalKey, parents.data(), children.data(),
							width, laneSums0.data(), laneSums1.data());
						leftAccumulator = leftAccumulator ^ pprfVaes::fold8(laneSums0.data());
						rightAccumulator = rightAccumulator ^ pprfVaes::fold8(laneSums1.data());
					}
#else
					for (u64 parentIdx = 0; parentIdx < width; ++parentIdx)
					{
						auto& parent = parents[parentIdx];
						auto& left = children[2 * parentIdx];
						auto& right = children[2 * parentIdx + 1];
						pprf::expandGgm8(
							mAesFixedKey, parent.data(), left.data(), right.data(),
							leftAccumulator, rightAccumulator);
					}
#endif

					const auto globalDepth = 3 + localDepth;
					const auto childDepth = globalDepth + 1;
					const auto missingPrefix = point >> (mDepth - childDepth);
					const auto localChildDepth = childDepth - 3;
					const auto lane = missingPrefix >> localChildDepth;
					const auto localMask = (u64{ 1 } << localChildDepth) - 1;
					const auto missing = missingPrefix & localMask;
					const auto sibling = missing ^ 1;
					const auto branch = sibling & 1;
					const std::array<block, 2> sums{
						leftAccumulator, rightAccumulator
					};
					children[sibling][lane] = (*theirSumsIter)[branch] ^
						sums[branch] ^ mBaseOTs(treeIdx, mDepth - 1 - globalDepth);
					children[missing][lane] = ZeroBlock;
					++theirSumsIter;
				}
			}
			assert(theirSumsIter == theirSums.end());

			AlignedArray<block, 2> sumStorage, otStorage;
			AlignedArray<block, 1> zeroStorage;
			auto leafSums = pprf::leafBuffer<F>(ctx, sumStorage);
			auto zero = pprf::leafBuffer<F>(ctx, zeroStorage);
			ctx.zero(zero.begin(), zero.end());
			for (u64 side = 0; side < 2; ++side)
			{
				F inactive;
				if constexpr (std::is_same_v<F, block>)
					inactive = gGgmAes[side].hashBlock(ZeroBlock);
				else
					ctx.fromBlock(inactive, gGgmAes[side].hashBlock(ZeroBlock));
				ctx.minus(leafSums[side], zero[0], inactive);
			}

			const auto padded = pprf::paddedDomain(mDomain);
			const auto subtreeDomain = mDepth > 3 ? padded / 8 : padded;
			u64 nativeLeaf = 0;

			auto storeLeaf = [&](u64 logicalLeaf, u64 physicalLeaf, const F& value) {
				if constexpr (Format == PprfOutputFormat::ByLeafIndex)
					ctx.copy(output[logicalLeaf * mPntCount + treeIdx], value);
				else if constexpr (Format == PprfOutputFormat::ByTreeIndex)
					ctx.copy(output[treeIdx * mDomain + logicalLeaf], value);
				else if constexpr (Format == PprfOutputFormat::ByPhysicalIndex)
					ctx.copy(output[treeIdx * mDomain + physicalLeaf], value);
				else
					ctx.copy(callbackLeaves[physicalLeaf], value);
			};

			auto addLeaf = [&](u64 side, const block& hashed, u64 logicalLeaf) {
				F value;
				if constexpr (std::is_same_v<F, block>)
					value = hashed;
				else
					ctx.fromBlock(value, hashed);
				ctx.plus(leafSums[side], leafSums[side], value);
				if (logicalLeaf < mDomain)
					storeLeaf(logicalLeaf, nativeLeaf++, value);
			};

			if (mDepth <= 3)
			{
				const auto parentWidth = padded / 2;
				for (u64 parentIdx = 0; parentIdx < parentWidth; ++parentIdx)
				{
					const auto parent = current[parentIdx];
					addLeaf(0, gGgmAes[0].hashBlock(parent), 2 * parentIdx);
					addLeaf(1, gGgmAes[1].hashBlock(parent), 2 * parentIdx + 1);
				}
			}
			else
			{
				auto parents = levels.back();
				auto generateGeneric = [&] {
					if constexpr (std::is_same_v<F, block> && Format == PprfOutputFormat::ByPhysicalIndex)
					{
						nativeLeaf = pprf::hashPhysicalBlockLeaves(parents, mDomain,
							output.begin() + treeIdx * mDomain, leafSums, ctx);
						return;
					}
					std::array<block, 8> hashed;
					for (u64 parentIdx = 0; parentIdx < parents.size(); ++parentIdx)
					{
						for (u64 side = 0; side < 2; ++side)
						{
							gGgmAes[side].hashBlocks<8>(
								parents[parentIdx].data(), hashed.data());
							const auto localLeaf = 2 * parentIdx + side;
							REGULAR_PPRF_SIMD8(lane, {
								addLeaf(
									side, hashed[lane],
									lane * subtreeDomain + localLeaf);
							});
						}
					}
				};

				if constexpr (
					std::is_same_v<F, block> &&
					std::is_base_of_v<CoeffCtxGF2, CoeffCtx> &&
					(Format == PprfOutputFormat::ByPhysicalIndex ||
						Format == PprfOutputFormat::Callback))
				{
					if (mDomain == padded)
					{
						block* dest;
						if constexpr (Format == PprfOutputFormat::ByPhysicalIndex)
							dest = output.data() + treeIdx * mDomain;
						else
							dest = callbackLeaves.data();

						block leftAccumulator = gGgmAes[0].hashBlock(ZeroBlock);
						block rightAccumulator = gGgmAes[1].hashBlock(ZeroBlock);
#ifdef OC_ENABLE_VAES
						const auto sums = pprfVaes::fullLeafLevel(parents, dest);
						leftAccumulator ^= sums[0];
						rightAccumulator ^= sums[1];
						nativeLeaf += 16 * parents.size();
#else
						for (u64 parentIdx = 0; parentIdx < parents.size(); ++parentIdx)
						{
							pprf::hashGgmLeaves8(gGgmAes[0],
								parents[parentIdx].data(), dest + nativeLeaf,
								leftAccumulator);
							nativeLeaf += 8;
							pprf::hashGgmLeaves8(gGgmAes[1],
								parents[parentIdx].data(), dest + nativeLeaf,
								rightAccumulator);
							nativeLeaf += 8;
						}
#endif
						leafSums[0] = leftAccumulator;
						leafSums[1] = rightAccumulator;
					}
					else
					{
						generateGeneric();
					}
				}
				else
				{
					generateGeneric();
				}
			}
			assert(nativeLeaf == mDomain);

			const auto active = point;
			const auto inactive = active ^ 1;
			const auto inactiveSide = inactive & 1;
			const auto valueCount = 1 + u64(programPuncturedPoint);
			const auto valueBytes = valueCount * ctx.template byteSize<F>();
			auto selected = leafMsgs.subspan(inactiveSide * valueBytes, valueBytes);
			PRNG otMasker;
			pprf::xorLeafMask(selected, mBaseOTs(treeIdx, 0), otMasker);

			auto leafOts = pprf::leafBuffer<F>(ctx, { otStorage.data(), valueCount });
			ctx.deserialize(selected.begin(), selected.end(), leafOts.begin());
			if (programPuncturedPoint)
			{
				F left;
				F right;
				ctx.minus(left, leafOts[0], leafSums[0]);
				ctx.minus(right, leafOts[1], leafSums[1]);
				storeLeaf(active & ~u64{ 1 },
					pprf::physicalLeafIndex(mDomain, active & ~u64{ 1 }), left);
				storeLeaf(active | 1,
					pprf::physicalLeafIndex(mDomain, active | 1), right);
			}
			else
			{
				F keep;
				ctx.minus(keep, leafOts[0], leafSums[inactiveSide]);
				storeLeaf(inactive,
					pprf::physicalLeafIndex(mDomain, inactive), keep);
				storeLeaf(active,
					pprf::physicalLeafIndex(mDomain, active), zero[0]);
			}
		}

	};

}

#undef REGULAR_PPRF_SIMD8
#undef REGULAR_PPRF_ROUND_BARRIER

#endif
