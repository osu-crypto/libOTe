#pragma once
#include "libOTe/Vole/Noisy/NoisyVoleSender.h"
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/BitVector.h"
#include <sstream>
#include <cryptoTools/Common/block.h>

namespace osuCrypto {

	/*
	 * Primitive CoeffCtx for integers-like types
	 *
	 * This class implements the required functions to perform a vole
	 *
	 * The core functions are plus, minus, mul. However, additional function
	 * and types are required.
	 */
	struct CoeffCtxInteger
	{
		template<typename R, typename F1, typename F2>
		OC_FORCEINLINE void plus(R&& ret, F1&& lhs, F2&& rhs)const {
			ret = lhs + rhs;
		}

		template<typename R, typename F1, typename F2>
		OC_FORCEINLINE void minus(R&& ret, F1&& lhs, F2&& rhs) const {
			ret = lhs - rhs;
		}
		template<typename R, typename F1, typename F2>
		OC_FORCEINLINE void mul(R&& ret, F1&& lhs, F2&& rhs)const {
			ret = lhs * rhs;
		}

		OC_FORCEINLINE bool eq(auto&& lhs, auto&& rhs)const {
			return lhs == rhs;
		}

		// is G a field?
		template<typename G>
		OC_FORCEINLINE bool isField() const {
			return false; // default.
		}

		// is G characteristic 2 where x+x = 0?
		template<typename G>
		bool characteristicTwo()const
		{
			auto v = make<G>();
			auto z = make<G>();
			one(v);
			zero(z);
			plus(v, v, v);
			return eq(v, z); // char 2 if 1+1 = 0;
		}

		// For the base field G is an extension fields, 
		// mulConst should multiply x by some constant in G to linearly
		// mix the components. Most of the LPN codes this library
		// uses are binary and so for extension field this would
		// result in the componets not interactive. This can lead 
		// to a splitting attack. To fix this we multiply by some 
		// non-zero G element.
		//
		// If your type is a scaler, e.g. Fp or Z2k, just return x.
		template<typename F>
		OC_FORCEINLINE void mulConst(F& ret, const F& x)const
		{
			ret = x;
		}

		// the bit size require to prepresent F
		// the protocol will perform binary decomposition
		// of F using this many bits
		template<typename F>
		u64 bitSize()const
		{
			return sizeof(F) * 8;
		}

		// return the binary decomposition of x. This will be used to 
		// reconstruct x as   
		// 
		//     x = sum_{i = 0,...,n} 2^i * binaryDecomposition(x)[i]
		//
		template<typename F>
		OC_FORCEINLINE BitVector binaryDecomposition(F& x) const {
			static_assert(std::is_trivially_copyable<F>::value, "memcpy is used so must be trivially_copyable.");
			return { (u8*)&x, bitSize<F>() };
		}

		// derive an F using the randomness b. 
		template<typename F>
		OC_FORCEINLINE void fromBlock(F& ret, const block& b) const {
			static_assert(std::is_trivially_copyable<F>::value, "memcpy is used so must be trivially_copyable.");

			if constexpr (std::is_same<F, block>::value)
			{
				// if F is a block, just return the block.
				ret = b;
			}
			else if constexpr (sizeof(F) <= sizeof(block))
			{
				// if small, just return the bytes of b
				memcpy(&ret, &b, sizeof(F));
			}
			else
			{
				// if large, we need to expand the seed. using fixed key AES in counter mode
				// with b as the IV.
				auto constexpr size = (sizeof(F) + sizeof(block) - 1) / sizeof(block);
				std::array<block, size> buffer;
				mAesFixedKey.ecbEncCounterMode(b, buffer);
				memcpy(&ret, buffer.data(), sizeof(ret));
			}
		}

		// return the F element with value 2^power
		template<typename F>
		OC_FORCEINLINE void powerOfTwo(F& ret, u64 power)const {
			static_assert(std::is_trivially_copyable<F>::value, "memcpy is used so must be trivially_copyable.");
			memset(&ret, 0, sizeof(F));
			*BitIterator((u8*)&ret, power) = 1;
		}

		// A vector like type that can be used to store
		// temporaries. 
		// 
		// must have:
		//  * size()
		//  * operator[i] that returns the i'th F element reference.
		//  * begin() iterator over the F elements
		//  * end() iterator over the F elements
		template<typename F>
		using Vec = std::conditional_t<std::is_trivially_constructible_v<F>, AlignedUnVector<F>, std::vector<F>>;

		// resize Vec<F>
		template<typename VecF>
		void resize(VecF& f, u64 size)const
		{
			f.resize(size);
		}


		// return a new vector of F.
		template<typename F>
		auto makeVec(u64 size)const
		{
			return Vec<F>(size);
		}

		// return a new F or something that is implicitly convertable to one.
		template<typename F>
		auto make()const
		{
			return F{};
		}

		// the size of F when serialized.
		template<typename F>
		u64 byteSize()const
		{
			return sizeof(F);
		}

		// copy a single F element.
		template<typename F>
		OC_FORCEINLINE void copy(F& dst, const F& src)const
		{
			dst = src;
		}

		// copy [begin,...,end) into [dstBegin, ...)
		// the iterators will point to the same types, i.e. F
		template<typename SrcIter, typename DstIter>
		OC_FORCEINLINE void copy(
			SrcIter begin,
			SrcIter end,
			DstIter dstBegin)const
		{
			using F1 = std::remove_reference_t<decltype(*begin)>;
			using F2 = std::remove_reference_t<decltype(*dstBegin)>;
			static_assert(std::is_trivially_copyable<F1>::value, "memcpy is used so must be trivially_copyable.");
			static_assert(std::is_same_v<F1, F2>, "src and destication types are not the same.");

			auto n = std::distance(begin, end);
			if (n)
				memcpy((F2 * __restrict) & *dstBegin, (F1 * __restrict) & *begin, n * sizeof(F1));
			//std::copy(begin, end, dstBegin);
		}

		// deserialize [begin,...,end) into  [dstBegin, ...)
		// begin will be a u8 pointer/iterator.
		// dstBegin will be an F pointer/iterator
		template<typename SrcIter, typename DstIter>
		void deserialize(SrcIter&& begin, SrcIter&& end, DstIter&& dstBegin)const
		{
			// as written this function is a bit more general than strictly neccessary
			// due to serialize(...) redirecting here.
			using SrcType = std::remove_reference_t<decltype(*begin)>;
			using DstType = std::remove_reference_t<decltype(*dstBegin)>;
			static_assert(std::is_trivially_copyable<SrcType>::value, "source serialization types must be trivially_copyable.");
			static_assert(std::is_trivially_copyable<DstType>::value, "destination serialization types must be trivially_copyable.");

			// how many source elem do we have?
			auto srcN = std::distance(begin, end);
			if (srcN)
			{
				// the source size in bytes
				auto n = srcN * sizeof(SrcType);

				// The byte size must be a multiple of the destination element byte size.
				if (n % sizeof(DstType))
				{
					std::cout << "bad buffer size. the source buffer (byte) size is not a multiple of the distination value type size." LOCATION << std::endl;
					std::terminate();
				}
				// the number of destination elements.
				auto dstN = n / sizeof(DstType);

				// make sure the pointer math work with this iterator type.
				auto beginU8 = (u8*)&*begin;
				auto dstBeginU8 = (u8*)&*dstBegin;

				auto dstBackPtr = dstBeginU8 + (n - sizeof(DstType));
				auto dstBackIter = dstBegin + (dstN - 1);

				// try to deref the back. might bounds check.
				// And check that the pointer math works
				if (dstBackPtr != (u8*)&*dstBackIter)
				{
					std::cout << "bad destination iterator type. pointer arithemtic not correct. " LOCATION << std::endl;
					std::terminate();
				}

				auto srcBackPtr = beginU8 + (n - sizeof(SrcType));
				auto srcBackIter = begin + (srcN - 1);

				// try to deref the back. might bounds check.
				// And check that the pointer math works
				if (srcBackPtr != (u8*)&*srcBackIter)
				{
					std::cout << "bad source iterator type. pointer arithemtic not correct. " LOCATION << std::endl;
					std::terminate();
				}

				// memcpy the bytes
				std::memcpy(dstBeginU8, beginU8, n);
			}
		}

		// serialize [begin,...,end) into  [dstBegin, ...)
		// begin will be an F pointer/iterator
		// dstBegin will be a byte pointer/iterator.
		template<typename SrcIter, typename DstIter>
		void serialize(SrcIter&& begin, SrcIter&& end, DstIter&& dstBegin)const
		{
			// for primitive types serialization and deserializaion 
			// are the same, a memcpy.
			deserialize(begin, end, dstBegin);
		}


		// If unsure you can just return iter. iter will be 
		// a Vec<F>::iterator or const of it.
		// This function allows for some compiler optimziations/
		// The idea is to return a pointer with the __restrict
		// attibute. If this does not make sense for your Vec<F>::iterator,
		// just return the iterator.
		template<typename F, typename Iter>
		F* __restrict restrictPtr(Iter iter)const
		{
			return &*iter;
		}


		// fill the range [begin,..., end) with zeros. 
		// begin will be an F pointer/iterator.
		template<typename Iter>
		void zero(Iter begin, Iter end)const
		{
			using F = std::remove_reference_t<decltype(*begin)>;
			static_assert(std::is_trivially_copyable<F>::value, "memset is used so must be trivially_copyable.");

			if (begin != end)
			{
				auto n = std::distance(begin, end);
				assert(n > 0);
				memset(&*begin, 0, n * sizeof(F));
			}
		}

		// fill the range [begin,..., end) with zeros. 
		// begin will be an F pointer/iterator.
		template<typename F>
		void zero(F&& x)const
		{

			if constexpr (requires(F x) { std::remove_cvref_t<F>::zero(); })
				x = std::remove_cvref_t<F>::zero();
			else
				x = std::remove_cvref_t<F>(0);
		}


		// fill the range [begin,..., end) with ones. 
		// begin will be an F pointer/iterator.
		template<typename Iter>
		void one(Iter begin, Iter end)const
		{
			using F = std::remove_reference_t<decltype(*begin)>;

			if (begin != end)
			{
				auto n = std::distance(begin, end);
				assert(n > 0);

				if constexpr (requires(F x) { F::one(); })
				{
					for (u64 i = 0; i < n; ++i)
						begin[i] = F::one();
				}
				else
				{
					static_assert(std::is_trivially_copyable<F>::value, "memset is used so must be trivially_copyable.");

					memset(&*begin, 0, n * sizeof(F));
					while (begin != end)
					{
						auto& v = *begin++;
						*(u8*)&v = 1;
					}
				}
			}
		}


		// fill the range [begin,..., end) with zeros. 
		// begin will be an F pointer/iterator.
		template<typename F>
		void one(F&& x)const
		{
			using FF = std::remove_cvref_t<F>;
			if constexpr (requires(FF x) { x = FF::one(); })
			{
				x = FF::one();
			}
			else
				x = FF(1);
		}

		// convert F into a string
		template<typename F>
		std::string str(F&& f)const
		{
			std::stringstream ss;
			if constexpr (std::is_same_v<std::remove_reference_t<F>, u64>)
			{
				ss << i64(f);
			}
			else if constexpr (std::is_same_v<std::remove_reference_t<F>, u8>)
				ss << int(f);
			else
				ss << f;

			return ss.str();
		}


		// given x and a masking block `mask` with value 0x0000...00 or 0xffff...ff,
		// return F(0) if `mask` is 0 and otherwise return x.
		template<typename F>
		void mask(F& ret, const F& x, const block& mask)const
		{
			if constexpr (
				requires(F & x) { x = x & x; } &&
				std::is_standard_layout<F>::value &&
				std::is_trivial<F>::value &&
				(sizeof(F) <= sizeof(block)) &&
				(sizeof(block) % sizeof(F) == 0))
			{
				F y = mask.get<F>(0);;
				ret = x & y;
			}
			else
			{
				static_assert(std::is_trivially_copyable<F>::value, "memcpy is used so must be trivially_copyable.");
				if constexpr (sizeof(F) % sizeof(block) == 0)
				{
					// block oriented
					block temp[sizeof(F) / sizeof(block)];
					memcpy(&temp, &x, sizeof(F));
					for (u64 i = 0; i < sizeof(F) / sizeof(block); ++i)
						temp[i] &= mask;
					memcpy(&ret, &temp, sizeof(F));
				}
				else
				{
					// byte oriented
					auto m = mask.get<u8>(0);
					u8 temp[sizeof(F)];
					memcpy(&temp, &x, sizeof(F));
					for (u64 i = 0; i < sizeof(F); ++i)
						temp[i] &= m;
					memcpy(&ret, &temp, sizeof(F));
				}
			}
		}

	};



	// block does not use operator*
	struct CoeffCtxGF2 : CoeffCtxInteger
	{
		template<typename F>
		OC_FORCEINLINE void plus(F& ret, const F& lhs, const F& rhs)const {
			ret = lhs ^ rhs;
		}
		template<typename F>
		OC_FORCEINLINE void minus(F& ret, const F& lhs, const F& rhs)const {
			ret = lhs ^ rhs;
		}
		template<typename F>
		OC_FORCEINLINE void mul(F& ret, const F& lhs, const F& rhs) const {
			ret = lhs & rhs;
		}

		template<typename F>
		OC_FORCEINLINE void mul(F& ret, const F& lhs, const bool& rhs) const {
			ret = rhs ? lhs : zeroElem<F>();
		}

		// the bit size require to prepresent F
		// the protocol will perform binary decomposition
		// of F using this many bits
		template<typename F>
		u64 bitSize()const
		{
			if (std::is_same<bool, F>::value)
				return 1;
			else
				return sizeof(F) * 8;
		}

		// is F a field?
		template<typename F>
		OC_FORCEINLINE bool isField() const {
			return true; // default.
		}

		template<typename G>
		bool characteristicTwo()const
		{
			return true; // GF2 is characteristic 2.
		}

		template<typename F>
		static OC_FORCEINLINE constexpr F zeroElem()
		{
			static_assert(std::is_trivially_copyable<F>::value, "memset is used so must be trivially_copyable.");
			F r;
			memset(&r, 0, sizeof(F));
			return r;
		}
	};


	// block does not use operator*
	struct CoeffCtxGF128 : CoeffCtxGF2
	{

		OC_FORCEINLINE void mul(block& ret, const block& lhs, const block& rhs) const {
			ret = lhs.gf128Mul(rhs);
		}

		// ret = x * 4234123421 mod 2^127 - 135
		OC_FORCEINLINE void mulConst(block& ret, const block& x)const
		{
			// multiplication y modulo mod
			block y(0, 4234123421);

#ifdef ENABLE_SSE
			static const constexpr std::uint64_t mod = 0b10000111;
			const __m128i modulus = _mm_loadl_epi64((const __m128i*) & (mod));

			block xy1 = _mm_clmulepi64_si128(x, y, (int)0x00);
			block xy2 = _mm_clmulepi64_si128(x, y, 0x01);
			xy1 = xy1 ^ _mm_slli_si128(xy2, 8);
			xy2 = _mm_srli_si128(xy2, 8);

			/* reduce w.r.t. high half of mul256_high */
			auto tmp = _mm_clmulepi64_si128(xy2, modulus, 0x00);
			ret = _mm_xor_si128(xy1, tmp);
#else
			ret = x.gf128Mul(y);
#endif
		}
	};


	template<typename G, u64 N>
	struct CoeffCtxArray : CoeffCtxInteger
	{
		using F = std::array<G, N>;

		OC_FORCEINLINE void plus(F& ret, const F& lhs, const F& rhs) const {
			for (u64 i = 0; i < lhs.size(); ++i) {
				ret[i] = lhs[i] + rhs[i];
			}
		}

		OC_FORCEINLINE void plus(G& ret, const  G& lhs, const G& rhs) const {
			ret = lhs + rhs;
		}

		OC_FORCEINLINE void minus(F& ret, const F& lhs, const F& rhs)const
		{
			for (u64 i = 0; i < lhs.size(); ++i) {
				ret[i] = lhs[i] - rhs[i];
			}
		}

		OC_FORCEINLINE void minus(G& ret, const G& lhs, const G& rhs)const {
			ret = lhs - rhs;
		}

		OC_FORCEINLINE void mul(F& ret, const F& lhs, const G& rhs)const
		{
			for (u64 i = 0; i < lhs.size(); ++i) {
				ret[i] = lhs[i] * rhs;
			}
		}

		OC_FORCEINLINE bool eq(const F& lhs, const F& rhs)const
		{
			for (u64 i = 0; i < lhs.size(); ++i) {
				if (lhs[i] != rhs[i])
					return false;
			}
			return true;
		}

		OC_FORCEINLINE bool eq(const G& lhs, const G& rhs)const
		{
			return lhs == rhs;
		}

		// convert F into a string
		std::string str(const F& f)const
		{
			auto delim = "{ ";
			std::stringstream ss;
			for (u64 i = 0; i < f.size(); ++i)
			{
				ss << std::exchange(delim, ", ");

				if constexpr (std::is_same_v<std::remove_reference_t<G>, u8>)
					ss << int(f[i]);
				else
					ss << f[i];

			}
			ss << " }";

			return ss.str();
		}

		// convert G into a string
		std::string str(const G& g)const
		{
			std::stringstream ss;
			if constexpr (std::is_same_v<std::remove_reference_t<G>, u8>)
				ss << int(g);
			else
				ss << g;

			return ss.str();
		}

	};

	template<typename F, typename G = F>
	struct DefaultCoeffCtx_t {
		using type = CoeffCtxInteger;
	};

	// GF128 vole
	template<>
	struct DefaultCoeffCtx_t<block, block> {
		using type = CoeffCtxGF128;
	};

	// OT, gf2
	template<> struct DefaultCoeffCtx_t<block, bool> {
		using type = CoeffCtxGF2;
	};

	template<typename F, typename G = F>
	using DefaultCoeffCtx = typename DefaultCoeffCtx_t<F, G>::type;
}
