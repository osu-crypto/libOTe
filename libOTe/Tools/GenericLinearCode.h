#pragma once
// © 2022 Lawrence Roy.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <libOTe/config.h>

#include <cryptoTools/Common/Defines.h>
#include <type_traits>

namespace osuCrypto
{

	template<typename Derived>
	class GenericLinearCode
	{
	protected:
		// Force correct inheritance (https://stackoverflow.com/a/4418038/4071916)
		GenericLinearCode(Derived* this_) {}

	public:
		u64 dimension() const { return static_cast<const Derived*>(this)->dimension(); }
		u64 length() const { return static_cast<const Derived*>(this)->length(); }
		u64 codimension() const { return length() - dimension(); }

		// All of the following functions must be linear over GF(2).

		// Encode a message using the linear code. Output is be XORed into codeWord.
		template<typename T>
		void encodeXor(const T* __restrict message, T* __restrict codeWord) const
		{
			static_cast<const Derived*>(this)->encodeXor(message, codeWord);
		}

		template<typename T>
		void encodeXor(span<const T> message, span<T> codeWord) const
		{
#ifndef NDEBUG
			if ((u64)message.size() != dimension())
				throw RTE_LOC;
			if ((u64)codeWord.size() != length())
				throw RTE_LOC;
#endif
			encodeXor(message.data(), codeWord.data());
		}

		// Same, but doesn't XOR
		template<typename T>
		void encode(const T* __restrict message, T* __restrict codeWord) const
		{
			if (static_cast<void (Derived::*)(const T*, T*) const>(&Derived::template encode<T>) ==
				static_cast<void (GenericLinearCode::*)(const T*, T*) const>(&GenericLinearCode::encode<T>))
			{
				// Default implementation
				std::fill_n(codeWord, length(), T(0));
				encodeXor(message, codeWord);
			}
			else
				static_cast<const Derived*>(this)->encode(message, codeWord);
		}

		template<typename T>
		void encode(span<T> message, span<std::remove_const_t<T>> codeWord) const
		{
#ifndef NDEBUG
			if ((u64)message.size() != dimension())
				throw RTE_LOC;
			if ((u64)codeWord.size() != length())
				throw RTE_LOC;
#endif
			encode(message.data(), codeWord.data());
		}

		// Encode a (length - dimension)-bit syndrome into a (somewhat arbitrary) message. The direct
		// sum of the image of encodeSyndrome with the code (i.e. the image of encode) must the whole
		// vector space. The output is written into word, which is called "word" rather than "codeWord"
		// because it will only be in the code if syndrome is zero.
		template<typename T>
		void encodeSyndrome(const T* __restrict syndrome, T* __restrict word) const
		{
			static_cast<const Derived*>(this)->encodeSyndrome(syndrome, word);
		}

		template<typename T>
		void encodeSyndrome(span< T> syndrome, span<std::remove_const_t<T>> word) const
		{
#ifndef NDEBUG
			const u64 len = length();
			const u64 codim = len - dimension();
			if ((u64)syndrome.size() != codim)
				throw RTE_LOC;
			if ((u64)word.size() != len)
				throw RTE_LOC;
#endif
			encodeSyndrome(syndrome.data(), word.data());
		}

		// Decode into a message and a syndrome. The syndrome is output in place, while the message is
		// written into message. This function is determined by the other two, as decoding the XOR of an
		// encoded message and an encoded syndrome should decode to the original message and syndrome.
		template<typename T>
		void decodeInPlace(T* __restrict wordInSyndromeOut, T* __restrict message) const
		{
			static_cast<const Derived*>(this)->decodeInPlace(wordInSyndromeOut, message);
		}

		// Returns the syndrome, which will be a prefix of the wordInSyndromeOut span.
		template<typename T>
		span<T> decodeInPlace(span<T> wordInSyndromeOut, span<T> message) const
		{
			const u64 len = length();
			const u64 dim = dimension();
			const u64 codim = len - dim;
#ifndef NDEBUG
			if ((u64)message.size() != dim)
				throw RTE_LOC;
			if ((u64)wordInSyndromeOut.size() != len)
				throw RTE_LOC;
#endif
			decodeInPlace(wordInSyndromeOut.data(), message.data());
			return wordInSyndromeOut.subspan(0, codim);
		}
	};

}
