#pragma once
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
	size_t dimension() const { return static_cast<const Derived*>(this)->dimension(); }
	size_t length() const { return static_cast<const Derived*>(this)->length(); }
	size_t codimension() const { return length() - dimension(); }

	// All of the following functions must be linear over GF(2).

	// Encode a message using the linear code. Output is be XORed into codeWord.
	template<typename T>
	void encodeXor(const T* BOOST_RESTRICT message, T* BOOST_RESTRICT codeWord) const
	{
		static_cast<const Derived*>(this)->encodeXor(message, codeWord);
	}

	template<typename T>
	void encodeXor(span<const T> message, span<T> codeWord) const
	{
#ifndef NDEBUG
		if ((size_t) message.size() != dimension())
			throw RTE_LOC;
		if ((size_t) codeWord.size() != length())
			throw RTE_LOC;
#endif
		encodeXor(message.data(), codeWord.data());
	}

	// Same, but doesn't XOR
	template<typename T>
	void encode(const T* BOOST_RESTRICT message, T* BOOST_RESTRICT codeWord) const
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
		if ((size_t) message.size() != dimension())
			throw RTE_LOC;
		if ((size_t) codeWord.size() != length())
			throw RTE_LOC;
#endif
		encode(message.data(), codeWord.data());
	}

	// Encode a (length - dimension)-bit syndrome into a (somewhat arbitrary) message. The direct
	// sum of the image of encodeSyndrome with the code (i.e. the image of encode) must the whole
	// vector space. The output is written into word, which is called "word" rather than "codeWord"
	// because it will only be in the code if syndrome is zero.
	template<typename T>
	void encodeSyndrome(const T* BOOST_RESTRICT syndrome, T* BOOST_RESTRICT word) const
	{
		static_cast<const Derived*>(this)->encodeSyndrome(syndrome, word);
	}

	template<typename T>
	void encodeSyndrome(span< T> syndrome, span<std::remove_const_t<T>> word) const
	{
#ifndef NDEBUG
		const size_t len = length();
		const size_t codim = len - dimension();
		if ((size_t) syndrome.size() != codim)
			throw RTE_LOC;
		if ((size_t) word.size() != len)
			throw RTE_LOC;
#endif
		encodeSyndrome(syndrome.data(), word.data());
	}

	// Decode into a message and a syndrome. The syndrome is output in place, while the message is
	// written into message. This function is determined by the other two, as decoding the XOR of an
	// encoded message and an encoded syndrome should decode to the original message and syndrome.
	template<typename T>
	void decodeInPlace(T* BOOST_RESTRICT wordInSyndromeOut, T* BOOST_RESTRICT message) const
	{
		static_cast<const Derived*>(this)->decodeInPlace(wordInSyndromeOut, message);
	}

	// Returns the syndrome, which will be a prefix of the wordInSyndromeOut span.
	template<typename T>
	span<T> decodeInPlace(span<T> wordInSyndromeOut, span<T> message) const
	{
		const size_t len = length();
		const size_t dim = dimension();
		const size_t codim = len - dim;
#ifndef NDEBUG
		if ((size_t) message.size() != dim)
			throw RTE_LOC;
		if ((size_t) wordInSyndromeOut.size() != len)
			throw RTE_LOC;
#endif
		decodeInPlace(wordInSyndromeOut.data(), message.data());
		return wordInSyndromeOut.subspan(0, codim);
	}
};

}
