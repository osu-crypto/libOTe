#pragma once
// © 2022 Lawrence Roy.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <libOTe/config.h>

#include <cryptoTools/Common/Defines.h>
#include "GenericLinearCode.h"

namespace osuCrypto
{

	struct RepetitionCode : public GenericLinearCode<RepetitionCode>
	{
		u64 n = 0;

		RepetitionCode() : GenericLinearCode<RepetitionCode>(this) {}
		RepetitionCode(u64 n_) : GenericLinearCode<RepetitionCode>(this), n(n_) {}

		RepetitionCode(const RepetitionCode& o) : GenericLinearCode<RepetitionCode>(this), n(o.n) {}
		RepetitionCode& operator=(const RepetitionCode& o) { 
			n = o.n; 
			return *this;
		};

		u64 dimension() const { return 1; }
		u64 length() const { return n; }

		template<typename T>
		void encodeXor(const T* __restrict message, T* __restrict codeWord) const
		{
			for (u64 i = 0; i < n; ++i)
				codeWord[i] ^= message[0];
		}

		template<typename T>
		void encodeSyndrome(const T* __restrict syndrome, T* __restrict word) const
		{
			for (u64 i = 0; i < n - 1; ++i)
				word[i] = syndrome[i];
			word[n - 1] = T(0);
		}

		template<typename T>
		void decodeInPlace(T* __restrict wordInSyndromeOut, T* __restrict message) const
		{
			T msg = wordInSyndromeOut[n - 1];
			*message = msg;
			for (u64 i = 0; i < n - 1; ++i)
				wordInSyndromeOut[i] ^= msg;
		}
	};

}
