#pragma once
// © 2025 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// Code partially authored by:
// Maxime Bombar, Dung Bui, Geoffroy Couteau, Alain Couvreur, Clément Ducros, and Sacha Servan - Schreiber

#include "libOTe/config.h"
#if defined(ENABLE_FOLEAGE)

#include <string.h>
#include <stdint.h>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/MatrixView.h"
#include "libOTe/Triple/Foleage/FoleageUtils.h"

namespace osuCrypto 
{

	// FFT for (up to) 64 polynomials over F4
	template<typename T>
	void foleageFft(
		span<T> coeffs,
		const size_t num_vars,
		const size_t num_coeffs)
	{
		// coeffs (coeffs_h, coeffs_l) are parsed as L(left)|M(middle)|R(right)

		if (num_vars > 1)
		{
			// apply FFT on all left coefficients
			foleageFft(
				coeffs,
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all middle coefficients
			foleageFft(
				coeffs.subspan(num_coeffs),
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all right coefficients
			foleageFft(
				coeffs.subspan(2 * num_coeffs),
				num_vars - 1,
				num_coeffs / 3);
		}

		// temp variables to store intermediate values
		T tL, tM;
		T mult, xor_h, xor_l;

		T* coeffsL = coeffs.data() + 0;
		T* coeffsM = coeffs.data() + num_coeffs;
		T* coeffsR = coeffs.data() + 2 * num_coeffs;

		T mask_h; // 1010101001010
		T mask_l; // 10101010100101
		setBytes(mask_h, 0b10101010);
		setBytes(mask_l, 0b01010101);

		for (size_t j = 0; j < num_coeffs; j++)
		{
			xor_h = (coeffsM[j] ^ coeffsR[j]) & mask_h;
			xor_l = (coeffsM[j] ^ coeffsR[j]) & mask_l;

			// pre compute: \alpha * (cM[j] ^ cR[j])
			// computed as: mult_l = (h ^ l) and mult_h = l
			// mult_l = (xor&mask_h>>1) ^ (xor & mask_l) [align h and l then xor]
			// mult_h = (xor&mask_l) shifted left by 1 to put in h place [shift and OR into place]
			if constexpr(std::is_same_v<T,block>)
				mult = (xor_h.srli_epi64(1) ^ xor_l) | xor_l.slli_epi64(1);
			else
				mult = ((xor_h >> 1) ^ xor_l) | (xor_l << 1);

			// tL coefficient obtained by evaluating on X_i=1
			tL = coeffsL[j] ^ coeffsM[j] ^ coeffsR[j];

			// tM coefficient obtained by evaluating on X_i=\alpha
			tM = coeffsL[j] ^ coeffsR[j] ^ mult;

			// Explanation:
			// cL + cM*\alpha + cR*\alpha^2
			// = cL + cM*\alpha + cR*\alpha + cR
			// = cL + cR + \alpha*(cM + cR)

			// tR: coefficient obtained by evaluating on X_i=\alpha^2=\alpha + 1
			coeffsR[j] = coeffsL[j] ^ coeffsM[j] ^ mult;

			// Explanation:
			// cL + cM*(\alpha+1) + cR(\alpha+1)^2
			// = cL + cM + cM*\alpha + cR*(3\alpha + 2)
			// = cL + cM + \alpha*(cM + cR)
			// Note: we're in the F_2 field extension so 3\alpha+2 = \alpha+0.

			coeffsL[j] = tL;
			coeffsM[j] = tM;
		}
	}
}

#endif