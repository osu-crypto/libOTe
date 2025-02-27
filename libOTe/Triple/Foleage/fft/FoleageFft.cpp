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

#include <stdlib.h>
#include <stdio.h>
#include "libOTe/Triple/Foleage/fft/FoleageFft.h"

namespace osuCrypto {

	void foleageFftUint64(
		span<uint64_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs)
	{

		if (num_vars > 1)
		{
			// apply FFT on all left coefficients
			foleageFftUint64(
				coeffs,
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all middle coefficients
			foleageFftUint64(
				coeffs.subspan(num_coeffs),
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all right coefficients
			foleageFftUint64(
				coeffs.subspan(2 * num_coeffs),
				num_vars - 1,
				num_coeffs / 3);
		}

		// temp variables to store intermediate values
		uint64_t tL, tM;
		uint64_t mult, xor_h, xor_l;

		uint64_t* coeffsL = coeffs.data() + 0;
		uint64_t* coeffsM = coeffs.data() + num_coeffs;
		uint64_t* coeffsR = coeffs.data() + 2 * num_coeffs;

		const uint64_t pattern = 0xaaaaaaaaaaaaaaaa;
		const uint64_t mask_h = pattern;     // 0b101010101010101001010
		const uint64_t mask_l = mask_h >> 1; // 0b010101010101010100101

		for (size_t j = 0; j < num_coeffs; j++)
		{
			xor_h = (coeffsM[j] ^ coeffsR[j]) & mask_h;
			xor_l = (coeffsM[j] ^ coeffsR[j]) & mask_l;

			// pre compute: \alpha * (cM[j] ^ cR[j])
			// computed as: mult_l = (h ^ l) and mult_h = l
			// mult_l = (xor&mask_h>>1) ^ (xor & mask_l) [align h and l then xor]
			// mult_h = (xor&mask_l) shifted left by 1 to put in h place [shift and OR into place]
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

	void foleageFftUint32(
		span<uint32_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs)
	{
		// coeffs (coeffs_h, coeffs_l) are parsed as L(left)|M(middle)|R(right)

		if (num_vars > 1)
		{
			// apply FFT on all left coefficients
			foleageFftUint32(
				coeffs,
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all middle coefficients
			foleageFftUint32(
				coeffs.subspan(num_coeffs),
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all right coefficients
			foleageFftUint32(
				coeffs.subspan(2 * num_coeffs),
				num_vars - 1,
				num_coeffs / 3);
		}

		// temp variables to store intermediate values
		uint32_t tL, tM;
		uint32_t mult, xor_h, xor_l;

		uint32_t* coeffsL = coeffs.data() + 0;
		uint32_t* coeffsM = coeffs.data() + num_coeffs;
		uint32_t* coeffsR = coeffs.data() + 2 * num_coeffs;

		const uint32_t pattern = 0xaaaaaaaa;
		const uint32_t mask_h = pattern;     // 0b101010101010101001010
		const uint32_t mask_l = mask_h >> 1; // 0b010101010101010100101

		for (size_t j = 0; j < num_coeffs; j++)
		{
			xor_h = (coeffsM[j] ^ coeffsR[j]) & mask_h;
			xor_l = (coeffsM[j] ^ coeffsR[j]) & mask_l;

			// pre compute: \alpha * (cM[j] ^ cR[j])
			// computed as: mult_l = (h ^ l) and mult_h = l
			// mult_l = (xor&mask_h>>1) ^ (xor & mask_l) [align h and l then xor]
			// mult_h = (xor&mask_l) shifted left by 1 to put in h place [shift and OR into place]
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

	void foleageFftUint16(
		span<uint16_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs)
	{
		// coeffs (coeffs_h, coeffs_l) are parsed as L(left)|M(middle)|R(right)

		if (num_vars > 1)
		{
			// apply FFT on all left coefficients
			foleageFftUint16(
				coeffs,
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all middle coefficients
			foleageFftUint16(
				coeffs.subspan(num_coeffs),
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all right coefficients
			foleageFftUint16(
				coeffs.subspan(2 * num_coeffs),
				num_vars - 1,
				num_coeffs / 3);
		}

		// temp variables to store intermediate values
		uint16_t tL, tM;
		uint16_t mult, xor_h, xor_l;

		uint16_t* coeffsL = coeffs.data() + 0;
		uint16_t* coeffsM = coeffs.data() + num_coeffs;
		uint16_t* coeffsR = coeffs.data() + 2 * num_coeffs;

		const uint16_t pattern = 0xaaaa;
		const uint16_t mask_h = pattern;     // 0b101010101010101001010
		const uint16_t mask_l = mask_h >> 1; // 0b010101010101010100101

		for (size_t j = 0; j < num_coeffs; j++)
		{
			xor_h = (coeffsM[j] ^ coeffsR[j]) & mask_h;
			xor_l = (coeffsM[j] ^ coeffsR[j]) & mask_l;

			// pre compute: \alpha * (cM[j] ^ cR[j])
			// computed as: mult_l = (h ^ l) and mult_h = l
			// mult_l = (xor&mask_h>>1) ^ (xor & mask_l) [align h and l then xor]
			// mult_h = (xor&mask_l) shifted left by 1 to put in h place [shift and OR into place]
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

	void foliageFftUint8(
		span<uint8_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs)
	{
		// coeffs (coeffs_h, coeffs_l) are parsed as L(left)|M(middle)|R(right)

		if (num_vars > 1)
		{
			// apply FFT on all left coefficients
			foliageFftUint8(
				coeffs,
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all middle coefficients
			foliageFftUint8(
				coeffs.subspan(num_coeffs),
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all right coefficients
			foliageFftUint8(
				coeffs.subspan(2 * num_coeffs),
				num_vars - 1,
				num_coeffs / 3);
		}

		// temp variables to store intermediate values
		uint8_t tL, tM;
		uint8_t mult, xor_h, xor_l;

		uint8_t* coeffsL = coeffs.data() + 0;
		uint8_t* coeffsM = coeffs.data() + num_coeffs;
		uint8_t* coeffsR = coeffs.data() + 2 * num_coeffs;

		const uint8_t pattern = 0xaa;
		const uint8_t mask_h = pattern;     // 0b101010101010101001010
		const uint8_t mask_l = mask_h >> 1; // 0b010101010101010100101

		for (size_t j = 0; j < num_coeffs; j++)
		{
			xor_h = (coeffsM[j] ^ coeffsR[j]) & mask_h;
			xor_l = (coeffsM[j] ^ coeffsR[j]) & mask_l;

			// pre compute: \alpha * (cM[j] ^ cR[j])
			// computed as: mult_l = (h ^ l) and mult_h = l
			// mult_l = (xor&mask_h>>1) ^ (xor & mask_l) [align h and l then xor]
			// mult_h = (xor&mask_l) shifted left by 1 to put in h place [shift and OR into place]
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