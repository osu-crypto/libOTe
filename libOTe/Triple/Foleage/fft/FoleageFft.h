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

namespace osuCrypto {

	// FFT for (up to) 32 polynomials over F4
	void foleageFftUint64(
		span<uint64_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs);

	// FFT for (up to) 16 polynomials over F4
	void foleageFftUint32(
		span<uint32_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs);

	// FFT for (up to) 8 polynomials over F4
	void foleageFftUint16(
		span<uint16_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs);

	// FFT for (up to) 4 polynomials over F4
	void foliageFftUint8(
		span<uint8_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs);


}

#endif