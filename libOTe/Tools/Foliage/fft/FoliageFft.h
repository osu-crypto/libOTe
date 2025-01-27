#pragma once

#include <string.h>
#include <stdint.h>
#include "cryptoTools/Common/Defines.h"

//#include "libOTe/Tools/Foliage/utils.h"
namespace osuCrypto {

	//typedef __int128 int128_t;
	//typedef unsigned __int128 uint128_t;

	// FFT for (up to) 32 polynomials over F4
	void fft_recursive_uint64(
		span<uint64_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs);

	// FFT for (up to) 16 polynomials over F4
	void fft_recursive_uint32(
		span<uint32_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs);

	// FFT for (up to) 8 polynomials over F4
	void fft_recursive_uint16(
		span<uint16_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs);

	// FFT for (up to) 4 polynomials over F4
	void fft_recursive_uint8(
		span<uint8_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs);

}
