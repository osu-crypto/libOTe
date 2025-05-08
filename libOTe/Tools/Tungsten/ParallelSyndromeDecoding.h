#ifndef PARALLEL_SYNDROME_DECODING_H
#define PARALLEL_SYNDROME_DECODING_H

namespace osuCrypto {

#ifdef ENABLE_CUDA
	void parallelSD();
#else
	void parallelSD() {
		throw RTE_LOC;
	}
#endif
}

#endif // PARALLEL_SYNDROME_DECODING_H
