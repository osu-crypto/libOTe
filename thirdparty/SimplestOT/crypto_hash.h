#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include "cryptoTools/Crypto/Edwards25519/ge4x.h"

#define crypto_hash_BYTES 32

int crypto_hash( unsigned char *out, 
                 const unsigned char *in, 
                 unsigned long long inlen );

void ge4x_hash(unsigned char *, unsigned char *, unsigned char *, ge4x *);

#endif //ifndef CRYPTO_HASH_H

