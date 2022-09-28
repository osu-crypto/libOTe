#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#define crypto_hash_BYTES 32

int crypto_hash( unsigned char *out, 
                 const unsigned char *in, 
                 unsigned long long inlen );

#endif //ifndef CRYPTO_HASH_H

