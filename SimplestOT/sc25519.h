#ifndef SC25519_H
#define SC25519_H

typedef struct 
{
  unsigned long long v[4]; 
}
sc25519;
#include "randombytes.h"

void sc25519_random(sc25519 *, int, rand_source rand_source);
void sc25519_from32bytes(sc25519 *r, const unsigned char x[32]);
void sc25519_window4(char r[64], const sc25519 *s); //

#endif

