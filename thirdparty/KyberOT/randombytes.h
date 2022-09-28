#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#define _GNU_SOURCE

#include <unistd.h>

void randombytes_kyber(unsigned char *x, size_t xlen);

#endif
