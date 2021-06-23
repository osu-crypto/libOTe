/*
randombytes/devurandom.h version 20080713
D. J. Bernstein
Public domain.
*/

#ifndef randombytes_devurandom_H
#define randombytes_devurandom_H

#ifdef __cplusplus
extern "C" {
#endif
    extern void randombytes(unsigned char *,unsigned long long);

    // object oriented random number generator. ctx can be anything 
    // and must be the first parameter to the get function.
    typedef struct {
        void(*get)(void* ctx, unsigned char *, unsigned long long);
        void* ctx;
    } rand_source;


    // construct the default random number generator (dev/urandom)
    extern rand_source default_rand_source();

#ifdef __cplusplus
}
#endif

#ifndef randombytes_implementation
#define randombytes_implementation "devurandom"
#endif

#endif

