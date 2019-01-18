#ifndef INDCPA_H
#define INDCPA_H

void indcpa_keypair(unsigned char *pk, 
                   unsigned char *sk);

void indcpa_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk,
               const unsigned char *coins);

void indcpa_dec(unsigned char *m,
               const unsigned char *c,
               const unsigned char *sk);

void pkPlus(unsigned char *pk, unsigned char *pk1, unsigned char *pk2);

//pk_1-pk_2
void pkMinus(unsigned char *pk, unsigned char *pk1, unsigned char *pk2);

void returnSeed(unsigned char *seed, unsigned char *pk);
void setSeed(unsigned char *pk,unsigned char *seed);

//random PK from seed1 with packed seed seed2
void randomPK(unsigned char *pk,unsigned char *seed1, unsigned char *seed2);

#endif
