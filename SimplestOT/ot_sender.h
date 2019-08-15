#ifndef OT_SENDER_H
#define OT_SENDER_H

#include <stdio.h>

#include "ge4x.h"
#include "sc25519.h"
#include "ot_config.h"

struct ot_sender
{
	unsigned char S_pack[SIMPLEST_OT_PACK_BYTES];
	sc25519 y;
	ge4x yS;
};

typedef struct ot_sender SENDER;

void sender_genS(SENDER * s, unsigned char * S_pack, rand_source rand);

void sender_keygen(SENDER *, unsigned char *, unsigned char (*)[4][SIMPLEST_OT_HASHBYTES]);

void sender_perf(SENDER* s, rand_source rand, int n);
void sender_add(SENDER* s, rand_source rand, int n);


#endif //ifndef OT_SENDER_H

