#ifndef OT_RECEIVER_H
#define OT_RECEIVER_H

#include <stdio.h>

#include "sc25519.h"
#include "ge4x.h"
#include "ot_config.h"

struct ot_receiver
{
	unsigned char S_pack[ SIMPLEST_OT_PACK_BYTES ];
	ge4x S;
	ge4x table[ 64/SIMPLEST_OT_DIS_T ][8];

	// temporary

	ge4x xB;
	sc25519 x[4];
};

typedef struct ot_receiver RECEIVER;

void receiver_maketable(RECEIVER *);
void receiver_procS(RECEIVER *);
void receiver_rsgen(RECEIVER *, unsigned char *, unsigned char *, rand_source rand);
void receiver_keygen(RECEIVER *, unsigned char (*)[SIMPLEST_OT_HASHBYTES]);

#endif //ifndef OT_RECEIVER_H

