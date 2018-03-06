#include "ot_receiver.h"

#include <stdlib.h>

#include "ge25519.h"
#include "ge4x.h"
#include "to_4x.h"

void receiver_maketable(RECEIVER * r)
{
	ge4x_maketable(r->table, &r->S, SIMPLEST_OT_DIS_T);
}

void receiver_procS(RECEIVER * r)
{
	int i;

	ge25519 S;

	if (ge25519_unpack_vartime(&S, r->S_pack) != 0)
	{ 
		fprintf(stderr, "Error: point decompression failed\n"); exit(-1);
	}

	for (i = 0; i < 3; i++) ge25519_double(&S, &S); // 8S

	ge25519_pack(r->S_pack, &S); // E_1(S)
	ge_to_4x(&r->S, &S);
}

void receiver_rsgen(RECEIVER * r, 
                     unsigned char * Rs_pack,
                     unsigned char * cs,
                    rand_source rand)
{
	int i;

	ge4x P;
	
	//

	for (i = 0; i < 4; i++) sc25519_random(&r->x[i], 1, rand);
	ge4x_scalarsmults_base(&r->xB, r->x); // 8x^iB

	ge4x_sub(&P, &r->S, &r->xB); // 8S - 8x^iB
	ge4x_cmovs(&r->xB, &P, cs);

	ge4x_pack(Rs_pack, &r->xB); // E^1(R^i)

}

void receiver_keygen(RECEIVER * r, 
                     unsigned char (*keys)[SIMPLEST_OT_HASHBYTES])
{
	int i;

	unsigned char Rs_pack[ 4 * SIMPLEST_OT_PACK_BYTES ];
	ge4x P;
	
	//

	for (i = 0; i < 3; i++) ge4x_double(&r->xB, &r->xB);
	ge4x_pack(Rs_pack, &r->xB); // E_2(R^i)

	ge4x_scalarsmults_table(&P, r->table, r->x, SIMPLEST_OT_DIS_T); // 64x^iS

	ge4x_hash(keys[0], r->S_pack, Rs_pack, &P); // E_2(x^iS)
}

