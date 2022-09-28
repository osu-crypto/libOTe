#include "ot_sender.h"

#include <stdlib.h>

#include "ge25519.h"
#include "ge4x.h"
#include "to_4x.h"

void sender_genS(SENDER * s, unsigned char * S_pack, rand_source rand)
{
	int i;

	ge25519 S, yS;

	//

	sc25519_random(&s->y, 0, rand);

	ge25519_scalarmult_base(&S, &s->y); // S	

	ge25519_pack(S_pack, &S); // E^0(S)

	for (i = 0; i < 3; i++) ge25519_double(&S, &S); // 8S

	ge25519_pack(s->S_pack, &S); // E_1(S)

	ge25519_scalarmult(&yS, &S, &s->y);	
	for (i = 0; i < 3; i++) ge25519_double(&yS, &yS); // 64T
	ge_to_4x(&s->yS, &yS);
}

void sender_keygen(SENDER * s, 
                   unsigned char * Rs_pack, 
                   unsigned char (*keys)[4][SIMPLEST_OT_HASHBYTES])
{
	int i;

	ge4x P0;
	ge4x P1;
	ge4x Rs;

	//

	if (ge4x_unpack_vartime(&Rs, Rs_pack) != 0)
	{ 
		fprintf(stderr, "Error: point decompression failed\n"); exit(-1);
	}

	for (i = 0; i < 3; i++) ge4x_double(&Rs, &Rs); // 64R^i

	ge4x_pack(Rs_pack, &Rs); // E_2(R^i)

	ge4x_scalarmults(&P0, &Rs, &s->y); // 64yR^i	
	ge4x_hash(keys[0][0], s->S_pack, Rs_pack, &P0); // E_2(yR^i)

	ge4x_sub(&P1, &s->yS, &P0); // 64(T-yR^i)
	ge4x_hash(keys[1][0], s->S_pack, Rs_pack, &P1); // E_2(T - yR^i)
}


void sender_perf(SENDER* s, rand_source rand, int n)
{
    //ge25519 S, yS;

    //sc25519_random(&s->y, 0, rand);

    ge4x P0;
    //ge4x P1;
    ge4x Rs;

    n = (n + 3) / 4;

    for (int i = 0; i < n; ++i)
        ge4x_scalarmults(&P0, &Rs, &s->y); // 64yR^i	

}

void sender_add(SENDER* s, rand_source rand, int n)
{
    //ge25519 S, yS;

    //sc25519_random(&s->y, 0, rand);

    ge4x P0;
    ge4x P1;
    //ge4x Rs;

    n = (n + 3) / 4;

    for (int i = 0; i < n; ++i)
        ge4x_sub(&P1, &s->yS, &P0); // 64yR^i	

}