#include "sc25519.h"
#include "randombytes.h"

void sc25519_random(sc25519 *r, int c, rand_source rand)
{
	unsigned char x[32];

	//randombytes(x, 32);

    rand.get(rand.ctx, x, 32);

	if (c == 0) 
	{
		x[31] &= 15;
	}
	else    
	{    
		x[0] &= 248;
		x[31] &= 127;
	}

	sc25519_from32bytes(r, x);
}

