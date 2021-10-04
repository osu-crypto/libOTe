#include "ge25519.h"

void ge25519_setneutral(ge25519 *r)
{
	fe25519_setint(&r->x, 0);
	fe25519_setint(&r->y, 1);
	fe25519_setint(&r->z, 1);
	fe25519_setint(&r->t, 0);
}

