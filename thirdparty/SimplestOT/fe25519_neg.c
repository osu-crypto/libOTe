#include "fe25519.h"

void fe25519_copy(fe25519 *r, const fe25519 *x)
{
//  fe25519 t;
 // /fe25519_setint(&t,0);
 // fe25519_sub(r,&t,x);
  int i;
  for (i = 0; i < 5; i++)
	r->v[i] = x->v[i];

//	printf("???\n");
}

void fe25519_neg(fe25519 *r, const fe25519 *x)
{
  fe25519 t;
  fe25519_setint(&t,0);
  fe25519_sub(r,&t,x);
}

