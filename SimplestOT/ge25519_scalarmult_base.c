#include "fe25519.h"
#include "sc25519.h"
#include "ge25519.h"


/* Multiples of the base point in Niels' representation */
static const ge25519_niels ge25519_base_multiples_niels[] = {
#include "ge25519.data"
};

extern void ge25519_lookup_niels_asm(ge25519_niels *, const ge25519_niels *, const char *);

void ge25519_scalarmult_base(ge25519_p3 *r, const sc25519 *s)
{
  char b[64];
  int i;
  ge25519_niels t;
  fe25519 d;

  sc25519_window4(b,s);

  ge25519_lookup_niels_asm((ge25519_niels *) r, ge25519_base_multiples_niels + 8*0, &b[0]);

  fe25519_sub(&d, &r->y, &r->x);
  fe25519_add(&r->y, &r->y, &r->x);
  r->x = d;
  r->t = r->z; 
  fe25519_setint(&r->z,2);

  for(i = 1; i < 64; i++)
  {
    ge25519_lookup_niels_asm(&t, ge25519_base_multiples_niels + 8*i, &b[i]);
    ge25519_nielsadd2(r, &t);
  }
}

