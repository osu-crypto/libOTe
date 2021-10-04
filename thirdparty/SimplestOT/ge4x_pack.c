#include "ge4x.h"

void ge4x_pack(unsigned char r[128], const ge4x *p)
{
  gfe4x tx, ty, zi;
  gfe4x_invert(&zi, &p->z); 
  gfe4x_mul(&tx, &p->x, &zi);
  gfe4x_mul(&ty, &p->y, &zi);
  gfe4x_pack(r, &ty);

  unsigned char res[4];
  gfe4x_getparity(res, &tx);

  r[31] ^= res[0] << 7;
  r[63] ^= res[1] << 7;
  r[95] ^= res[2] << 7;
  r[127] ^= res[3] << 7;
}

