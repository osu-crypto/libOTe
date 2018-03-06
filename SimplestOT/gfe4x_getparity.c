#include "gfe4x.h"

void gfe4x_getparity(unsigned char * res, const gfe4x * a)
{
	unsigned char pa[128];

	gfe4x_pack(pa, a);

	res[0] = pa[ 0] & 1;
	res[1] = pa[32] & 1;
	res[2] = pa[64] & 1;
	res[3] = pa[96] & 1;
}

