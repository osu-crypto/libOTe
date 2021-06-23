#include "gfe4x.h"

void gfe4x_nsquare(gfe4x *r, const int n)
{
	int i;

	for (i = 0; i < n; i++)
		gfe4x_square(r, r);
}

