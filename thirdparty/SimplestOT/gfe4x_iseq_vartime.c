#include "gfe4x.h"

void gfe4x_iseq_vartime(unsigned char *r, const gfe4x *x, const gfe4x *y)
{
	int i, j;

	unsigned char px[128];
	unsigned char py[128];

	gfe4x_pack(px, x);
	gfe4x_pack(py, y);

	for (i = 0; i < 4; i++)	
	{
		r[i] = 0;

		for (j = 0; j < 32; j++)	
		{
			if (px[i*32+j] != py[i*32+j])
			{
				r[i] = 1;
				break;
			}
		}
	}
}

