#include "gfe4x.h"

void gfe4x_pow2523(gfe4x *r, const gfe4x *x)
{
	gfe4x z2;
	gfe4x z9;
	gfe4x z11;
	gfe4x z2_5_0;
	gfe4x z2_10_0;
	gfe4x z2_20_0;
	gfe4x z2_50_0;
	gfe4x z2_100_0;
	gfe4x t;
		
	/* 2 */ gfe4x_square(&z2,x);
	/* 4 */ gfe4x_square(&t,&z2);
	/* 8 */ gfe4x_square(&t,&t);
	/* 9 */ gfe4x_mul(&z9,&t,x);
	/* 11 */ gfe4x_mul(&z11,&z9,&z2);
	/* 22 */ gfe4x_square(&t,&z11);
	/* 2^5 - 2^0 = 31 */ gfe4x_mul(&z2_5_0,&t,&z9);

	/* 2^6 - 2^1 */ gfe4x_square(&t,&z2_5_0);
	/* 2^10 - 2^5 */ gfe4x_nsquare(&t,4);
	/* 2^10 - 2^0 */ gfe4x_mul(&z2_10_0,&t,&z2_5_0);

	/* 2^11 - 2^1 */ gfe4x_square(&t,&z2_10_0);
	/* 2^20 - 2^10 */ gfe4x_nsquare(&t,9);
	/* 2^20 - 2^0 */ gfe4x_mul(&z2_20_0,&t,&z2_10_0);

	/* 2^21 - 2^1 */ gfe4x_square(&t,&z2_20_0);
	/* 2^40 - 2^20 */ gfe4x_nsquare(&t,19);
	/* 2^40 - 2^0 */ gfe4x_mul(&t,&t,&z2_20_0);

	/* 2^41 - 2^1 */ gfe4x_square(&t,&t);
	/* 2^50 - 2^10 */ gfe4x_nsquare(&t,9);
	/* 2^50 - 2^0 */ gfe4x_mul(&z2_50_0,&t,&z2_10_0);

	/* 2^51 - 2^1 */ gfe4x_square(&t,&z2_50_0);
	/* 2^100 - 2^50 */ gfe4x_nsquare(&t,49);
	/* 2^100 - 2^0 */ gfe4x_mul(&z2_100_0,&t,&z2_50_0);

	/* 2^101 - 2^1 */ gfe4x_square(&t,&z2_100_0);
	/* 2^200 - 2^100 */ gfe4x_nsquare(&t,99);
	/* 2^200 - 2^0 */ gfe4x_mul(&t,&t,&z2_100_0);

	/* 2^201 - 2^1 */ gfe4x_square(&t,&t);
	/* 2^250 - 2^50 */ gfe4x_nsquare(&t,49);
	/* 2^250 - 2^0 */ gfe4x_mul(&t,&t,&z2_50_0);

	/* 2^251 - 2^1 */ gfe4x_square(&t,&t);
	/* 2^252 - 2^2 */ gfe4x_square(&t,&t);
	/* 2^252 - 3 */ gfe4x_mul(r,&t,x);
}
