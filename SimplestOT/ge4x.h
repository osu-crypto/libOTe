#ifndef GE4X_H
#define GE4X_H

#include "gfe4x.h"
#include "sc25519.h"

typedef struct{

	gfe4x x;
	gfe4x y;
	gfe4x z;
	gfe4x t;

} ge4x;

typedef struct{

	gfe4x x;
	gfe4x y;
	gfe4x z;
	gfe4x t;

} ge4x_p1p1;

typedef struct{

	gfe4x x;
	gfe4x y;
	gfe4x z;

} ge4x_p2;

typedef struct{

	gfe4x x;
	gfe4x y;
	gfe4x z;

} ge4x_niels;

void ge4x_cmovs(ge4x *r, const ge4x *x, unsigned char * b);

void ge4x_setneutral(ge4x * a);
void ge4x_neg(ge4x * a, const ge4x * b);
void ge4x_add(ge4x * a, const ge4x * b, const ge4x * c);
void ge4x_sub(ge4x * c, const ge4x * a, const ge4x * b);
void ge4x_double(ge4x * a, const ge4x * b);

void ge4x_maketable(ge4x (*table)[8], const ge4x * b, int dist);

void ge4x_scalarmults_base(ge4x * a, const sc25519 * s);
void ge4x_scalarmults(ge4x * a, ge4x * b, const sc25519 * s);

void ge4x_scalarsmults_base(ge4x * a, const sc25519 * s);
void ge4x_scalarsmults_naive(ge4x * a, ge4x * b, const sc25519 * s);
void ge4x_scalarsmults(ge4x * a, ge4x * b, const sc25519 * s);
void ge4x_scalarsmults_table(ge4x * a, ge4x (*table)[8], const sc25519 * s, int dist);

void ge4x_hash(unsigned char *, unsigned char *, unsigned char *, ge4x *);

int ge4x_unpack_vartime(ge4x * r, unsigned char p[128]);
void ge4x_pack(unsigned char r[128], const ge4x *p);

#endif //ifndef GE4X_H

