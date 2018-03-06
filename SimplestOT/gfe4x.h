#ifndef GFE4X_H
#define GFE4X_H

typedef struct{
  double v[4];
} __attribute__ ((aligned (32))) limb;

typedef struct{
  limb v[12];
} gfe4x;

void gfe4x_pack(unsigned char r[128], const gfe4x *x);

void gfe4x_unpack(gfe4x *, const unsigned char *);
void gfe4x_unpack_single(gfe4x *, const unsigned char *, int);

void gfe4x_neg(gfe4x *r, const gfe4x *x);
void gfe4x_neg_single(gfe4x *r, const gfe4x *x, int pos);

void gfe4x_add(gfe4x *r, const gfe4x *x, const gfe4x *y);
void gfe4x_sub(gfe4x *r, const gfe4x *x, const gfe4x *y);

void gfe4x_setzero(gfe4x *r);
void gfe4x_setone(gfe4x *r);
void gfe4x_settwo(gfe4x *r);

void gfe4x_cmov(gfe4x *r, const gfe4x *x, unsigned char * b);
void gfe4x_cmov_vartime(gfe4x *r, const gfe4x *x, unsigned char * b);

void gfe4x_mul(gfe4x *r, const gfe4x *x, const gfe4x *y);
void gfe4x_square(gfe4x *r, const gfe4x *x);
void gfe4x_nsquare(gfe4x *r, const int n);

void gfe4x_invert(gfe4x *r, const gfe4x *x);

void gfe4x_pow2523(gfe4x *r, const gfe4x *x);

void gfe4x_iseq_vartime(unsigned char *r, const gfe4x *x, const gfe4x *y);

void gfe4x_getparity(unsigned char * res, const gfe4x * a);

void gfe4x_print(const gfe4x *x, int pos);

#endif

