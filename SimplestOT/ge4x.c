#include "ge4x.h"

#include "crypto_hash.h"

void ge4x_cmovs(ge4x *r, const ge4x *x, unsigned char * b)
{
	gfe4x_cmov(&r->x, &(x->x), b);
	gfe4x_cmov(&r->y, &(x->y), b);
	gfe4x_cmov(&r->z, &(x->z), b);
	gfe4x_cmov(&r->t, &(x->t), b);
}

void ge4x_setneutral(ge4x * a)
{
	gfe4x_setzero(&a->x);
	gfe4x_setone(&a->y);
	gfe4x_setone(&a->z);
	gfe4x_setzero(&a->t);
}

void ge4x_neg(ge4x * a, const ge4x * b)
{
	gfe4x_neg(&a->x, &b->x);
	a->y = b->y;
	a->z = b->z;
	gfe4x_neg(&a->t, &b->t);
}

///////////////////////////////////////////////////////////

#define repeat4x(x) {x, x, x, x}

const gfe4x Gk = 
{{
	{ repeat4x(3338585.0) } ,
	{ repeat4x(3934835965952.0) } ,
	{ repeat4x(16993937369696567296.0) } ,
	{ repeat4x(4464222746302153748381696.0) } ,
	{ repeat4x(93371163235585075216663357423616.0) } ,
	{ repeat4x(1163399014865459815517614333765877760.0) } ,
	{ repeat4x(441936960085431936284569284157504919873519616.0) } ,
	{ repeat4x(355047131404459050871642921761149483359549389799424.0) } ,
	{ repeat4x(626647004757192365988092839070681114614100044180388577280.0) } ,
	{ repeat4x(13159058716893486699394031679446200360393917757201178927420145664.0) } ,
	{ repeat4x(12842070454865951878207543570322902610654944894655310136406629955928064.0) } ,
	{ repeat4x(16295354408597167049195255459117446390458785936524946835293367493552880222208.0) } 
}};

extern void ge4x_niels_add_p1p1_asm(ge4x_p1p1 *, const ge4x *, const ge4x_niels *);

extern void ge4x_add_p1p1_asm(ge4x_p1p1 *, const ge4x *, const ge4x *);

void ge4x_p1p1_to_p2(ge4x_p2 * a, const ge4x_p1p1 * b)
{
	gfe4x_mul(&a->x, &b->x, &b->t);
	gfe4x_mul(&a->y, &b->y, &b->z);
	gfe4x_mul(&a->z, &b->z, &b->t);
}

void ge4x_p1p1_to_p3(ge4x * a, const ge4x_p1p1 * b)
{
	gfe4x_mul(&a->x, &b->x, &b->t);
	gfe4x_mul(&a->y, &b->y, &b->z);
	gfe4x_mul(&a->z, &b->z, &b->t);
	gfe4x_mul(&a->t, &b->x, &b->y);
}

void ge4x_add_niels(ge4x * c, const ge4x * a, const ge4x_niels * b)
{
	ge4x_p1p1 tmp;
	ge4x_niels_add_p1p1_asm(&tmp, a, b);
	ge4x_p1p1_to_p3(c, &tmp);
}

void ge4x_add(ge4x * c, const ge4x * a, const ge4x * b)
{
	ge4x_p1p1 tmp;
	ge4x_add_p1p1_asm(&tmp, a, b);
	ge4x_p1p1_to_p3(c, &tmp);
}

void ge4x_sub(ge4x * c, const ge4x * a, const ge4x * b)
{
	ge4x t;

	ge4x_neg(&t, b);
	ge4x_add(c, a, &t);
}

extern void ge4x_double_p1p1_asm(ge4x_p1p1 *, const ge4x_p2 *);

void ge4x_double(ge4x * a, const ge4x * b)
{
	ge4x_p1p1 tmp;
	ge4x_double_p1p1_asm(&tmp, (ge4x_p2 *)b);
	ge4x_p1p1_to_p3(a, &tmp);
}

void ge4x_doubles(ge4x * a, ge4x * b, int n)
{
	int i;
	ge4x_p1p1 tp1p1;

	if (n == 1)
	{
		ge4x_double_p1p1_asm(&tp1p1, (ge4x_p2 *)b);
		ge4x_p1p1_to_p3(a, &tp1p1);
	}

	if (n > 1)
	{
		ge4x_double_p1p1_asm(&tp1p1, (ge4x_p2 *)b);
		ge4x_p1p1_to_p2((ge4x_p2 *)a, &tp1p1);

		for (i = 0; i < n-2; i++)
		{
			ge4x_double_p1p1_asm(&tp1p1, (ge4x_p2 *)a);
			ge4x_p1p1_to_p2((ge4x_p2 *)a, &tp1p1);
		}
		
		ge4x_double_p1p1_asm(&tp1p1, (ge4x_p2 *)a);
		ge4x_p1p1_to_p3(a, &tp1p1);
	}
}

void ge4x_idoubles(ge4x * a, int n)
{
	ge4x_doubles(a, a, n);
}

///////////////////////////////////////////////////////////

void ge4x_scalarmults_base(ge4x * a, const sc25519 * s)
{
	int i;
	sc25519 ss[4];

	for (i = 0; i < 4; i++)
		ss[i] = *s;

	ge4x_scalarsmults_base(a, ss);
}

void ge4x_scalarmults(ge4x * a, ge4x * b, const sc25519 * s)
{
	int i;
	sc25519 ss[4];

	for (i = 0; i < 4; i++)
		ss[i] = *s;

	ge4x_scalarsmults(a, b, ss);
}

void ge4x_maketable(ge4x (*table)[8], const ge4x * b, int dist)
{
	const int n = 64/dist;

	int i; 
	ge4x p = *b;

	for (i = 0; i < n; i++)
	{
		table[i][1-1] = p;
		ge4x_double(&table[i][2-1], &p);
		ge4x_add(&table[i][3-1], &table[i][2-1], &p);
		ge4x_double(&table[i][4-1], &table[i][2-1]);
		ge4x_add(&table[i][5-1], &table[i][4-1], &p);
		ge4x_double(&table[i][6-1], &table[i][3-1]);
		ge4x_add(&table[i][7-1], &table[i][6-1], &p);
		ge4x_double(&table[i][8-1], &table[i][4-1]);

		if (i < n-1)
		{
			ge4x_double(&p, &table[i][8-1]);
			ge4x_idoubles(&p, 4*(dist-1));
		}
	}
}

extern void ge4x_lookup_niels_asm(ge4x_niels *, const double (*)[3][12], const char *);

extern void ge4x_lookup_asm(ge4x *, const ge4x *, const char *);

static void convert(ge4x * dest, ge4x_niels * src)
{
	gfe4x_sub(&dest->x, &src->y, &src->x);
	gfe4x_add(&dest->y, &src->y, &src->x);
	gfe4x_settwo(&dest->z);
	dest->t = src->z;
}


static const double ge4x_base_multiples_niels[32][8][3][12] = 
{
#include "ge4x.data"
};

void ge4x_scalarsmults_base(ge4x * a, const sc25519 * s)
{
	const int dist=2;
	int i, j, pos;
	char idx[4], w[4][64];

	ge4x_niels tmp[ dist ]; 
	ge4x t[ dist ];
	ge4x_p1p1 t_p1p1;

	//

	for (pos = 0; pos < 4; pos++)
		sc25519_window4(w[pos], &s[pos]);

	//

	for (i = 0; i < dist; i++)
	{
		for (pos = 0; pos < 4; pos++) 
			idx[pos] = w[pos][i];

		ge4x_lookup_niels_asm(&tmp[i], ge4x_base_multiples_niels[0], idx);

		if (i == dist-1) convert(    a, &tmp[i]);
		else             convert(&t[i], &tmp[i]);
	}

	for (j = dist; j < 64; j += dist)
	{
		for (i = 0; i < dist; i++)
		{
			for (pos = 0; pos < 4; pos++) 
				idx[pos] = w[pos][i+j];
		
			ge4x_lookup_niels_asm(&tmp[i], ge4x_base_multiples_niels[j/dist], idx);
		}

		for (i = 0; i < dist-1; i++)
			ge4x_add_niels(&t[i], &t[i], &tmp[i]);

		if (j+dist < 64)
		{
			ge4x_add_niels(a, a, &tmp[ dist-1 ]);
		}
		else
		{
			ge4x_niels_add_p1p1_asm(&t_p1p1, a, &tmp[ dist-1 ]);
			ge4x_p1p1_to_p2((ge4x_p2 *)a, &t_p1p1);
		}
	}

	//

	ge4x_idoubles(a, 4);

	for (i = dist-2; i >= 1; i--)
	{
		ge4x_add_p1p1_asm(&t_p1p1, a, &t[i]);
		ge4x_p1p1_to_p2((ge4x_p2 *)a, &t_p1p1);
		ge4x_idoubles(a, 4);
	}

	ge4x_add(a, a, &t[0]);
}

void ge4x_scalarsmults(ge4x * a, ge4x * b, const sc25519 * s)
{
	ge4x table[1][8];

	//

	ge4x_maketable(table, b, 64);
	ge4x_scalarsmults_table(a, table, s, 64);
}

void ge4x_scalarsmults_table(ge4x * a, ge4x (*table)[8], const sc25519 * s, int dist)
{
	int i, j, pos;
	ge4x t;
	ge4x_p1p1 t_p1p1;
	char idx[4], w[4][64];

	//

	for (pos = 0; pos < 4; pos++)
		sc25519_window4(w[pos], &s[pos]);

	//

	for (i = dist-1; i < 64; i += dist)
	{
		for (pos = 0; pos < 4; pos++) 
			idx[pos] = w[pos][i];

		if (i == dist-1)
			ge4x_lookup_asm(a, table[i/dist], idx);

		else
		{
			ge4x_lookup_asm(&t, table[i/dist], idx);
			ge4x_add_p1p1_asm(&t_p1p1, a, &t);
			
			if (i + dist < 64) 
				ge4x_p1p1_to_p3(a, &t_p1p1);
			else
				ge4x_p1p1_to_p2((ge4x_p2 *)a, &t_p1p1);
		}
	}

	//

	for (i = dist-2; i >= 0; i--)
	{
		ge4x_idoubles(a, 4);

		///

		for (j = i; j < 64; j += dist)
		{
			for (pos = 0; pos < 4; pos++) 
				idx[pos] = w[pos][j];
	
			ge4x_lookup_asm(&t, table[j/dist], idx);
			ge4x_add_p1p1_asm(&t_p1p1, a, &t);
				
			if (j + dist < 64 || i == 0) 
				ge4x_p1p1_to_p3(a, &t_p1p1);
			else
				ge4x_p1p1_to_p2((ge4x_p2 *)a, &t_p1p1);
		}
	}
}

void ge4x_hash(unsigned char * k,
               unsigned char * sp,
               unsigned char * q,
               ge4x * p)
{
	int i, j;

	unsigned char r[128];
	unsigned char in[96];

	//

	ge4x_pack(r, p);

	for (j = 0; j < 32; j++) in[j] = sp[j];

	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 32; j++) in[j + 32] = q[i*32 + j];
		for (j = 0; j < 32; j++) in[j + 64] = r[i*32 + j];

		crypto_hash(k + i*32, in, sizeof(in));
	}
}

