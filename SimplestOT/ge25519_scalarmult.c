#include <stdio.h>

#include "ge25519.h"

static void ge25519_idoubles(ge25519 * a, int n)
{
	int i;
	ge25519_p1p1 tp1p1;

	//

	for (i = 0; i < n-1; i++)
	{
		ge25519_dbl_p1p1(&tp1p1, (ge25519_p2 *)a);
		ge25519_p1p1_to_p2((ge25519_p2 *)a, &tp1p1);
	}

	ge25519_dbl_p1p1(&tp1p1, (ge25519_p2 *)a);
	ge25519_p1p1_to_p3(a, &tp1p1);
}

static void ge25519_maketable(ge25519 (*table)[8], const ge25519 * b, int dist)
{
	const int n = 64/dist;

	int i; 
	ge25519 p = *b;

	//

	for (i = 0; i < n; i++)
	{
		table[i][1-1] = p;
		ge25519_double(&table[i][2-1], &p);
		ge25519_add(&table[i][3-1], &table[i][2-1], &p);
		ge25519_double(&table[i][4-1], &table[i][2-1]);
		ge25519_add(&table[i][5-1], &table[i][4-1], &p);
		ge25519_double(&table[i][6-1], &table[i][3-1]);
		ge25519_add(&table[i][7-1], &table[i][6-1], &p);
		ge25519_double(&table[i][8-1], &table[i][4-1]);

		if (i < n-1)
		{
			ge25519_double(&p, &table[i][8-1]);
			ge25519_idoubles(&p, 4*(dist-1));
		}
	}
}

extern void ge25519_lookup_asm(ge25519 *, const ge25519 *, const char *);

static void ge25519_scalarmult_table(ge25519 *r, ge25519 (*table)[8], const sc25519 *s, int dist)
{
	int i, j;
	ge25519 t;
	ge25519_p1p1 t_p1p1;
	char w[64];

	//

	sc25519_window4(w, s);

	//

	for (i = dist-1; i < 64; i += dist)
	{
		if (i == dist-1)
			ge25519_lookup_asm(r, table[i/dist], &w[i]);

		else
	  	{
			ge25519_lookup_asm(&t, table[i/dist], &w[i]);
			ge25519_add_p1p1(&t_p1p1, r, &t);
  		
			if (i + dist < 64) 
				ge25519_p1p1_to_p3(r, &t_p1p1);
			else
				ge25519_p1p1_to_p2((ge25519_p2 *)r, &t_p1p1);
		}

	}

	//

	for (i = dist-2; i >= 0; i--)
	{
		ge25519_idoubles(r, 4);

		for (j = i; j < 64; j += dist)
		{
			ge25519_lookup_asm(&t, table[j/dist], &w[j]);
			ge25519_add_p1p1(&t_p1p1, r, &t);
				
			if (j + dist < 64 || i == 0) 
				ge25519_p1p1_to_p3(r, &t_p1p1);
			else
				ge25519_p1p1_to_p2((ge25519_p2 *)r, &t_p1p1);
		}
	}
}

void ge25519_scalarmult(ge25519 * a, ge25519 * b, const sc25519 * s)
{
	ge25519 table[1][8];

	//

	ge25519_maketable(table, b, 64);
	ge25519_scalarmult_table(a, table, s, 64);
}

