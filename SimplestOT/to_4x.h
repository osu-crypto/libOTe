static void fe_to_4x(gfe4x * a, fe25519 * b)
{
	int i;
	unsigned char buf[32];

	fe25519_pack(buf, b);

	gfe4x_unpack_single(a, buf, 0);

	for (i = 0; i < 12; i++)
	{
		a->v[i].v[1] = a->v[i].v[0];
		a->v[i].v[2] = a->v[i].v[0];
		a->v[i].v[3] = a->v[i].v[0];
	}
}

static void ge_to_4x(ge4x * a, ge25519 * b)
{
	fe_to_4x(&a->x, &b->x);
	fe_to_4x(&a->y, &b->y);
	fe_to_4x(&a->z, &b->z);
	fe_to_4x(&a->t, &b->t);
}

