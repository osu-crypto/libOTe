#include "ge4x.h"

#define repeat4x(x) {x, x, x, x}

static const gfe4x ecd = 
{{
	{ repeat4x(1669283.0) } ,
	{ repeat4x(6365464494080.0) } ,
	{ repeat4x(8496964286801772544.0) } ,
	{ repeat4x(2232111373151076874190848.0) } ,
	{ repeat4x(46685581617792537608331678711808.0) } ,
	{ repeat4x(581699507432729907758807166882938880.0) } ,
	{ repeat4x(577780403219205938406856134441126244032446464.0) } ,
	{ repeat4x(177523208890306348945851196309082379305990599213056.0) } ,
	{ repeat4x(3451874370071936564911941131139173765358227744322211545088.0) },
	{ repeat4x(6579526219895875656356633921828388576363750827422867231692816384.0) },
	{ repeat4x(6421035227432975939103771785161451305327472447327655068203314977964032.0) },
	{ repeat4x(37095699513627632380490373981730700158546889134672614427511079748754722521088.0) }
}};

static const gfe4x sqrtm1 =
{{
	{ repeat4x(958640.0) } ,
	{ repeat4x(3467280121856.0) } ,
	{ repeat4x(14190305864170078208.0) } ,
	{ repeat4x(19212800461602561875509248.0) } ,
	{ repeat4x(528948567410906390584241422336.0) } ,
	{ repeat4x(62822086469243367117680649821264805888.0) } ,
	{ repeat4x(620906088990931074573886915313991388311322624.0) } ,
	{ repeat4x(223962994315572871555725705183030052053612408864768.0) } ,
	{ repeat4x(1061732066906148624681392299747573581275857698087826882560.0) },
	{ repeat4x(769792371319145595473002035915072170938712359931846872489000960.0) },
	{ repeat4x(3459271828655849329356536893846285443202986369943387069203793412358144.0) },
	{ repeat4x(19681157917434907507524698511986411320718631367220517708432557327070548459520.0) }
}}; 

int ge4x_unpack_vartime(ge4x * r, unsigned char p[128])
{
  int i;

  gfe4x t, chk, num, den, den2, den4, den6;
  unsigned char par[4];
  unsigned char eq[4];

  par[0] = p[31] >> 7;
  par[1] = p[63] >> 7;
  par[2] = p[95] >> 7;
  par[3] = p[127] >> 7;

  gfe4x_setone(&r->z); // ???
  gfe4x_unpack(&r->y, p); // ???
  gfe4x_square(&num, &r->y); /* x = y^2 */
  gfe4x_mul(&den, &num, &ecd); /* den = dy^2 */
  gfe4x_sub(&num, &num, &r->z); /* x = y^2-1 */
  gfe4x_add(&den, &r->z, &den); /* den = dy^2+1 */

  /* Computation of sqrt(num/den)
     1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8)
  */
  gfe4x_square(&den2, &den);
  gfe4x_square(&den4, &den2);
  gfe4x_mul(&den6, &den4, &den2);
  gfe4x_mul(&t, &den6, &num);
  gfe4x_mul(&t, &t, &den);

  gfe4x_pow2523(&t, &t);
  /* 2. computation of r->x = t * num * den^3
  */
  gfe4x_mul(&t, &t, &num);
  gfe4x_mul(&t, &t, &den);
  gfe4x_mul(&t, &t, &den);
  gfe4x_mul(&r->x, &t, &den);

  /* 3. Check whether sqrt computation gave correct result, multiply by sqrt(-1) if not:
  */
  gfe4x_square(&chk, &r->x);
  gfe4x_mul(&chk, &chk, &den);

//  if (!gfe4x_iseq_vartime(&chk, &num))
//    gfe4x_mul(&r->x, &r->x, &sqrtm1);

  gfe4x_setone(&t);
  gfe4x_iseq_vartime(eq, &chk, &num);
  gfe4x_cmov_vartime(&t, &sqrtm1, eq);
  gfe4x_mul(&r->x, &r->x, &t);

  /* 4. Now we have one of the two square roots, except if input was not a square
  */
  gfe4x_square(&chk, &r->x);
  gfe4x_mul(&chk, &chk, &den);
  gfe4x_iseq_vartime(eq, &chk, &num);

  if (eq[0] || eq[1] || eq[2] || eq[3]) return -1;

  /* 5. Choose the desired square root according to parity:
  */

  gfe4x_getparity(eq, &r->x);

  for (i = 0; i < 4; i++)
  {
    if (eq[i] != par[i])
      gfe4x_neg_single(&r->x, &r->x, i);
  }

  gfe4x_mul(&r->t, &r->x, &r->y);

  return 0;
}

