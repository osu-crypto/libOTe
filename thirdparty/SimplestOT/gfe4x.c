#include <stdio.h>
#include "gfe4x.h"

/*
extern void limb_add(limb *r, const limb *x, const limb *y);
static void limb_add(limb *r, const limb *x, const limb *y)
{
  r->v[0] = x->v[0] + y->v[0];
  r->v[1] = x->v[1] + y->v[1];
  r->v[2] = x->v[2] + y->v[2];
  r->v[3] = x->v[3] + y->v[3];
}

static void limb_sub(limb *r, const limb *x, const limb *y)
{
  r->v[0] = x->v[0] - y->v[0];
  r->v[1] = x->v[1] - y->v[1];
  r->v[2] = x->v[2] - y->v[2];
  r->v[3] = x->v[3] - y->v[3];
}

extern void limb_mul(limb *r, const limb *x, const limb *y);
static void limb_mul(limb *r, const limb *x, const limb *y)
{
  r->v[0] = x->v[0] * y->v[0];
  r->v[1] = x->v[1] * y->v[1];
  r->v[2] = x->v[2] * y->v[2];
  r->v[3] = x->v[3] * y->v[3];
}

extern void limb_muladd(limb *r, const limb *x, const limb *y);

void limb_muladd(limb *r, const limb *x, const limb *y)
{
  r->v[0] += x->v[0] * y->v[0];
  r->v[1] += x->v[1] * y->v[1];
  r->v[2] += x->v[2] * y->v[2];
  r->v[3] += x->v[3] * y->v[3];
}
*/

unsigned long long llutod = 0x3ff0000000000000ULL;


static const double _2_22  = 4194304.;
static const double _2_23  = 8388608.;
static const double _2_43  = 8796093022208.;
static const double _2_44  = 17592186044416.;
static const double _2_64  = 18446744073709551616.;
static const double _2_65  = 36893488147419103232.;
static const double _2_85  = 38685626227668133590597632.;
static const double _2_86  = 77371252455336267181195264.;
static const double _2_107 = 162259276829213363391578010288128.;
static const double _2_108 = 324518553658426726783156020576256.;
static const double _2_128 = 340282366920938463463374607431768211456.;
static const double _2_129 = 680564733841876926926749214863536422912.;
static const double _2_149 = 713623846352979940529142984724747568191373312.;
static const double _2_150 = 1427247692705959881058285969449495136382746624.;
static const double _2_170 = 1496577676626844588240573268701473812127674924007424.;
static const double _2_171 = 2993155353253689176481146537402947624255349848014848.;
static const double _2_192 = 6277101735386680763835789423207666416102355444464034512896.;
static const double _2_193 = 12554203470773361527671578846415332832204710888928069025792.;
static const double _2_213 = 13164036458569648337239753460458804039861886925068638906788872192.;
static const double _2_214 = 26328072917139296674479506920917608079723773850137277813577744384.;
static const double _2_234 = 27606985387162255149739023449108101809804435888681546220650096895197184.;
static const double _2_235 = 55213970774324510299478046898216203619608871777363092441300193790394368.;
static const double _2_255 = 57896044618658097711785492504343953926634992332820282019728792003956564819968.;

static const double _2_22inv   = .0000002384185791015625;
static const double _2_43inv   = .0000000000001136868377216160297393798828125;
static const double _2_64inv   = .0000000000000000000542101086242752217003726400434970855712890625;
static const double _2_85inv   = .0000000000000000000000000258493941422821148397315216271863391739316284656524658203125;
static const double _2_107inv  = .00000000000000000000000000000000616297582203915472977912941627176741932192527428924222476780414581298828125;
static const double _2_128inv  = .00000000000000000000000000000000000000293873587705571876992184134305561419454666389193021880377187926569604314863681793212890625;
static const double _2_149inv  = .00000000000000000000000000000000000000000000140129846432481707092372958328991613128026194187651577175706828388979108268586060148663818836212158203125;
static const double _2_170inv  = .00000000000000000000000000000000000000000000000000066819117752304891153513411678787046970379922002626217449048437304009966024678258966762456338983611203730106353759765625;
static const double _2_192inv  = .000000000000000000000000000000000000000000000000000000000159309191113245227702888039776771180559110455519261878607388585338616290151305816094308987472018268594098344692611135542392730712890625;
static const double _2_213inv  = .000000000000000000000000000000000000000000000000000000000000000075964541966078389979785938156495657233767726668959559730238239926632065845158489272264951454171308800744221063905303736873975140042603015899658203125;
static const double _2_234inv  = .000000000000000000000000000000000000000000000000000000000000000000000036222716315306849470036477163551167122730124792556552758330459559742005274371380458958125807843832397815809757187511318623530931493093021344975568354129791259765625;

void gfe4x_unpack_single(gfe4x *r, const unsigned char * x, int i)
{
    x += i*32;

    r->v[0].v[i]  = x[0];
    r->v[0].v[i] += x[1] << 8;
    r->v[0].v[i] += (x[2] & 0x3f) << 16; /* 22 bits */
    r->v[0].v[i] = r->v[0].v[i] - _2_22 + 19;
    r->v[1].v[i]  = x[2] >> 6;
    r->v[1].v[i] += x[3] << 2;
    r->v[1].v[i] += x[4] << 10;
    r->v[1].v[i] += (x[5] & 0x07) << 18; /* 21 bits */
    r->v[1].v[i] *= _2_22;
    r->v[1].v[i] = r->v[1].v[i] + _2_22 - _2_43;
    r->v[2].v[i]  = x[5] >> 3;
    r->v[2].v[i] += x[6] << 5;
    r->v[2].v[i] += x[7] << 13; /* 21 bits */
    r->v[2].v[i] *= _2_43;
    r->v[2].v[i] = r->v[2].v[i] + _2_43 - _2_64;
    r->v[3].v[i]  = x[8];
    r->v[3].v[i] += x[9] << 8;
    r->v[3].v[i] += (x[10] & 0x1f) << 16; /* 21 bits */
    r->v[3].v[i] *= _2_64;
    r->v[3].v[i] = r->v[3].v[i] + _2_64 - _2_85;
    r->v[4].v[i]  = x[10] >> 5;
    r->v[4].v[i] += x[11] << 3;
    r->v[4].v[i] += x[12] << 11;
    r->v[4].v[i] += (x[13] & 0x07) << 19; /* 22 bits */
    r->v[4].v[i] *= _2_85;
    r->v[4].v[i] = r->v[4].v[i] + _2_85 - _2_107;
    r->v[5].v[i]  = x[13] >> 3;
    r->v[5].v[i] += x[14] << 5;
    r->v[5].v[i] += x[15] << 13; /* 21 bits */
    r->v[5].v[i] *= _2_107;
    r->v[5].v[i] = r->v[5].v[i] + _2_107 - _2_128;
    r->v[6].v[i]  = x[16];
    r->v[6].v[i] += x[17] << 8;
    r->v[6].v[i] += (x[18] & 0x1f) << 16; /* 21 bits */
    r->v[6].v[i] *= _2_128;
    r->v[6].v[i] = r->v[6].v[i] + _2_128 - _2_149;
    r->v[7].v[i]  = x[18] >> 5;
    r->v[7].v[i] += x[19] << 3;
    r->v[7].v[i] += x[20] << 11;
    r->v[7].v[i] += (x[21] & 0x03) << 19; /* 21 bits */
    r->v[7].v[i] *= _2_149;
    r->v[7].v[i] = r->v[7].v[i] + _2_149 - _2_170;
    r->v[8].v[i]  = x[21] >> 2;
    r->v[8].v[i] += x[22] << 6;
    r->v[8].v[i] += x[23] << 14; /* 22 bits */
    r->v[8].v[i] *= _2_170;
    r->v[8].v[i] = r->v[8].v[i] + _2_170 - _2_192;
    r->v[9].v[i]  = x[24];
    r->v[9].v[i] += x[25] << 8;
    r->v[9].v[i] += (x[26] & 0x1f) << 16; /* 21 bits */
    r->v[9].v[i] *= _2_192;
    r->v[9].v[i] = r->v[9].v[i] + _2_192 - _2_213;
    r->v[10].v[i]  = x[26] >> 5;
    r->v[10].v[i] += x[27] << 3;
    r->v[10].v[i] += x[28] << 11;
    r->v[10].v[i] += (x[29] & 0x03) << 19; /* 21 bits */
    r->v[10].v[i] *= _2_213;
    r->v[10].v[i] = r->v[10].v[i] + _2_213 - _2_234;
    r->v[11].v[i]  = x[29] >> 2;
    r->v[11].v[i] += x[30] << 6;
    r->v[11].v[i] += (x[31] & 0x7f) << 14; /* 21 bits */
    r->v[11].v[i] *= _2_234;
    r->v[11].v[i] = r->v[11].v[i] + _2_234 - _2_255;
}

void gfe4x_unpack(gfe4x *r, const unsigned char x[128])
{
	gfe4x_unpack_single(r, x, 0);
	gfe4x_unpack_single(r, x, 1);
	gfe4x_unpack_single(r, x, 2);
	gfe4x_unpack_single(r, x, 3);
}

void gfe4x_pack(unsigned char r[128], const gfe4x *x)
{
  double u[12];
  int i,j;
  unsigned long long t;
  unsigned char minusr[32];
  for(i=0;i<4;i++)
  {
    u[0]  = x->v[0].v[i]  + _2_23 - 19.;
    u[1]  = x->v[1].v[i]  + _2_44  - _2_23;
    u[1] *= _2_22inv;
    u[2]  = x->v[2].v[i]  + _2_65  - _2_44;
    u[2] *= _2_43inv;
    u[3]  = x->v[3].v[i]  + _2_86  - _2_65;
    u[3] *= _2_64inv;
    u[4]  = x->v[4].v[i]  + _2_108 - _2_86;
    u[4] *= _2_85inv;
    u[5]  = x->v[5].v[i]  + _2_129 - _2_108;
    u[5] *= _2_107inv;
    u[6]  = x->v[6].v[i]  + _2_150 - _2_129;
    u[6] *= _2_128inv;
    u[7]  = x->v[7].v[i]  + _2_171 - _2_150;
    u[7] *= _2_149inv;
    u[8]  = x->v[8].v[i]  + _2_193 - _2_171;
    u[8] *= _2_170inv;
    u[9]  = x->v[9].v[i]  + _2_214 - _2_193;
    u[9] *= _2_192inv;
    u[10] = x->v[10].v[i] + _2_235 - _2_214;
    u[10] *= _2_213inv;
    u[11] = x->v[11].v[i] + _2_255 - _2_235;
    u[11] *= _2_234inv;

    t = u[0];
    r[0]  = t & 0xff;
    r[1]  = (t >>  8) & 0xff;
    t = ((unsigned long long)u[1] << 6) + (t >> 16);
    r[2]  = t & 0xff;
    r[3]  = (t >>  8) & 0xff;
    r[4]  = (t >> 16) & 0xff;
    t = ((unsigned long long)u[2] << 3) + (t >> 24);
    r[5]  = t & 0xff;
    r[6]  = (t >>  8) & 0xff;
    r[7]  = (t >> 16) & 0xff;
    t = (unsigned long long)u[3]  + (t >> 24);
    r[8]  = t & 0xff;
    r[9]  = (t >> 8) & 0xff;
    t = ((unsigned long long)u[4] << 5) + (t >> 16);
    r[10]  = t & 0xff;
    r[11]  = (t >> 8) & 0xff;
    r[12]  = (t >> 16) & 0xff;
    t = ((unsigned long long)u[5] << 3) + (t >> 24);
    r[13]  = t & 0xff;
    r[14]  = (t >> 8) & 0xff;
    r[15]  = (t >> 16) & 0xff;
    t = (unsigned long long)u[6]  + (t >> 24);
    r[16]  = t & 0xff;
    r[17]  = (t >> 8) & 0xff;
    t = ((unsigned long long)u[7] << 5) + (t >> 16);
    r[18]  = t & 0xff;
    r[19]  = (t >> 8) & 0xff;
    r[20]  = (t >> 16) & 0xff;
    t = ((unsigned long long)u[8] << 2) + (t >> 24);
    r[21]  = t & 0xff;
    r[22]  = (t >> 8) & 0xff;
    r[23]  = (t >> 16) & 0xff;
    t = (unsigned long long)u[9]  + (t >> 24);
    r[24]  = t & 0xff;
    r[25]  = (t >> 8) & 0xff;
    t = ((unsigned long long)u[10] << 5) + (t >> 16);
    r[26]  = t & 0xff;
    r[27]  = (t >> 8) & 0xff;
    r[28]  = (t >> 16) & 0xff;
    t = ((unsigned long long)u[11] << 2) + (t >> 24);
    r[29]  = t & 0xff;
    r[30]  = (t >> 8) & 0xff;
    r[31]  = (t >> 16) & 0xff;

    //freeze by adding 19:
    t = (unsigned long long)r[0] + 19;
    for(j=0;j<31;j++)
    {
      minusr[j] = t & 0xff;
      t = (unsigned long long)r[j+1] + (t >> 8);
    }
    minusr[31] = t & 0x7f;
    t >>= 7;
    for(j=0;j<32;j++)
      r[j] = t * minusr[j] + (1-t) * r[j];
    
    r += 32;
  }
}

void gfe4x_neg_single(gfe4x *r, const gfe4x *x, int pos)
{
	int i;

	for (i = 0; i < 12; i++)
		r->v[i].v[pos] = -(x->v[i].v[pos]);
}

void gfe4x_neg(gfe4x *r, const gfe4x *x)
{
	gfe4x_neg_single(r, x, 0);
	gfe4x_neg_single(r, x, 1);
	gfe4x_neg_single(r, x, 2);
	gfe4x_neg_single(r, x, 3);
}

/*
void gfe4x_add(gfe4x *r, const gfe4x *x, const gfe4x *y)
{
  int i;
  for(i=0;i<12;i++)
    limb_add(r->v+i, x->v+i, y->v+i);
}

void gfe4x_sub(gfe4x *r, const gfe4x *x, const gfe4x *y)
{
  int i;
  for(i=0;i<12;i++)
    limb_sub(r->v+i, x->v+i, y->v+i);
}
*/

void gfe4x_setzero(gfe4x *r)
{
  int i;
  for(i=0;i<12;i++)
  {
    r->v[i].v[0] = 0.;
    r->v[i].v[1] = 0.;
    r->v[i].v[2] = 0.;
    r->v[i].v[3] = 0.;
  }
}

void gfe4x_setone(gfe4x *r)
{
  int i;
  r->v[0].v[0] = 1.;
  r->v[0].v[1] = 1.;
  r->v[0].v[2] = 1.;
  r->v[0].v[3] = 1.;
  for(i=1;i<12;i++)
  {
    r->v[i].v[0] = 0.;
    r->v[i].v[1] = 0.;
    r->v[i].v[2] = 0.;
    r->v[i].v[3] = 0.;
  }
}

void gfe4x_settwo(gfe4x *r)
{
  int i;
  r->v[0].v[0] = 2.;
  r->v[0].v[1] = 2.;
  r->v[0].v[2] = 2.;
  r->v[0].v[3] = 2.;
  for(i=1;i<12;i++)
  {
    r->v[i].v[0] = 0.;
    r->v[i].v[1] = 0.;
    r->v[i].v[2] = 0.;
    r->v[i].v[3] = 0.;
  }
}

/* b[i] is either 0 or 1 */
static void gfe4x_cmov_single(gfe4x *r, const gfe4x *x, unsigned char b, int pos)
{
  int i;

  for (i = 0; i < 12; i++)
    r->v[i].v[pos] = (double)b * x->v[i].v[pos] + (double)(1-b) * r->v[i].v[pos];
}

void gfe4x_cmov(gfe4x * r, const gfe4x * x, unsigned char * b)
{
	gfe4x_cmov_single(r, x, b[0], 0);
	gfe4x_cmov_single(r, x, b[1], 1);
	gfe4x_cmov_single(r, x, b[2], 2);
	gfe4x_cmov_single(r, x, b[3], 3);
}

void gfe4x_cmov_vartime(gfe4x * r, const gfe4x * x, unsigned char * b)
{
	int pos, j;

	for (pos = 0; pos < 4; pos++)
	{
		if (b[pos])
		{
			for (j = 0; j < 12; j++)
				r->v[j].v[pos] = x->v[j].v[pos];
		}
	}
}

//static const unsigned long long d25519 = 0x3043000000000000; /* 19* 2^-255 */

const limb scale19 = {{
  0.000000000000000000000000000000000000000000000000000000000000000000000000000328174405093588895764681370786415183702408013848578692630900731866406488520172228202917285131946952609300797169953687216685813759979613974358814143528206841438077390193939208984375,
  0.000000000000000000000000000000000000000000000000000000000000000000000000000328174405093588895764681370786415183702408013848578692630900731866406488520172228202917285131946952609300797169953687216685813759979613974358814143528206841438077390193939208984375,
  0.000000000000000000000000000000000000000000000000000000000000000000000000000328174405093588895764681370786415183702408013848578692630900731866406488520172228202917285131946952609300797169953687216685813759979613974358814143528206841438077390193939208984375,
  0.000000000000000000000000000000000000000000000000000000000000000000000000000328174405093588895764681370786415183702408013848578692630900731866406488520172228202917285131946952609300797169953687216685813759979613974358814143528206841438077390193939208984375}};

const limb two4x = {{2., 2., 2., 2.}};
const limb _4x121666 = {{121666., 121666., 121666., 121666.}};

const limb alpha22 = {{
  28334198897217871282176.0, 
  28334198897217871282176.0, 
  28334198897217871282176.0, 
  28334198897217871282176.0}};
const limb alpha43 = {{
  59421121885698253195157962752.0, 
  59421121885698253195157962752.0, 
  59421121885698253195157962752.0, 
  59421121885698253195157962752.0}};
const limb alpha64 = {{
  124615124604835863084731911901282304.0,
  124615124604835863084731911901282304.0,
  124615124604835863084731911901282304.0,
  124615124604835863084731911901282304.0}};
const limb alpha85 = {{
  261336857795280739939871698507597986398208.0,
  261336857795280739939871698507597986398208.0,
  261336857795280739939871698507597986398208.0,
  261336857795280739939871698507597986398208.0}};
const limb alpha107 = {{
  1096126227998177188652763624537212264741949407232.0,
  1096126227998177188652763624537212264741949407232.0,
  1096126227998177188652763624537212264741949407232.0,
  1096126227998177188652763624537212264741949407232.0}};
const limb alpha128 = {{
  2298743311298833287537520540725463775428108683275403264.0,
  2298743311298833287537520540725463775428108683275403264.0,
  2298743311298833287537520540725463775428108683275403264.0,
  2298743311298833287537520540725463775428108683275403264.0}};
const limb alpha149 = {{
  4820814132776970826625886277023487807566608981348378505904128.0,
  4820814132776970826625886277023487807566608981348378505904128.0,
  4820814132776970826625886277023487807566608981348378505904128.0,
  4820814132776970826625886277023487807566608981348378505904128.0}};
const limb alpha170 = {{
  10109980000181489923000130657632361502613929158452714680413853843456.0,
  10109980000181489923000130657632361502613929158452714680413853843456.0,
  10109980000181489923000130657632361502613929158452714680413853843456.0,
  10109980000181489923000130657632361502613929158452714680413853843456.0}};
const limb alpha192 = {{
  42404329554681223909999140017830044379859613525014854994918548831022874624.0,
  42404329554681223909999140017830044379859613525014854994918548831022874624.0,
  42404329554681223909999140017830044379859613525014854994918548831022874624.0,
  42404329554681223909999140017830044379859613525014854994918548831022874624.0}};
const limb alpha213 = {{
  88928324534258838085302516486672313231311348223211953182303424518077283563470848.0,
  88928324534258838085302516486672313231311348223211953182303424518077283563470848.0,
  88928324534258838085302516486672313231311348223211953182303424518077283563470848.0,
  88928324534258838085302516486672313231311348223211953182303424518077283563470848.0}};
const limb alpha234 = {{
  186496213653669990808268343055057815037671056549005394040173991334934811379700015824896.0,
  186496213653669990808268343055057815037671056549005394040173991334934811379700015824896.0,
  186496213653669990808268343055057815037671056549005394040173991334934811379700015824896.0,
  186496213653669990808268343055057815037671056549005394040173991334934811379700015824896.0}};
const limb alpha255 = {{
  391110907456221328563541572174600606921881931583859760122138966276041209554560647587212296192.0,
  391110907456221328563541572174600606921881931583859760122138966276041209554560647587212296192.0,
  391110907456221328563541572174600606921881931583859760122138966276041209554560647587212296192.0,
  391110907456221328563541572174600606921881931583859760122138966276041209554560647587212296192.0}};

/* For carrying see http://cr.yp.to/highspeed/fall2006.html */
/*
void gfe4x_mul(gfe4x *rr, const gfe4x *x, const gfe4x *y)
{
  limb y19[12];
  limb t;

  gfe4x r;

  limb_mul(y19+ 1,y->v+ 1, &scale19);
  limb_mul(y19+ 2,y->v+ 2, &scale19);
  limb_mul(y19+ 3,y->v+ 3, &scale19);
  limb_mul(y19+ 4,y->v+ 4, &scale19);
  limb_mul(y19+ 5,y->v+ 5, &scale19);
  limb_mul(y19+ 6,y->v+ 6, &scale19);
  limb_mul(y19+ 7,y->v+ 7, &scale19);
  limb_mul(y19+ 8,y->v+ 8, &scale19);
  limb_mul(y19+ 9,y->v+ 9, &scale19);
  limb_mul(y19+10,y->v+10, &scale19);
  limb_mul(y19+11,y->v+11, &scale19);

  limb_mul(r.v+ 0, x->v+ 0, y->v+ 0);
  limb_mul(r.v+ 1, x->v+ 0, y->v+ 1);
  limb_mul(r.v+ 2, x->v+ 0, y->v+ 2);
  limb_mul(r.v+ 3, x->v+ 0, y->v+ 3);
  limb_mul(r.v+ 4, x->v+ 0, y->v+ 4);
  limb_mul(r.v+ 5, x->v+ 0, y->v+ 5);
  limb_mul(r.v+ 6, x->v+ 0, y->v+ 6);
  limb_mul(r.v+ 7, x->v+ 0, y->v+ 7);
  limb_mul(r.v+ 8, x->v+ 0, y->v+ 8);
  limb_mul(r.v+ 9, x->v+ 0, y->v+ 9);
  limb_mul(r.v+10, x->v+ 0, y->v+10);
  limb_mul(r.v+11, x->v+ 0, y->v+11);

  limb_muladd(r.v+ 1, x->v+ 1, y->v+ 0);
  limb_muladd(r.v+ 2, x->v+ 1, y->v+ 1);
  limb_muladd(r.v+ 3, x->v+ 1, y->v+ 2);
  limb_muladd(r.v+ 4, x->v+ 1, y->v+ 3);
  limb_muladd(r.v+ 5, x->v+ 1, y->v+ 4);
  limb_muladd(r.v+ 6, x->v+ 1, y->v+ 5);
  limb_muladd(r.v+ 7, x->v+ 1, y->v+ 6);
  limb_muladd(r.v+ 8, x->v+ 1, y->v+ 7);
  limb_muladd(r.v+ 9, x->v+ 1, y->v+ 8);
  limb_muladd(r.v+10, x->v+ 1, y->v+ 9);
  limb_muladd(r.v+11, x->v+ 1, y->v+10);
  limb_muladd(r.v+ 0, x->v+ 1, y19+11);

  limb_muladd(r.v+ 2, x->v+ 2, y->v+ 0);
  limb_muladd(r.v+ 3, x->v+ 2, y->v+ 1);
  limb_muladd(r.v+ 4, x->v+ 2, y->v+ 2);
  limb_muladd(r.v+ 5, x->v+ 2, y->v+ 3);
  limb_muladd(r.v+ 6, x->v+ 2, y->v+ 4);
  limb_muladd(r.v+ 7, x->v+ 2, y->v+ 5);
  limb_muladd(r.v+ 8, x->v+ 2, y->v+ 6);
  limb_muladd(r.v+ 9, x->v+ 2, y->v+ 7);
  limb_muladd(r.v+10, x->v+ 2, y->v+ 8);
  limb_muladd(r.v+11, x->v+ 2, y->v+ 9);
  limb_muladd(r.v+ 0, x->v+ 2, y19+10);
  limb_muladd(r.v+ 1, x->v+ 2, y19+11);

  limb_muladd(r.v+ 3, x->v+ 3, y->v+ 0);
  limb_muladd(r.v+ 4, x->v+ 3, y->v+ 1);
  limb_muladd(r.v+ 5, x->v+ 3, y->v+ 2);
  limb_muladd(r.v+ 6, x->v+ 3, y->v+ 3);
  limb_muladd(r.v+ 7, x->v+ 3, y->v+ 4);
  limb_muladd(r.v+ 8, x->v+ 3, y->v+ 5);
  limb_muladd(r.v+ 9, x->v+ 3, y->v+ 6);
  limb_muladd(r.v+10, x->v+ 3, y->v+ 7);
  limb_muladd(r.v+11, x->v+ 3, y->v+ 8);
  limb_muladd(r.v+ 0, x->v+ 3, y19+ 9);
  limb_muladd(r.v+ 1, x->v+ 3, y19+10);
  limb_muladd(r.v+ 2, x->v+ 3, y19+11);

  limb_muladd(r.v+ 4, x->v+ 4, y->v+ 0);
  limb_muladd(r.v+ 5, x->v+ 4, y->v+ 1);
  limb_muladd(r.v+ 6, x->v+ 4, y->v+ 2);
  limb_muladd(r.v+ 7, x->v+ 4, y->v+ 3);
  limb_muladd(r.v+ 8, x->v+ 4, y->v+ 4);
  limb_muladd(r.v+ 9, x->v+ 4, y->v+ 5);
  limb_muladd(r.v+10, x->v+ 4, y->v+ 6);
  limb_muladd(r.v+11, x->v+ 4, y->v+ 7);
  limb_muladd(r.v+ 0, x->v+ 4, y19+ 8);
  limb_muladd(r.v+ 1, x->v+ 4, y19+ 9);
  limb_muladd(r.v+ 2, x->v+ 4, y19+10);
  limb_muladd(r.v+ 3, x->v+ 4, y19+11);

  limb_muladd(r.v+ 5, x->v+ 5, y->v+ 0);
  limb_muladd(r.v+ 6, x->v+ 5, y->v+ 1);
  limb_muladd(r.v+ 7, x->v+ 5, y->v+ 2);
  limb_muladd(r.v+ 8, x->v+ 5, y->v+ 3);
  limb_muladd(r.v+ 9, x->v+ 5, y->v+ 4);
  limb_muladd(r.v+10, x->v+ 5, y->v+ 5);
  limb_muladd(r.v+11, x->v+ 5, y->v+ 6);
  limb_muladd(r.v+ 0, x->v+ 5, y19+ 7);
  limb_muladd(r.v+ 1, x->v+ 5, y19+ 8);
  limb_muladd(r.v+ 2, x->v+ 5, y19+ 9);
  limb_muladd(r.v+ 3, x->v+ 5, y19+10);
  limb_muladd(r.v+ 4, x->v+ 5, y19+11);

  limb_muladd(r.v+ 6, x->v+ 6, y->v+ 0);
  limb_muladd(r.v+ 7, x->v+ 6, y->v+ 1);
  limb_muladd(r.v+ 8, x->v+ 6, y->v+ 2);
  limb_muladd(r.v+ 9, x->v+ 6, y->v+ 3);
  limb_muladd(r.v+10, x->v+ 6, y->v+ 4);
  limb_muladd(r.v+11, x->v+ 6, y->v+ 5);
  limb_muladd(r.v+ 0, x->v+ 6, y19+ 6);
  limb_muladd(r.v+ 1, x->v+ 6, y19+ 7);
  limb_muladd(r.v+ 2, x->v+ 6, y19+ 8);
  limb_muladd(r.v+ 3, x->v+ 6, y19+ 9);
  limb_muladd(r.v+ 4, x->v+ 6, y19+10);
  limb_muladd(r.v+ 5, x->v+ 6, y19+11);

  limb_muladd(r.v+ 7, x->v+ 7, y->v+ 0);
  limb_muladd(r.v+ 8, x->v+ 7, y->v+ 1);
  limb_muladd(r.v+ 9, x->v+ 7, y->v+ 2);
  limb_muladd(r.v+10, x->v+ 7, y->v+ 3);
  limb_muladd(r.v+11, x->v+ 7, y->v+ 4);
  limb_muladd(r.v+ 0, x->v+ 7, y19+ 5);
  limb_muladd(r.v+ 1, x->v+ 7, y19+ 6);
  limb_muladd(r.v+ 2, x->v+ 7, y19+ 7);
  limb_muladd(r.v+ 3, x->v+ 7, y19+ 8);
  limb_muladd(r.v+ 4, x->v+ 7, y19+ 9);
  limb_muladd(r.v+ 5, x->v+ 7, y19+10);
  limb_muladd(r.v+ 6, x->v+ 7, y19+11);

  limb_muladd(r.v+ 8, x->v+ 8, y->v+ 0);
  limb_muladd(r.v+ 9, x->v+ 8, y->v+ 1);
  limb_muladd(r.v+10, x->v+ 8, y->v+ 2);
  limb_muladd(r.v+11, x->v+ 8, y->v+ 3);
  limb_muladd(r.v+ 0, x->v+ 8, y19+ 4);
  limb_muladd(r.v+ 1, x->v+ 8, y19+ 5);
  limb_muladd(r.v+ 2, x->v+ 8, y19+ 6);
  limb_muladd(r.v+ 3, x->v+ 8, y19+ 7);
  limb_muladd(r.v+ 4, x->v+ 8, y19+ 8);
  limb_muladd(r.v+ 5, x->v+ 8, y19+ 9);
  limb_muladd(r.v+ 6, x->v+ 8, y19+10);
  limb_muladd(r.v+ 7, x->v+ 8, y19+11);

  limb_muladd(r.v+ 9, x->v+ 9, y->v+ 0);
  limb_muladd(r.v+10, x->v+ 9, y->v+ 1);
  limb_muladd(r.v+11, x->v+ 9, y->v+ 2);
  limb_muladd(r.v+ 0, x->v+ 9, y19+ 3);
  limb_muladd(r.v+ 1, x->v+ 9, y19+ 4);
  limb_muladd(r.v+ 2, x->v+ 9, y19+ 5);
  limb_muladd(r.v+ 3, x->v+ 9, y19+ 6);
  limb_muladd(r.v+ 4, x->v+ 9, y19+ 7);
  limb_muladd(r.v+ 5, x->v+ 9, y19+ 8);
  limb_muladd(r.v+ 6, x->v+ 9, y19+ 9);
  limb_muladd(r.v+ 7, x->v+ 9, y19+10);
  limb_muladd(r.v+ 8, x->v+ 9, y19+11);

  limb_muladd(r.v+10, x->v+10, y->v+ 0);
  limb_muladd(r.v+11, x->v+10, y->v+ 1);
  limb_muladd(r.v+ 0, x->v+10, y19+ 2);
  limb_muladd(r.v+ 1, x->v+10, y19+ 3);
  limb_muladd(r.v+ 2, x->v+10, y19+ 4);
  limb_muladd(r.v+ 3, x->v+10, y19+ 5);
  limb_muladd(r.v+ 4, x->v+10, y19+ 6);
  limb_muladd(r.v+ 5, x->v+10, y19+ 7);
  limb_muladd(r.v+ 6, x->v+10, y19+ 8);
  limb_muladd(r.v+ 7, x->v+10, y19+ 9);
  limb_muladd(r.v+ 8, x->v+10, y19+10);
  limb_muladd(r.v+ 9, x->v+10, y19+11);

  limb_muladd(r.v+11, x->v+11, y->v+ 0);
  limb_muladd(r.v+ 0, x->v+11, y19+ 1);
  limb_muladd(r.v+ 1, x->v+11, y19+ 2);
  limb_muladd(r.v+ 2, x->v+11, y19+ 3);
  limb_muladd(r.v+ 3, x->v+11, y19+ 4);
  limb_muladd(r.v+ 4, x->v+11, y19+ 5);
  limb_muladd(r.v+ 5, x->v+11, y19+ 6);
  limb_muladd(r.v+ 6, x->v+11, y19+ 7);
  limb_muladd(r.v+ 7, x->v+11, y19+ 8);
  limb_muladd(r.v+ 8, x->v+11, y19+ 9);
  limb_muladd(r.v+ 9, x->v+11, y19+10);
  limb_muladd(r.v+10, x->v+11, y19+11);

  limb_add(&t, r.v+0, &alpha22);
  limb_sub(&t, &t, &alpha22);
  limb_sub(r.v+0, r.v+0, &t);
  limb_add(r.v+1, r.v+1, &t);

  limb_add(&t, r.v+1, &alpha43);
  limb_sub(&t, &t, &alpha43);
  limb_sub(r.v+1, r.v+1, &t);
  limb_add(r.v+2, r.v+2, &t);
  
  limb_add(&t, r.v+2, &alpha64);
  limb_sub(&t, &t, &alpha64);
  limb_sub(r.v+2, r.v+2, &t);
  limb_add(r.v+3, r.v+3, &t);
  
  limb_add(&t, r.v+3, &alpha85);
  limb_sub(&t, &t, &alpha85);
  limb_sub(r.v+3, r.v+3, &t);
  limb_add(r.v+4, r.v+4, &t);
  
  limb_add(&t, r.v+4, &alpha107);
  limb_sub(&t, &t, &alpha107);
  limb_sub(r.v+4, r.v+4, &t);
  limb_add(r.v+5, r.v+5, &t);
  
  limb_add(&t, r.v+5, &alpha128);
  limb_sub(&t, &t, &alpha128);
  limb_sub(r.v+5, r.v+5, &t);
  limb_add(r.v+6, r.v+6, &t);
  
  limb_add(&t, r.v+6, &alpha149);
  limb_sub(&t, &t, &alpha149);
  limb_sub(r.v+6, r.v+6, &t);
  limb_add(r.v+7, r.v+7, &t);
  
  limb_add(&t, r.v+7, &alpha170);
  limb_sub(&t, &t, &alpha170);
  limb_sub(r.v+7, r.v+7, &t);
  limb_add(r.v+8, r.v+8, &t);
  
  limb_add(&t, r.v+8, &alpha192);
  limb_sub(&t, &t, &alpha192);
  limb_sub(r.v+8, r.v+8, &t);
  limb_add(r.v+9, r.v+9, &t);
  
  limb_add(&t, r.v+9, &alpha213);
  limb_sub(&t, &t, &alpha213);
  limb_sub(r.v+9, r.v+9, &t);
  limb_add(r.v+10, r.v+10, &t);
  
  limb_add(&t, r.v+10, &alpha234);
  limb_sub(&t, &t, &alpha234);
  limb_sub(r.v+10, r.v+10, &t);
  limb_add(r.v+11, r.v+11, &t);

  limb_add(&t, r.v+11, &alpha255);
  limb_sub(&t, &t, &alpha255);
  limb_sub(r.v+11, r.v+11, &t);
  limb_mul(&t, &t, &scale19);
  limb_add(r.v+0, r.v+0, &t);

  limb_add(&t, r.v+0, &alpha22);
  limb_sub(&t, &t, &alpha22);
  limb_sub(r.v+0, r.v+0, &t);
  limb_add(r.v+1, r.v+1, &t);

  *rr = r;
}

void gfe4x_square(gfe4x *r, const gfe4x *x)
{
  gfe4x_mul(r, x, x);
}
*/

void gfe4x_invert(gfe4x *r, const gfe4x *x)
{
	gfe4x z2;
	gfe4x z9;
	gfe4x z11;
	gfe4x z2_5_0;
	gfe4x z2_10_0;
	gfe4x z2_20_0;
	gfe4x z2_50_0;
	gfe4x z2_100_0;
	gfe4x t0;
	gfe4x t1;
	int i;

	/* 2 */ gfe4x_square(&z2,x);
	/* 4 */ gfe4x_square(&t1,&z2);
	/* 8 */ gfe4x_square(&t0,&t1);
	/* 9 */ gfe4x_mul(&z9,&t0,x);
	/* 11 */ gfe4x_mul(&z11,&z9,&z2);
	/* 22 */ gfe4x_square(&t0,&z11);
	/* 2^5 - 2^0 = 31 */ gfe4x_mul(&z2_5_0,&t0,&z9);

	/* 2^6 - 2^1 */ gfe4x_square(&t0,&z2_5_0);
	/* 2^7 - 2^2 */ gfe4x_square(&t1,&t0);
	/* 2^8 - 2^3 */ gfe4x_square(&t0,&t1);
	/* 2^9 - 2^4 */ gfe4x_square(&t1,&t0);
	/* 2^10 - 2^5 */ gfe4x_square(&t0,&t1);
	/* 2^10 - 2^0 */ gfe4x_mul(&z2_10_0,&t0,&z2_5_0);

	/* 2^11 - 2^1 */ gfe4x_square(&t0,&z2_10_0);
	/* 2^12 - 2^2 */ gfe4x_square(&t1,&t0);
	/* 2^20 - 2^10 */ for (i = 2;i < 10;i += 2) { gfe4x_square(&t0,&t1); gfe4x_square(&t1,&t0); }
	/* 2^20 - 2^0 */ gfe4x_mul(&z2_20_0,&t1,&z2_10_0);

	/* 2^21 - 2^1 */ gfe4x_square(&t0,&z2_20_0);
	/* 2^22 - 2^2 */ gfe4x_square(&t1,&t0);
	/* 2^40 - 2^20 */ for (i = 2;i < 20;i += 2) { gfe4x_square(&t0,&t1); gfe4x_square(&t1,&t0); }
	/* 2^40 - 2^0 */ gfe4x_mul(&t0,&t1,&z2_20_0);

	/* 2^41 - 2^1 */ gfe4x_square(&t1,&t0);
	/* 2^42 - 2^2 */ gfe4x_square(&t0,&t1);
	/* 2^50 - 2^10 */ for (i = 2;i < 10;i += 2) { gfe4x_square(&t1,&t0); gfe4x_square(&t0,&t1); }
	/* 2^50 - 2^0 */ gfe4x_mul(&z2_50_0,&t0,&z2_10_0);

	/* 2^51 - 2^1 */ gfe4x_square(&t0,&z2_50_0);
	/* 2^52 - 2^2 */ gfe4x_square(&t1,&t0);
	/* 2^100 - 2^50 */ for (i = 2;i < 50;i += 2) { gfe4x_square(&t0,&t1); gfe4x_square(&t1,&t0); }
	/* 2^100 - 2^0 */ gfe4x_mul(&z2_100_0,&t1,&z2_50_0);

	/* 2^101 - 2^1 */ gfe4x_square(&t1,&z2_100_0);
	/* 2^102 - 2^2 */ gfe4x_square(&t0,&t1);
	/* 2^200 - 2^100 */ for (i = 2;i < 100;i += 2) { gfe4x_square(&t1,&t0); gfe4x_square(&t0,&t1); }
	/* 2^200 - 2^0 */ gfe4x_mul(&t1,&t0,&z2_100_0);

	/* 2^201 - 2^1 */ gfe4x_square(&t0,&t1);
	/* 2^202 - 2^2 */ gfe4x_square(&t1,&t0);
	/* 2^250 - 2^50 */ for (i = 2;i < 50;i += 2) { gfe4x_square(&t0,&t1); gfe4x_square(&t1,&t0); }
	/* 2^250 - 2^0 */ gfe4x_mul(&t0,&t1,&z2_50_0);

	/* 2^251 - 2^1 */ gfe4x_square(&t1,&t0);
	/* 2^252 - 2^2 */ gfe4x_square(&t0,&t1);
	/* 2^253 - 2^3 */ gfe4x_square(&t1,&t0);
	/* 2^254 - 2^4 */ gfe4x_square(&t0,&t1);
	/* 2^255 - 2^5 */ gfe4x_square(&t1,&t0);
	/* 2^255 - 21 */ gfe4x_mul(r,&t1,&z11);
}

void gfe4x_print(const gfe4x *x, int pos)
{
  int i;
  printf("(");
  for(i=0;i<11;i++)
    printf("%lf +", x->v[i].v[pos]);
  printf("%lf)", x->v[11].v[pos]);
}

