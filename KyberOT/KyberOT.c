#include "KyberOT.h"
#include<stdio.h>
#include "indcpa.h"
#include "polyvec.h"
//to sample randomness
#include "randombytes.h"
#include "fips202.h"
#include <string.h>

unsigned char listeng[256] = {
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
            'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F',
            'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
            'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '_',
            '!', '"', '$', '%', '&', '/', '(', ')', '=', '?', '+', '*', '#', ',', ';', ':',
            '.', '[', ']', '<', '>', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
            'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '1',
            '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
            'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
            'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3',
            '4', '5', '6', '7', '8', '9', '0', '-', '_', '!', '"', '$', '%', '&', '/', '(',
            ')', '=', '?', '+', '*', '#', ',', ';', ':', '.', '[', ']', '<', '>', 'a', 'b',
            'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
            's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '1', '2', '3', '4', '5', '6', '7', '8',
            '9', '0', '-', '_', '!', '"', '$', '%', '&', '/', '(', ')', '=', '?', '+', '#',
};

void subeng(unsigned char* W) {
    *(W) = listeng[*(W)];
}

void pkHash(unsigned char *h, unsigned char *pk, unsigned char *publicseed)
{
    //compute H(pk) and store it in h
    unsigned char seed[32];
    sha3_256(&seed[0], pk, PKlengthsmall);
    randomPK(h, &seed[0], publicseed);
}

void KyberReceiverMessage(KyberOTRecver* recver, KyberOtRecvPKs* pks)
{
    unsigned char pk[PKlength];
    unsigned char h[PKlength];
    unsigned char seed[32];


    //get pk, sk
    indcpa_keypair(pk, recver->secretKey);

    // sample random public key for the one we dont want.
    randombytes(seed, 32);
    randomPK(pks->keys[1 ^ recver->b], seed, &pk[PKlengthsmall]);

    //compute H(r_{not b})
    pkHash(h, pks->keys[1 ^ recver->b], &pk[PKlengthsmall]);

    //set r_b=pk-H(r_{not b})
    pkMinus(pks->keys[recver->b], pk, h);
}

void KyberSenderMessage(KyberOTCtxt* ctxt, KyberOTPtxt* ptxt, KyberOtRecvPKs* recvPks)
{
    unsigned char h[PKlength];
    unsigned char pk[PKlength];
    unsigned char coins[Coinslength];
    //compute ct_i=Enc(pk_i, sot_i) and sample coins
    //random coins
    randombytes(coins, Coinslength);
    //compute pk0
    pkHash(h, recvPks->keys[1], recvPks->keys[0] + PKlengthsmall);
    //pk_0=r_0+h(r_1)
    pkPlus(pk, recvPks->keys[0], h);
    //enc
    indcpa_enc(ctxt->sm[0], ptxt->sot[0], pk, coins);
    //random coins
    randombytes(coins, Coinslength);
    //compute pk1
    pkHash(h, recvPks->keys[0], recvPks->keys[0] + PKlengthsmall);
    //pk_1=r_1+h(r_0)
    pkPlus(pk, recvPks->keys[1], h);
    //enc
    indcpa_enc(ctxt->sm[1], ptxt->sot[1], pk, coins);
}

void KyberReceiverStrings(KyberOTRecver* recver, KyberOTCtxt* ctxt)
{
    indcpa_dec(recver->rot, ctxt->sm[recver->b], recver->secretKey);
}



int KyberExample()				//main-Funktion
{

    KyberOTCtxt ctxt;
    KyberOTPtxt ptxt;
    KyberOTRecver recver;
    KyberOtRecvPKs pks;
    //random choice bit

    randombytes(&recver.b, 1);
    recver.b &= 1;

    //sample random OT strings
    randombytes(ptxt.sot[0], OTlength);
    randombytes(ptxt.sot[1], OTlength);

    //get receivers message and secret coins
    KyberReceiverMessage(&recver, &pks);

    //get senders message, secret coins and ot strings
    KyberSenderMessage(&ctxt, &ptxt, &pks);

    //get receivers ot strings
    KyberReceiverStrings(&recver, &ctxt);


    //convert output into something readable
    for (int i = 0; i < OTlength; i++)
        printf("%x", ptxt.sot[0][i]);
    printf(" ");
    for (int i = 0; i < OTlength; i++)
        printf("%x", ptxt.sot[1][i]);
    printf("\n\n");
    for (int i = 0; i < OTlength; i++) {
        printf("%x", recver.rot[i]);
    }
    printf("\n");

    
    printf("Choice Bit: %i\n" , recver.b);
    if (memcmp(recver.rot, ptxt.sot[recver.b], OTlength) == 0)
    {
        printf("PASSED\n");
    }
    else
    {
        printf("FAILED\n");
    }

    //printf("%.(OTlength)s", rot);

    return 0;
}
