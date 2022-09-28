#include "params.h"

//length in bytes/unsigned chars
#define PKlength (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define PKlengthsmall KYBER_POLYVECBYTES
#define SKlength KYBER_INDCPA_SECRETKEYBYTES
#define CTlength (KYBER_POLYVECBYTES+KYBER_POLYBYTES)
#define OTlength KYBER_INDCPA_MSGBYTES
#define Coinslength (32)

typedef struct 
{
    // sender message
    unsigned char sm[2][CTlength];

} KyberOTCtxt;

typedef struct
{
    // sender chosen strings
    unsigned char sot[2][OTlength];

} KyberOTPtxt;


//receiver message 1 in the Kyber OT protocol.
typedef struct 
{
    //receiver message
    unsigned char keys[2][PKlength];
} KyberOtRecvPKs;

typedef struct 
{


    // receiver secret randomness
    unsigned char secretKey[SKlength];


    // receiver learned strings
    unsigned char rot[OTlength];

    // receiver choice bit
    unsigned char b;

} KyberOTRecver;

void KyberReceiverMessage(KyberOTRecver* recver, KyberOtRecvPKs* pks);
void KyberSenderMessage(KyberOTCtxt* ctxt, KyberOTPtxt* ptxt, KyberOtRecvPKs* recvPks);
void KyberReceiverStrings(KyberOTRecver* recver, KyberOTCtxt* ctxt);


int KyberExample();
