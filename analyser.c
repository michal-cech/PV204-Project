#include "BearSSL/inc/bearssl.h"

#include "utils.h"
#include "rsa_analysis.h"
#include "ecc_analysis.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>


#define TRIES 20000
#define BITS 2048

void rsaSignedPart(br_hmac_drbg_context* ctx) {
//    fixedMessageRandomExpSigRSA(ctx, TRIES, BITS);
//    randomMessagesFixedExpSigRSA(ctx,TRIES, BITS);
    highHammingWeightRSASign(ctx, TRIES);
//    lowHammingWeightRSASign(ctx, TRIES);
}

void rsaEncryptionPart(br_hmac_drbg_context* ctx) {
//    randomMessagesFixedExpRSA(ctx, TRIES, BITS);
//    fixedMessageRandomExpRSA(ctx, TRIES, BITS);
//    highHammingWeightRSADec(ctx, TRIES);
//    lowHammingWeightRSADec(ctx, TRIES);
}

void rsaPart(br_hmac_drbg_context* ctx) {
    rsaEncryptionPart(ctx);
    rsaSignedPart(ctx);
}

void eccPart(br_hmac_drbg_context * ctx) {
    eccRandomMessages(ctx, TRIES);
    eccRandomExponent(ctx, TRIES);
}

int main(int argc, char * argv[]) {
    br_hmac_drbg_context ctx;
    prepareRNG(&ctx);
    rsaPart(&ctx);
    eccPart(&ctx);

}	
