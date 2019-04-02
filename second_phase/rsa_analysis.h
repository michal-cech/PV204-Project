//
// Created by MrMCech on 30.03.2019.
//
#include "../BearSSL/inc/bearssl.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>


#ifndef PV204_PROJECT_RSA_ANALYSIS_H
#define PV204_PROJECT_RSA_ANALYSIS_H
void encryptDecrypt(br_hmac_drbg_context* ctx, br_rsa_private_key *pk, br_rsa_public_key * pbk,
                    unsigned char * encMessage, size_t messageLength,
                    int index, struct timespec * tstart, struct timespec *tend );

void signRSA(br_hmac_drbg_context* ctx, br_rsa_private_key *pk, br_rsa_public_key * pbk,
             unsigned char * hash, size_t hashLength,
             int index, struct timespec * tstart, struct timespec *tend);

void generateRSA(br_hmac_drbg_context * ctx,br_rsa_private_key *pk, br_rsa_public_key * pbk,
        unsigned char *buffer_priv, unsigned char *buffer_pub, unsigned int bits);

void generateLowRSA(br_rsa_private_key *pk, br_rsa_public_key * pbk);

void generateHighRSA(br_rsa_private_key *pk, br_rsa_public_key * pbk);

void fixedMessageRandomExpRSA(br_hmac_drbg_context* ctx, size_t tries, size_t bits);
void randomMessagesFixedExpRSA(br_hmac_drbg_context* ctx, size_t tries, size_t bits);
void fixedMessageRandomExpSigRSA(br_hmac_drbg_context* ctx, size_t tries, size_t bits);
void randomMessagesFixedExpSigRSA(br_hmac_drbg_context* ctx, size_t tries, size_t bits);
void highHammingWeightRSADec(br_hmac_drbg_context* ctx, size_t tries);
void highHammingWeightRSASign(br_hmac_drbg_context* ctx, size_t tries);
void lowHammingWeightRSADec(br_hmac_drbg_context* ctx, size_t tries);
void lowHammingWeightRSASign(br_hmac_drbg_context* ctx, size_t tries);



#endif //PV204_PROJECT_RSA_ANALYSIS_H
