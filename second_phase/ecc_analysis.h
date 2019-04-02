//
// Created by MrMCech on 30.03.2019.
//

#ifndef PV204_PROJECT_ECC_ANALYSIS_H
#define PV204_PROJECT_ECC_ANALYSIS_H

#include "../BearSSL/inc/bearssl.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

void generateECC(br_hmac_drbg_context * ctx, br_ec_private_key * sk, void * buffer_priv, br_ec_public_key * pk, void * buffer_pub, br_ec_impl * impl);
void eccRandomMessages(br_hmac_drbg_context * ctx, size_t tries);
void eccRandomExponent(br_hmac_drbg_context * ctx, size_t tries);

void generateShortECC(br_hmac_drbg_context * ctx, br_ec_private_key * sk, void * buffer_priv, br_ec_public_key * pk, void * buffer_pub, br_ec_impl * impl);
void generateLargeECC(br_hmac_drbg_context * ctx, br_ec_private_key * sk, void * buffer_priv, br_ec_public_key * pk, void * buffer_pub, br_ec_impl * impl);
void eccShortExp(br_hmac_drbg_context * ctx, size_t tries);
void eccLargeExp(br_hmac_drbg_context * ctx, size_t tries);


#endif //PV204_PROJECT_ECC_ANALYSIS_H
