//
// Created by MrMCech on 30.03.2019.
//


#ifndef PV204_PROJECT_UTILS_H
#define PV204_PROJECT_UTILS_H

#include "BearSSL/inc/bearssl.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

void prepareRNG(br_hmac_drbg_context * ctx);
int hammingWeight(unsigned char * x, size_t size);
void hexStringToByteArray(const unsigned char * src, unsigned char* dest, size_t length);

#endif //PV204_PROJECT_UTILS_H