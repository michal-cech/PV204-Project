//
// Created by MrMCech on 30.03.2019.
//
#include "BearSSL/inc/bearssl.h"
#include <stdlib.h>

void prepareRNG(br_hmac_drbg_context * ctx) {
    //prepare PRNG
#ifdef linux
    size_t byte_count = 64;
    char data[64];
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    fread(&data, 1, byte_count, fp);
    fclose(fp);
    br_hmac_drbg_context ctx;
    br_hmac_drbg_init(&ctx, &br_sha256_vtable, data, byte_count);
#endif
#ifdef __WIN32
    br_hmac_drbg_init(ctx, &br_sha256_vtable, NULL, 0);
#endif
}
int hammingWeight(unsigned char * x, size_t size) {

    int count = 0;

    for (size_t i = 0; i < size; i++) {
        unsigned char y = x[i];
        while (y > 0) {
            count += __builtin_popcount((uint8_t) (y & 0xFF));
            y >>= 8;
        }
    }
    return count;
}
