#include "BearSSL/inc/bearssl.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

void generateECC(int number, unsigned int bits) {
    br_hmac_drbg_context ctx;
    br_hmac_drbg_init(&ctx, &br_sha256_vtable, NULL, 0);

    br_ec_private_key private_key;
    br_ec_public_key public_key;
    br_ec_impl impl;

    char buffer_priv[bits / 8];
    char buffer_pub[bits / 8];

    double ex_time;

    FILE *fp;
    fp = fopen("result.csv", "w+");

    for (int i = 0; i < number; i++) {
        time_t start = time(NULL);

        br_ec_keygen (&ctx.vtable, &impl, &private_key, buffer_priv, 5);
        br_ec_compute_pub (&impl, &public_key, buffer_pub, &private_key);

        ex_time = (double)((time(NULL) - start) * 1000000000);

        fprintf(fp, "%d;%s;%s;%d", i, public_key, private_key, ex_time);
    }

    fclose(fp);
}


int main(int argc, char * argv[]) {
    generateECC(1, 256);

    return 0;
}
