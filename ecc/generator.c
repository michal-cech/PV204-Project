#include "BearSSL/bearssl.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

void generateECC(int number, unsigned int bits) {

    //prepare PRNG
    br_hmac_drbg_context ctx;
    br_hmac_drbg_init(&ctx, &br_sha256_vtable, NULL, 0);

    br_rsa_private_key private_key;
    br_rsa_public_key public_key;
    char buffer_priv[bits / 8];
    char buffer_pub[bits / 8];

    FILE *fp;
    fp = fopen("result.csv", "w+");

    for (int i = 0; i < number; i++) {
        time_t start = time(NULL);
        impl = br_ec_get_default();

        br_ec_keygen (&ctx.vtable, &impl, &private_key, buffer_priv, 5);
        br_ec_compute_pub (&impl, &public_key, buffer_pub, &private_key);

        fprintf(fp, "%d;%s;%s;%d", i, public_key, private_key, (double)(time(NULL) - start)));
    }

    fclose(fp);
}


int main(int argc, char * argv[]) {
    generateECC(1, 256);
    return 0;
}
