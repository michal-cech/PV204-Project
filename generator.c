#include "BearSSL/bearssl.h"
#include <stdlib.h>
#include <stdio.h>

void generateRSA(int number, unsigned int bits) {
    //prepare PRNG
    br_hmac_drbg_context ctx;
    br_hmac_drbg_init(&ctx, &br_sha256_vtable, NULL, 0);

    //start generating
    br_rsa_private_key pk;
    br_rsa_public_key pbk;
    char buffer_priv[bits / 8];
    char buffer_pub[bits / 8];

    for (int i = 0; i < number; i++) {
        br_rsa_keygen keygen = br_rsa_keygen_get_default();
        keygen(&ctx.vtable, &pk, buffer_priv, &pbk, buffer_pub, bits, 0);

    }

}


int main(int argc, char * argv[]) {
    generateRSA(1,512);
    return 0;
}	
