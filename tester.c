#include "BearSSL/inc/bearssl.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

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

void generateRSA(br_rsa_private_key *pk, br_rsa_public_key * pbk, unsigned int bits) {
    br_hmac_drbg_context ctx;
    prepareRNG(&ctx);

    //start generating
    br_rsa_keygen keygen = br_rsa_keygen_get_default();


    unsigned char buffer_priv[BR_RSA_KBUF_PRIV_SIZE(bits)];
    unsigned char buffer_pub[BR_RSA_KBUF_PUB_SIZE(bits)];


    keygen(&ctx.vtable, pk, buffer_priv, pbk, buffer_pub, bits, 0);
}

void generateECC(br_ec_private_key * sk, br_ec_public_key * pk, br_ec_impl * impl) {
    br_hmac_drbg_context ctx;
    prepareRNG(&ctx);

    struct timespec tstart={0,0}, tend={0,0};
/*
    br_ec_private_key private_key;
    br_ec_public_key public_key;
*/

    unsigned char buffer_priv[BR_EC_KBUF_PRIV_MAX_SIZE];
    unsigned char buffer_pub[BR_EC_KBUF_PUB_MAX_SIZE];

    FILE *file = fopen("result.csv", "w");

    if (!file) {
        fprintf(stderr, "Could not open file");
        exit(2);
    }
    br_ec_keygen (&ctx.vtable, impl, sk, buffer_priv, 23);
    br_ec_compute_pub(impl, pk, buffer_pub, sk);

    fclose(file);
}




int main(int argc, char * argv[]) {
    // RSA part /
    br_hmac_drbg_context rngCtx;
    const br_hash_class * class = &br_sha224_vtable;
    prepareRNG(&rngCtx);

    unsigned char dest[265] = {0};
    br_rsa_private_key pk;
    br_rsa_public_key pbk;
    generateRSA(&pk, &pbk, 2048);
    char *encMessage =  "randommsg";
    size_t lengthM = strlen(encMessage);
        br_rsa_i31_oaep_encrypt(&rngCtx.vtable, class, NULL, 0, &pbk, dest, 265, encMessage, lengthM);
    size_t length = 1024;
    if (br_rsa_i31_oaep_decrypt(class, NULL, 0, &pk, dest, &length)) {
        printf ("Success");
    }

 //   generateRSA(10,1024);
  //  generateRSA(10,2048);

  // ECC PART //
    br_ec_private_key private_key;
    br_ec_public_key public_key;
    br_ec_impl impl = br_ec_p256_m31;
    generateECC(&private_key, &public_key, &impl);
    unsigned char signature[256] = {0 };

    br_sha256_context ctx;
    br_sha256_init(&ctx);
    char * message = "RANDOMDATA";
    br_sha256_update(&ctx, &message, strlen(message));
    unsigned char output[256] = {0};
    br_sha256_out(&ctx, output);


    br_ecdsa_i31_sign_raw(&impl, ctx.vtable, output, &private_key, signature );
    if (br_ecdsa_i31_vrfy_raw(&impl, ctx.vtable, 32, &public_key, signature, 64)) {
        printf("Success");
    } else {
        printf("YOU SUCK");
    }
    return 0;
}	
