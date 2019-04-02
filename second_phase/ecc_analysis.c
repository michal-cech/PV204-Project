//
// Created by MrMCech on 30.03.2019.
//
#include "../BearSSL/inc/bearssl.h"
#include "utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static unsigned char largeKey[] = {255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 188, 230, 250, 173, 167, 17, 158, 84, 243, 185, 202, 194, 252, 63, 25, 51};

void generateECC(br_hmac_drbg_context * ctx, br_ec_private_key * sk, void * buffer_priv, br_ec_public_key * pk, void * buffer_pub, br_ec_impl * impl) {
    br_ec_keygen (&ctx->vtable, impl, sk, buffer_priv, 23);
    br_ec_compute_pub(impl, pk, buffer_pub, sk);
}

void generateShortECC(br_hmac_drbg_context * ctx, br_ec_private_key * sk, void * buffer_priv, br_ec_public_key * pk, void * buffer_pub, br_ec_impl * impl) {
    br_ec_keygen (&ctx->vtable, impl, sk, buffer_priv, 23);
    *(sk->x) = (unsigned char) 3;
    sk->xlen = 1;
    br_ec_compute_pub(impl, pk, buffer_pub, sk);

}

void generateLargeECC(br_hmac_drbg_context * ctx, br_ec_private_key * sk, void * buffer_priv, br_ec_public_key * pk, void * buffer_pub, br_ec_impl * impl) {

        br_ec_keygen(&ctx->vtable, impl, sk, buffer_priv, 23);
        sk->x = largeKey;
        sk->xlen = 32;
        br_ec_compute_pub(impl, pk, buffer_pub, sk);
}



void eccSign(br_sha512_context * ctx, br_ec_private_key * pk, br_ec_public_key * pbk, br_ec_impl * impl,
        unsigned char * output, size_t outputLength,
        int index, struct timespec * tstart, struct timespec * tend) {

    unsigned char signature[64] = {0 };
    clock_gettime(CLOCK_MONOTONIC, tstart);
    size_t signedLength = br_ecdsa_i31_sign_raw(impl, ctx->vtable, output, pk, signature );
    clock_gettime(CLOCK_MONOTONIC, tend);
    if (!signedLength) {
        printf("ecc index %d", index);
    }
    if (!br_ecdsa_i31_vrfy_raw(impl, output, 32, pbk, signature, signedLength)) {
        printf("ecc index %d", index);
    }
}

void eccRandomMessages(br_hmac_drbg_context * ctx, size_t tries) {
    struct timespec tstart={0,0}, tend={0,0};
    unsigned char *buffer_priv = calloc(BR_EC_KBUF_PRIV_MAX_SIZE, sizeof(unsigned char));
    unsigned char *buffer_pub = calloc(BR_EC_KBUF_PUB_MAX_SIZE, sizeof(unsigned char));
    br_ec_private_key private_key;
    br_ec_public_key public_key;
    br_ec_impl impl = br_ec_p256_m31;
    generateECC(ctx, &private_key, buffer_priv, &public_key, buffer_pub, &impl);

    br_sha512_context ctn;
    br_sha512_init(&ctn);
    FILE * file = fopen("ecc_random_messages.txt", "w");
    fprintf(file, "ID;HW;TIME\n");
    for (int i = 0; i < tries; i++) {
        size_t bytes = (size_t) rand() % 190;
        unsigned char message[bytes];
        for (int j = 0; j < bytes; j++) {
            message[j] = (unsigned char) (rand() % 256);
        }
        br_sha512_update(&ctn, message, bytes);
        unsigned char output[64] = {0};
        br_sha512_out(&ctn, output);
        int hW = hammingWeight(output, 64);

        eccSign(&ctn, &private_key, &public_key, &impl, output, 64, i, &tstart, &tend);

        fprintf(file, "%d;%d;",i,hW);
        fprintf(file,"%.5f ns;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);
    }
    free(buffer_priv);
    free(buffer_pub);
    fclose(file);
}
void eccRandomExponent(br_hmac_drbg_context * ctx, size_t tries) {
    struct timespec tstart={0,0}, tend={0,0};
    br_ec_impl impl = br_ec_p256_m31;
    br_sha512_context ctn;
    br_sha512_init(&ctn);

    size_t bytes = (size_t) rand() % 190;
    unsigned char message[bytes];
    for (int j = 0; j < bytes; j++) {
        message[j] = (unsigned char) (rand() % 256);
    }
    br_sha512_update(&ctn, message, bytes);
    unsigned char output[64] = {0};
    br_sha512_out(&ctn, output);

    FILE * file = fopen("ecc_random_exp.txt", "w");
    fprintf(file, "ID;HW;TIME\n");
    for (int i = 0; i < tries; i++) {
        unsigned char buffer_priv[BR_EC_KBUF_PRIV_MAX_SIZE];
        unsigned char buffer_pub[BR_EC_KBUF_PUB_MAX_SIZE];
        br_ec_private_key private_key;
        br_ec_public_key public_key;
        generateECC(ctx, &private_key, buffer_priv, &public_key, buffer_pub, &impl);

        int hW = hammingWeight(private_key.x, private_key.xlen);

        eccSign(&ctn, &private_key, &public_key, &impl, output, 32, i, &tstart, &tend);
        fprintf(file, "%d;%d;",i,hW);
        fprintf(file,"%.5f ns;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);
    }
    fclose(file);
}

void eccShortExp(br_hmac_drbg_context * ctx, size_t tries) {
    struct timespec tstart={0,0}, tend={0,0};
    unsigned char buffer_priv[BR_EC_KBUF_PRIV_MAX_SIZE];
    unsigned char buffer_pub[BR_EC_KBUF_PUB_MAX_SIZE];
    br_ec_private_key private_key;
    br_ec_public_key public_key;
    br_ec_impl impl = br_ec_p256_m31;
    generateShortECC(ctx, &private_key, buffer_priv, &public_key, buffer_pub, &impl);

    br_sha512_context ctn;
    br_sha512_init(&ctn);
    unsigned char message[] = "Testovaci zprava";
    size_t messageLength = sizeof(message);
    br_sha512_update(&ctn, message, messageLength);
    unsigned char output[64] = {0};
    br_sha512_out(&ctn, output);
    FILE * file = fopen("ecc_short_exponent.txt", "w");
    fprintf(file, "ID;TIME;\n");
    for (int i = 0; i < tries; i++) {
        eccSign(&ctn, &private_key, &public_key, &impl, output, 64, i, &tstart, &tend);

        fprintf(file, "%d;",i);
        fprintf(file,"%.5f;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);
    }
    fclose(file);
}

void eccLargeExp(br_hmac_drbg_context * ctx, size_t tries) {
    struct timespec tstart={0,0}, tend={0,0};
    unsigned char buffer_priv[BR_EC_KBUF_PRIV_MAX_SIZE];
    unsigned char buffer_pub[BR_EC_KBUF_PUB_MAX_SIZE];
    br_ec_private_key private_key;
    br_ec_public_key public_key;
    br_ec_impl impl = br_ec_p256_m31;
    generateLargeECC(ctx, &private_key, buffer_priv, &public_key, buffer_pub, &impl);

    br_sha512_context ctn;
    br_sha512_init(&ctn);
    unsigned char message[] = "Testovaci zprava";
    size_t messageLength = sizeof(message);
    br_sha512_update(&ctn, message, messageLength);
    unsigned char output[64] = {0};
    br_sha512_out(&ctn, output);
    FILE * file = fopen("ecc_large_exponent.txt", "w");
    fprintf(file, "ID;TIME;\n");
    for (int i = 0; i < tries; i++) {
        eccSign(&ctn, &private_key, &public_key, &impl, output, 64, i, &tstart, &tend);

        fprintf(file, "%d;",i);
        fprintf(file,"%.5f;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);
    }
    fclose(file);
}


