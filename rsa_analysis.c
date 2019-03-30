//
// Created by MrMCech on 30.03.2019.
//
#include "BearSSL/inc/bearssl.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "utils.h"


void encryptDecrypt(br_hmac_drbg_context* ctx, br_rsa_private_key *pk, br_rsa_public_key * pbk,
                    unsigned char * encMessage, size_t messageLength,
                    int index, struct timespec * tstart, struct timespec *tend ) {

    unsigned char dest[256];
    size_t encrypted;
    if ((encrypted = br_rsa_i31_oaep_encrypt(&ctx->vtable,ctx->digest_class, NULL, 0, pbk, dest, 256, encMessage, messageLength)) == 0) {
        printf("ERRROR at index: %d", index);
    }

    clock_gettime(CLOCK_MONOTONIC, tstart);
    int result = (br_rsa_i31_oaep_decrypt(ctx->digest_class, NULL, 0, pk, dest, &encrypted));
    clock_gettime(CLOCK_MONOTONIC, tend);
    if (!result) {
        printf("ERRROR at index: %d", index);
    }
}

void signRSA(br_hmac_drbg_context* ctx, br_rsa_private_key *pk, br_rsa_public_key * pbk,
             unsigned char * hash, size_t hashLength,
             int index, struct timespec * tstart, struct timespec *tend) {

    const unsigned char *hash_oid = BR_HASH_OID_SHA512;
    size_t sigLength = 256;
    unsigned char signature[sigLength];
    clock_gettime(CLOCK_MONOTONIC, tstart);
    int result = br_rsa_i31_pkcs1_sign(hash_oid, hash, hashLength, pk, signature);
    clock_gettime(CLOCK_MONOTONIC, tend);
    if (!result) {
        printf("PKCS sig not success, index: %d\n", index);
    }
    unsigned char hash_out[hashLength];
    if (!br_rsa_i31_pkcs1_vrfy(signature, sigLength, hash_oid, hashLength, pbk, hash_out)) {
        printf("PKCS Verification not success, index: %d\n",index);
    }
}

void generateHighRSA(br_hmac_drbg_context* ctx, br_rsa_private_key *pk, br_rsa_public_key * pbk, unsigned char *buffer_priv, unsigned char *buffer_pub, unsigned int bits) {

    int weight = 0;
    br_rsa_keygen keygen = br_rsa_keygen_get_default();

    //start generating
    while (weight < (bits * 3 / 5)) {
        printf("try");
        keygen(&ctx->vtable, pk, buffer_priv, pbk, buffer_pub, bits, 0);
        br_rsa_compute_privexp privFun = br_rsa_compute_privexp_get_default();
        br_rsa_compute_pubexp pubFun = br_rsa_compute_pubexp_get_default();
        uint32_t pubExp = pubFun(pk);
        size_t privLength = privFun(NULL,pk, pubExp);
        unsigned char privExp[privLength];
        privFun(privExp,pk,pubExp);
        weight = hammingWeight(privExp, privLength);
        printf ("%d\n",weight);
    }
}

void generateLowRSA(br_hmac_drbg_context* ctx, br_rsa_private_key *pk, br_rsa_public_key * pbk, unsigned char *buffer_priv, unsigned char *buffer_pub, unsigned int bits) {
    int weight = 2048;
    br_rsa_keygen keygen = br_rsa_keygen_get_default();

    //start generating
    while (weight > (bits*2 / 5)) {
        keygen(&ctx->vtable, pk, buffer_priv, pbk, buffer_pub, bits, 0);
        br_rsa_compute_privexp privFun = br_rsa_compute_privexp_get_default();
        br_rsa_compute_pubexp pubFun = br_rsa_compute_pubexp_get_default();
        uint32_t pubExp = pubFun(pk);
        size_t privLength = privFun(NULL,pk, pubExp);
        unsigned char privExp[privLength];
        privFun(privExp,pk,pubExp);
        weight = hammingWeight(privExp, privLength);
        printf ("%d\n",weight);
    }
}

void generateRSA(br_hmac_drbg_context * ctx,br_rsa_private_key *pk, br_rsa_public_key * pbk, unsigned char *buffer_priv, unsigned char *buffer_pub, unsigned int bits) {
    br_rsa_keygen keygen = br_rsa_keygen_get_default();
    keygen(&ctx->vtable, pk, buffer_priv, pbk, buffer_pub, bits, 0);
}

void randomMessagesFixedExpSigRSA(br_hmac_drbg_context* ctx, size_t tries, size_t bits) {
    struct timespec tstart={0,0}, tend={0,0};
    unsigned char *buffer_priv = calloc(BR_RSA_KBUF_PRIV_SIZE(bits), sizeof(unsigned char));
    unsigned char * buffer_pub = calloc(BR_RSA_KBUF_PUB_SIZE(bits), sizeof(unsigned char));
    br_rsa_private_key pk;
    br_rsa_public_key pbk;
    generateRSA(ctx,&pk, &pbk, buffer_priv, buffer_pub, bits);

    br_sha512_context ctn;
    br_sha512_init(&ctn);

    FILE *  file = fopen("rsa_random_message_sig", "w");
    fprintf(file,"ID;HW;LENGTH;TIME\n");
    for (int i = 0; i < tries; i++) {
        size_t bytes = (size_t) rand() % 190;
        unsigned char message[bytes];
        for (int j = 0; j < bytes; j++) {
            message[j] = (unsigned char) (rand() % 256);
        }
        br_sha512_update(&ctn, message, bytes);
        unsigned char hash[bytes];
        br_sha512_out(&ctn, hash);

        int hW = hammingWeight(hash, bytes);
        signRSA(ctx, &pk, &pbk, hash, bytes, i, &tstart, &tend );
        fprintf(file, "%d;%d;%u;",i,hW,bytes);
        fprintf(file,"%.5f ns;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);

    }
    free(buffer_priv);
    free(buffer_pub);
    fclose(file);

}

void fixedMessageRandomExpSigRSA(br_hmac_drbg_context* ctx, size_t tries, size_t bits) {
    struct timespec tstart={0,0}, tend={0,0};
    size_t hashLength = 64;
    size_t signatureLength = 256;

    br_sha512_context ctn;
    br_sha512_init(&ctn);

    unsigned char hashedMsg[] = "HashingMSG";
    size_t length = sizeof(hashedMsg);

    br_sha512_update(&ctn, hashedMsg, length);
    unsigned char hash[hashLength];
    br_sha512_out(&ctn, hash);

    FILE *  file = fopen("rsa_random_exp_sig", "w");
    fprintf(file,"ID;HW;LENGTH;TIME\n");
    for (int i = 0; i < tries; i++) {
        br_rsa_private_key pk;
        br_rsa_public_key pbk;
        unsigned char buffer_priv_high[BR_RSA_KBUF_PRIV_SIZE(bits)];
        unsigned char buffer_pub_high[BR_RSA_KBUF_PUB_SIZE(bits)];
        generateRSA(ctx, &pk, &pbk, buffer_priv_high, buffer_pub_high, bits);

        br_rsa_compute_pubexp pubFun = br_rsa_compute_pubexp_get_default();
        uint32_t pubExp = pubFun(&pk);

        br_rsa_compute_privexp privFun = br_rsa_compute_privexp_get_default();
        size_t privLength = privFun(NULL, &pk, pubExp);

        unsigned char privExp[privLength];
        privFun(privExp, &pk, pubExp);

        int hW = hammingWeight(privExp, signatureLength);

        signRSA(ctx, &pk, &pbk, hash, hashLength, i, &tstart, &tend);
        fprintf(file, "%d;%d;", i, hW);
        fprintf(file, "%.5f ns;\n",
                (((double) tend.tv_sec + 1.0e-9 * tend.tv_nsec) -
                 ((double) tstart.tv_sec + 1.0e-9 * tstart.tv_nsec)) * 1.0e9);
    }
    fclose(file);


}

void randomMessagesFixedExpRSA(br_hmac_drbg_context* ctx, size_t tries, size_t bits) {
    // RSA part /
    unsigned char *buffer_priv_high = calloc(BR_RSA_KBUF_PRIV_SIZE(bits), sizeof(unsigned char));

    unsigned char * buffer_pub_high = calloc(BR_RSA_KBUF_PUB_SIZE(bits), sizeof(unsigned char));

    br_rsa_private_key pk_high;
    br_rsa_public_key pbk_high;

    generateRSA(ctx,&pk_high, &pbk_high, buffer_priv_high, buffer_pub_high, bits);

    struct timespec tstart={0,0}, tend={0,0};
    // FIXED EXPONENT, RANDOM MESSAGES
    FILE *  file = fopen("rsa_random_msg_dec", "w");
    fprintf(file,"ID;HW;LENGTH;TIME\n");
    for (int i = 0; i < tries; i++) {
        size_t bytes = (size_t) rand() % 190;
        unsigned char encMessage[bytes];
        for (int j = 0; j < bytes; j++) {
            encMessage[j] = (unsigned char) (rand() % 256);
        }
        int hW = hammingWeight(encMessage, bytes);
        encryptDecrypt(ctx, &pk_high, &pbk_high,encMessage, bytes, i, &tstart, &tend );
        fprintf(file, "%d;%d;%u;",i,hW,bytes);
        fprintf(file,"%.5f ns;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);

    }
    free(buffer_priv_high);
    free(buffer_pub_high);
    fclose(file);
}

void fixedMessageRandomExpRSA(br_hmac_drbg_context* ctx, size_t tries, size_t bits) {
    struct timespec tstart={0,0}, tend={0,0};

    FILE *  file = fopen("rsa_random_exp_dec", "w");
    fprintf(file,"ID;HW;TIME\n");

    size_t bytes = 190;
    unsigned char encMessage[bytes];
    for (int j = 0; j < bytes; j++) {
        encMessage[j] = (unsigned char) (rand() % 256);
    }

    for (int i = 0; i < tries; i++) {
        br_rsa_private_key pk_high;
        br_rsa_public_key pbk_high;
        unsigned char buffer_priv_high[BR_RSA_KBUF_PRIV_SIZE(bits)];
        unsigned char buffer_pub_high[BR_RSA_KBUF_PUB_SIZE(bits)];
        generateRSA(ctx, &pk_high, &pbk_high, buffer_priv_high, buffer_pub_high, bits);
        br_rsa_compute_pubexp pubFun = br_rsa_compute_pubexp_get_default();
        uint32_t pubExp = pubFun(&pk_high);

        br_rsa_compute_privexp privFun = br_rsa_compute_privexp_get_default();
        size_t privLength = privFun(NULL,&pk_high, pubExp);

        unsigned char privExp[privLength];
        privFun(privExp,&pk_high,pubExp);

        int hW = hammingWeight(privExp, bytes);

        encryptDecrypt(ctx, &pk_high, &pbk_high,encMessage, bytes, i, &tstart, &tend );

        fprintf(file, "%d;%d;",i,hW);
        fprintf(file,"%.5f ns;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);
    }
    fclose(file);
}
