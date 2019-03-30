#include "BearSSL/inc/bearssl.h"
#include "BearSSL/src/inner.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>


#define TRIES 100000
#define BITS 2048
void prepareRNG(br_hmac_drbg_context * ctx) {
    //prepare PRNG
#ifdef linux
    size_t byte_count = 64;
    char data[64];
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    fread(&data, 1, byte_count, fp);
    fclose(fp);
    br_hmac_drbg_init(ctx, &br_sha256_vtable, data, byte_count);
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

void generateHighRSA(br_hmac_drbg_context* ctx, br_rsa_private_key *pk, br_rsa_public_key * pbk, unsigned char *buffer_priv, unsigned char *buffer_pub, unsigned intBIbits) {

    int weight = 0;
    br_rsa_keygen keygen = br_rsa_keygen_get_default();

    //start generating
    while (weight < (BITS * 3 / 5)) {
        printf("try");
        keygen(&ctx->vtable, pk, buffer_priv, pbk, buffer_pub, BITS, 0);
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

void generateECC(br_ec_private_key * sk, void * buffer_priv, br_ec_public_key * pk, void * buffer_pub, br_ec_impl * impl) {
    br_hmac_drbg_context ctx;
    prepareRNG(&ctx);

    struct timespec tstart={0,0}, tend={0,0};

    br_ec_keygen (&ctx.vtable, impl, sk, buffer_priv, 23);
    br_ec_compute_pub(impl, pk, buffer_pub, sk);

}

void rsaSignedPart(br_hmac_drbg_context* ctx) {
    const unsigned char *hash_oid = NULL;
    size_t hash_len = 256;
    size_t byte = 256;

    br_rsa_private_key sk;
    br_rsa_public_key pubk;


    unsigned char buffer_priv[BR_RSA_KBUF_PRIV_SIZE(BITS)];
    unsigned char buffer_pub[BR_RSA_KBUF_PUB_SIZE(BITS)];

    generateRSA(ctx, &sk, &pubk, buffer_priv, buffer_pub, 2048);
    unsigned char x[64] = {0 };

    br_sha256_context ctn;
    br_sha256_init(&ctn);
    char * msg = "RRRRRRRRRR";
    br_sha256_update(&ctn, msg, strlen(msg));
    unsigned char hash[32] = {0};
    br_sha256_out(&ctn, hash);

    if (br_rsa_i31_pkcs1_sign(hash_oid, hash, hash_len, &sk, x) != 0) {
        printf("Sign PKCS Success\n");
    } else {
        printf("Sign PKCS Not Success\n");
    }

    unsigned char hash_out[64] = {0 };

    if (br_rsa_i31_pkcs1_vrfy(x, 64, NULL, 256, &pubk, hash_out)) {
        printf("PKCS Verification success\n");
    } else {
        printf("PKCS Verification not success\n");
    }

}


void randomMessagesFixedExponentRSA(br_hmac_drbg_context* ctx) {
    // RSA part /
    unsigned char *buffer_priv_high = calloc(BR_RSA_KBUF_PRIV_SIZE(BITS), sizeof(unsigned char));

    unsigned char * buffer_pub_high = calloc(BR_RSA_KBUF_PUB_SIZE(BITS), sizeof(unsigned char));

    br_rsa_private_key pk_high;
    br_rsa_public_key pbk_high;

    generateRSA(ctx,&pk_high, &pbk_high, buffer_priv_high, buffer_pub_high, BITS);

    struct timespec tstart={0,0}, tend={0,0};
    // FIXED EXPONENT, RANDOM MESSAGES
    FILE *  file = fopen("timesRandomMessage", "w");
    fprintf(file,"ID;HW;LENGTH;TIME_OF_RANDOM_MESSAGE\n");
    for (int i = 0; i < TRIES; i++) {
        size_t bytes = (size_t) rand() % 190;
        unsigned char encMessage[bytes];
        for (int j = 0; j < bytes; j++) {
            encMessage[j] = (unsigned char) (rand() % 256);
        }

        int hW = hammingWeight(encMessage, bytes);
        unsigned char dest[256];
        size_t encrypted;
        if ((encrypted = br_rsa_i31_oaep_encrypt(&ctx->vtable,ctx->digest_class, NULL, 0, &pbk_high, dest, 256, encMessage, bytes)) == 0) {
            printf("ERRROR at index: %d", i);
        }

        clock_gettime(CLOCK_MONOTONIC, &tstart);
        int result = (br_rsa_i31_oaep_decrypt(ctx->digest_class, NULL, 0, &pk_high, dest, &encrypted));
        clock_gettime(CLOCK_MONOTONIC, &tend);
        if (!result) {
            printf("ERRROR at index: %d", i);
        }

        fprintf(file, "%d;%d;%u;",i,hW,bytes);
        fprintf(file,"%.5f ns;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);

    }
    free(buffer_priv_high);
    free(buffer_pub_high);
    fclose(file);
}

void fixedMessageRandomExponentRSA(br_hmac_drbg_context* ctx) {
    struct timespec tstart={0,0}, tend={0,0};

    FILE *  file = fopen("timesRandomExponent", "w");
    fprintf(file,"ID;HW;TIME_OF_RANDOM_MESSAGE\n");
    size_t bytes = 190;
    unsigned char encMessage[bytes];
    for (int j = 0; j < bytes; j++) {
        encMessage[j] = (unsigned char) (rand() % 256);
    }

    for (int i = 0; i < TRIES; i++) {
        br_rsa_private_key pk_high;
        br_rsa_public_key pbk_high;
        unsigned char buffer_priv_high[BR_RSA_KBUF_PRIV_SIZE(BITS)];
        unsigned char buffer_pub_high[BR_RSA_KBUF_PUB_SIZE(BITS)];
        generateRSA(ctx, &pk_high, &pbk_high, buffer_priv_high, buffer_pub_high, BITS);
        br_rsa_compute_pubexp pubFun = br_rsa_compute_pubexp_get_default();
        uint32_t pubExp = pubFun(&pk_high);

        br_rsa_compute_privexp privFun = br_rsa_compute_privexp_get_default();
        size_t privLength = privFun(NULL,&pk_high, pubExp);

        unsigned char privExp[privLength];
        privFun(privExp,&pk_high,pubExp);

        int hW = hammingWeight(privExp, bytes);

        unsigned char dest[256];
        size_t encrypted;
        if ((encrypted = br_rsa_i31_oaep_encrypt(&ctx->vtable, ctx->digest_class, NULL, 0, &pbk_high, dest, 256, encMessage, bytes)) == 0) {
            printf("ERRROR at index: %d", i);
        }

        clock_gettime(CLOCK_MONOTONIC, &tstart);
        int result = (br_rsa_i31_oaep_decrypt(ctx->digest_class, NULL, 0, &pk_high, dest, &encrypted));
        clock_gettime(CLOCK_MONOTONIC, &tend);
        if (!result) {
            printf("ERRROR at index: %d", i);
        }

        fprintf(file, "%d;%d;",i,hW);
        fprintf(file,"%.5f ns;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);
    }
    fclose(file);
}

void rsaEncryptionPart(br_hmac_drbg_context* ctx) {
    randomMessagesFixedExponentRSA(ctx);
    fixedMessageRandomExponentRSA(ctx);
}

void rsaPart(br_hmac_drbg_context* ctx) {
    rsaEncryptionPart(ctx);
    //rsaSignedPart(ctx);
}

int main(int argc, char * argv[]) {
    br_hmac_drbg_context ctx;
    prepareRNG(&ctx);
    rsaPart(&ctx);

/*
  // ECC PART //
    unsigned char buffer_priv[BR_EC_KBUF_PRIV_MAX_SIZE];
    unsigned char buffer_pub[BR_EC_KBUF_PUB_MAX_SIZE];
    br_ec_private_key private_key;
    br_ec_public_key public_key;
    br_ec_impl impl = br_ec_p256_m31;


    generateECC(&private_key, buffer_priv, &public_key, buffer_pub, &impl);
    unsigned char signature[64] = {0 };

    br_sha256_context ctx;
    br_sha256_init(&ctx);
    char * message = "RRRRRRRRRR";
    br_sha256_update(&ctx, message, strlen(message));
    unsigned char output[32] = {0};
    br_sha256_out(&ctx, output);

    size_t signedLength = 0;
    if (( signedLength = br_ecdsa_i31_sign_raw(&impl, ctx.vtable, output, &private_key, signature )) != 0) {
        printf("Signed");
    }
    if (br_ecdsa_i31_vrfy_raw(&impl, output, 32, &public_key, signature, signedLength)) {
        printf("Success");
    }
    return 0;
    */
}	
