#include "BearSSL/inc/bearssl.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

void printKeysToFile(br_rsa_private_key* pk, br_rsa_public_key* pbk, int counter, FILE* file, struct timespec t1, struct timespec t2) {

    unsigned char modulus[pbk->nlen];
    br_rsa_compute_modulus modulusFunction = br_rsa_compute_modulus_get_default();
    modulusFunction(modulus,pk);

    br_rsa_compute_pubexp pubFun = br_rsa_compute_pubexp_get_default();
    uint32_t pubExp = pubFun(pk);

    br_rsa_compute_privexp privFun = br_rsa_compute_privexp_get_default();
    size_t privLength = privFun(NULL,pk, pubExp);
    unsigned char privExp[privLength];
    privFun(privExp,pk,pubExp);


    fprintf(file, "%d;",counter);
    for (size_t i = 0; i < pbk->nlen; i++ ) {
        fprintf(file,"%02hhX",modulus[i]);
    }

    fprintf(file,";");
    for (size_t i = 0; i < pbk->elen; i++ ) {
        fprintf(file, "%02hhX", pbk->e[i]);
    }
    fprintf(file,";");
    for (size_t i = 0; i < pk->plen; i++ ) {
        fprintf(file, "%02hhX", pk->p[i]);
    }
    fprintf(file,";");
    for (size_t i = 0; i < pk->qlen; i++ ) {
        fprintf(file, "%02hhX", pk->q[i]);
    }
    fprintf(file,";");

    for (size_t i = 0; i < privLength; i++ ) {
        fprintf(file,"%02hhX",privExp[i]);
    }

    fprintf(file,";%.5f ns;\n",
            (((double)t2.tv_sec + 1.0e-9*t2.tv_nsec) -
           ((double)t1.tv_sec + 1.0e-9*t1.tv_nsec))*1.0e9);
}

void generateRSA(int number, unsigned int bits) {
    //prepare PRNG
    size_t byte_count = 64;
    char data[64];
#ifdef linux
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    fread(&data, 1, byte_count, fp);
    fclose(fp);
    br_hmac_drbg_context ctx;
    br_hmac_drbg_init(&ctx, &br_sha256_vtable, data, byte_count);
#endif

#ifdef __WIN32
    br_hmac_drbg_context ctx;
    br_hmac_drbg_init(&ctx, &br_sha256_vtable, NULL, 0);
#endif

    //start generating
    br_rsa_private_key pk;
    br_rsa_public_key pbk;
    br_rsa_keygen keygen = br_rsa_keygen_get_default();
    char * filename;

    if (bits == 512) {
        filename = "rsa512.txt";
    } else if (bits == 1024){
        filename = "rsa1024.txt";
    } else {
        filename = "rsa2048.txt";
    }

    unsigned char buffer_priv[BR_RSA_KBUF_PRIV_SIZE(bits)];
    unsigned char buffer_pub[BR_RSA_KBUF_PUB_SIZE(bits)];
    FILE* file = fopen(filename, "w");
    clock_t timer = clock();
    struct timespec tstart={0,0}, tend={0,0};
    for (int i = 0; i < number; i++) {
	clock_gettime(CLOCK_MONOTONIC, &tstart);
        keygen(&ctx.vtable, &pk, buffer_priv, &pbk, buffer_pub, bits, 0);
	clock_gettime(CLOCK_MONOTONIC, &tend);
        printKeysToFile(&pk,&pbk,i,file, tstart, tend);
    }
    fclose(file);

}


int main(int argc, char * argv[]) {
    generateRSA(1000000,512);
    generateRSA(10000,1024);
    generateRSA(10000,2048);
    return 0;
}	
