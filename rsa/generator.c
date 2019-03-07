#include "BearSSL/inc/bearssl.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
void printKeysToFile(br_rsa_private_key* pk, br_rsa_public_key* pbk, int counter, FILE* file, struct timespec t1, struct timespec t2) {
    fprintf(file, "%d;",counter);
    for (size_t i = 0; i < pbk->nlen; i++ ) {
        fprintf(file, "%02hhX", pbk->n[i]);
    }
    fprintf(file,";");
    fprintf(file,"%u;",*pbk->e);
    for (size_t i = 0; i < pk->plen; i++ ) {
        fprintf(file, "%02hhX", pk->p[i]);
    }
    fprintf(file,";");
    for (size_t i = 0; i < pk->qlen; i++ ) {
        fprintf(file, "%02hhX", pk->q[i]);
    }
    fprintf(file,";");
    fprintf(file,"%.5f\n;",
           ((double)t2.tv_sec + 1.0e-9*t2.tv_nsec) - 
           ((double)t1.tv_sec + 1.0e-9*t1.tv_nsec));
}
void generateRSA(int number, unsigned int bits) {
    //prepare PRNG
    br_hmac_drbg_context ctx;
    br_hmac_drbg_init(&ctx, &br_sha256_vtable, NULL, 0);

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
    generateRSA(100,512);
    generateRSA(100,1024);
    generateRSA(100,2048);
    return 0;
}	
