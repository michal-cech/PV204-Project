#include "BearSSL/bearssl.h"
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
    fprintf(file,"%ld.%09ld\n", (long)(t2.tv_sec - t1.tv_sec),
           t2.tv_nsec - t1.tv_nsec);
    fprintf(file,"\n");
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
    struct timespec t1, t2;
    for (int i = 0; i < number; i++) {
        clock_gettime(CLOCK_REALTIME, &t1);
        keygen(&ctx.vtable, &pk, buffer_priv, &pbk, buffer_pub, bits, 0);
        clock_gettime(CLOCK_REALTIME, &t2);
        if (t2.tv_nsec < t1.tv_nsec) {
            t2.tv_nsec += 1000000000;
            t2.tv_sec--;
        }
        printKeysToFile(&pk,&pbk,i,file, t1, t2);
    }
    fclose(file);

}


int main(int argc, char * argv[]) {
    generateRSA(1000000,512);
    generateRSA(10000,1024);
    generateRSA(10000,2048);
    return 0;
}	
