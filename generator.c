#include "bearssl.h"
#include <stdlib.h>
#include <stdio.h>

void initRandomGenerator(br_prng_class ** prng) {
    br_hmac_drbg_context* ctx;
    br_hmac_drbg_init(ctx, &br_sha256_vtable, NULL, NULL);
}


int main(int argc, char * argv[]) {
    br_prng_class * prng;
    initRandomGenerator(&prng);
    return 0;
}	
