#include "../BearSSL/inc/bearssl.h"


#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#ifdef linux
#include <dlfcn.h>
    int dll_handle = dlopen(PKCS11_DLL)
#endif
#ifdef __WIN32
    #include <windows.h>
#endif

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

int encryptDemo(br_rsa_public_key * pk, br_rsa_private_key * sk) {
    br_hmac_drbg_context ctx;
    prepareRNG(&ctx);
    unsigned char encMessage[] ="Demo";
    size_t messageLength = sizeof(encMessage);
    unsigned char dest[256];
    size_t encrypted;
    if ((encrypted = br_rsa_i31_oaep_encrypt(&(ctx.vtable),ctx.digest_class, NULL, 0, pk, dest, 256, encMessage, messageLength)) == 0) {
        return 0;
    }

    if (br_rsa_token_oaep_decrypt(ctx.digest_class,NULL,0,sk,dest,&encrypted)) {
        return 1;
    } else {
        return 0;
    }

}

int signDemo(br_rsa_public_key * pk, br_rsa_private_key * sk) {
    br_sha512_context ctn;
    br_sha512_init(&ctn);

    unsigned char message[] = "Message for signing!";

    size_t message_len = sizeof(message);
    size_t hash_len = 64;

    unsigned char hash[64] = {0};
    unsigned char sign[256] = {0};

    const unsigned char *hash_oid = BR_HASH_OID_SHA512;

    br_sha512_update(&ctn, message, message_len);
    br_sha512_out(&ctn, hash);

    //SIGN
    br_rsa_token_pkcs1_sign(hash_oid, hash, hash_len, sk, sign);
    unsigned char hash_out[hash_len];
    if (!br_rsa_i31_pkcs1_vrfy(sign, 256, hash_oid, hash_len, pk, hash_out)) {
        return 0;
    } else {
        return 1;
    }
}


int main(int argc, char * argv[]) {
    br_rsa_private_key sk;
    br_rsa_public_key pk;
    int bitSize = 2048;

    unsigned char token[] = "token";
    unsigned char label[] = "test_token";
    unsigned char pin[] = "123456";
    unsigned char id[] = "my_key";
    size_t labelSize = sizeof(label);
    size_t pinSize = sizeof(pin);
    size_t tokenSize = sizeof(token);
    size_t idSize = sizeof(id);

    unsigned char privateBuffer[labelSize + pinSize + tokenSize + idSize];
    memcpy(privateBuffer,token, tokenSize);
    sk.plen = tokenSize;
    sk.p = privateBuffer;

    memcpy(privateBuffer + sk.plen, label, labelSize);
    sk.dplen = labelSize;
    sk.dp = privateBuffer + sk.plen;

    memcpy(privateBuffer + sk.plen + sk.dplen, pin, pinSize );
    sk.dqlen = pinSize;
    sk.dq = privateBuffer + tokenSize + labelSize;

    memcpy(privateBuffer + sk.plen + sk.dplen + sk.dqlen, id, idSize);
    sk.iqlen = idSize;
    sk.iq = privateBuffer + tokenSize + labelSize + pinSize;

    sk.n_bitlen = bitSize;

    unsigned char publicBuffer[BR_RSA_KBUF_PUB_SIZE(bitSize)];
    br_rsa_token_keygen(NULL,&sk,privateBuffer,&pk,publicBuffer,bitSize, 3);
    //ENCRYPT DEMO
//    encryptDemo(&pk, &sk);
    //SIGN RSA DEMO
    signDemo(&pk, &sk);

}
