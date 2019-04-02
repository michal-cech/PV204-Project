//
// Created by MrMCech on 30.03.2019.
//
#include "BearSSL/inc/bearssl.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "utils.h"

//p, q, dp, dq, iq
// HIGH
static unsigned char private_buffer_high[] = {179, 241, 235, 177, 149, 15, 153, 168, 187, 92, 249, 137, 97, 190, 216, 117, 148, 124, 60, 5, 230, 209, 41, 251, 58, 170, 250, 251, 67, 254, 26, 2, 92, 219, 24, 236, 84, 60, 175, 50, 251, 59, 176, 236, 42, 92, 56, 143, 150, 107, 220, 234, 151, 126, 1, 62, 103, 252, 225, 65, 161, 62, 233, 112, 135, 220, 61, 33, 65, 116, 130, 14, 17, 84, 180, 155, 198, 205, 178, 171, 212, 94, 233, 88, 23, 5, 93, 37, 90, 163, 88, 49, 183, 13, 50, 102, 154, 201, 159, 51, 99, 46, 90, 118, 141, 231, 232, 27, 248, 84, 194, 124, 70, 227, 251, 242, 171, 186, 205, 41, 236, 74, 255, 81, 115, 114, 101, 39,
                                              177, 236, 193, 254, 169, 235, 83, 83, 228, 87, 235, 170, 153, 239, 233, 247, 237, 106, 99, 210, 137, 235, 135, 220, 26, 235, 71, 24, 156, 15, 178, 183, 70, 214, 175, 86, 6, 251, 104, 57, 189, 255, 192, 165, 254, 131, 148, 30, 220, 120, 78, 173, 208, 156, 153, 2, 79, 59, 101, 228, 200, 220, 11, 236, 211, 179, 237, 205, 61, 104, 121, 24, 1, 61, 17, 227, 167, 31, 208, 50, 167, 178, 20, 210, 81, 97, 152, 102, 110, 137, 220, 220, 12, 88, 3, 6, 118, 133, 80, 37, 107, 60, 10, 33, 153, 246, 15, 112, 116, 34, 29, 213, 96, 183, 57, 234, 243, 18, 137, 146, 125, 132, 221, 9, 229, 129, 102, 59,
                                              108, 222, 210, 132, 42, 50, 201, 27, 198, 132, 121, 224, 232, 94, 85, 239, 216, 37, 136, 83, 104, 33, 164, 151, 39, 174, 77, 175, 95, 92, 78, 45, 42, 59, 189, 106, 82, 229, 9, 230, 205, 27, 44, 131, 3, 177, 230, 134, 96, 23, 85, 103, 34, 110, 21, 86, 1, 27, 152, 207, 189, 154, 52, 169, 37, 144, 138, 188, 124, 82, 38, 159, 239, 124, 164, 104, 26, 85, 18, 48,113, 63, 64, 28, 45, 41, 210, 241, 119, 6, 157, 101, 16, 242, 111, 66, 111, 213, 136, 193, 165, 191, 151, 87, 163, 250,226, 75, 217, 25, 128, 84, 116, 67, 175, 252, 35, 60, 40, 218, 79, 121, 165, 167, 207, 21, 1, 151,
                                              114, 80, 112, 190, 201, 47, 237, 202, 152, 31, 192, 181, 113, 144, 244, 14, 174, 144, 136, 182, 4, 205, 144, 41, 48, 89, 42, 141, 110, 55, 101, 127, 119, 140, 153, 245, 138, 97, 181, 113, 120, 235, 84, 44, 81, 170, 252, 144, 226, 87, 221,4, 75, 135, 181, 234, 65, 59, 158, 229, 26, 73, 217, 253, 159, 155, 75, 104, 180, 154, 136, 66, 239, 233, 217, 213, 236,11, 25, 153, 22, 110, 199, 70, 134, 192, 155, 25, 191, 251, 1, 172, 114, 72, 131, 174, 135, 155, 121, 252, 100, 90, 28,202, 91, 77, 198, 7, 4, 164, 84, 204, 37, 156, 82, 169, 227, 0, 142, 108, 189, 161, 47, 136, 126, 226, 108, 247,
                                              42, 2, 1, 211, 19, 173, 193, 146, 190, 82, 165, 9, 94, 163, 249, 137, 45, 186, 108, 253, 26, 170, 75, 199, 18, 86, 131, 187, 226, 63, 68, 97, 254, 159, 104, 187, 42, 186, 253, 118, 255, 235, 255, 230, 24, 163, 145, 71, 6, 232, 17, 185, 100, 60, 49, 65, 248, 41, 226, 115, 27, 23, 220, 76, 46, 119, 251, 245, 199, 30, 144, 235, 121, 58, 241, 133, 213, 138, 39, 102, 157, 1, 219, 249, 49, 124, 28, 151, 58, 67, 147, 101, 168, 234, 46, 243, 174, 74, 168, 177, 27, 225, 47, 251, 33, 55, 226, 167, 123, 4, 231, 86, 98, 216, 45, 188, 228, 197, 249, 113, 59, 136, 244, 205, 55, 170, 0, 60 };

static unsigned char public_buffer_high[]  = {125, 16, 175, 87, 115, 238, 13, 111, 248, 49, 15, 91, 26, 98, 108, 56, 202, 156, 8, 200, 19, 151, 142, 65, 51, 117, 225, 96, 139, 195, 86, 149, 56, 165, 89, 4, 106, 104, 58, 248, 220, 197, 133, 23, 164, 78, 90, 76, 131, 124, 61, 181, 169, 133, 35, 226, 71, 238, 187, 69, 3, 35, 74, 121, 63, 173, 83, 28, 217, 122, 0, 168, 144, 126, 82, 6, 162, 81, 148, 83, 246, 168, 110, 193, 216, 195, 138, 208, 86, 126, 55, 33, 171, 151, 100, 162, 59, 5, 170, 226, 29, 246, 18, 181, 161, 58, 181, 205, 174, 3, 89, 71, 81, 78, 249, 142, 230, 21, 121, 183, 153, 165, 102, 127, 202, 54, 185, 180, 197, 197, 231, 230, 102, 105, 160, 212, 222, 202, 82, 206, 209, 123, 63, 72, 205, 67, 13, 240, 122, 250, 238, 221, 231, 170, 70, 179, 105, 206, 177, 156, 220, 54, 35, 100, 141, 126, 2, 11, 117, 91, 209, 61, 192, 9, 70, 133, 83, 3, 160, 91, 120, 28, 143, 94, 217, 106, 34, 105, 160, 38, 154, 130, 211, 26, 244, 63, 72, 87, 179, 234, 222, 70, 150, 221, 129, 143, 170, 35, 12, 251, 210, 92, 15, 156, 128, 217, 182, 44, 197, 59, 171, 5, 218, 94, 97, 240, 219, 50, 58, 153, 229, 3, 8, 145, 206, 159, 223, 221, 223, 185, 220, 48, 76, 191, 141, 211, 97, 34, 222, 200, 6, 69, 11, 81, 217, 253,
                                              52, 220, 152, 212, 220, 52, 149, 245, 126, 184, 18, 212, 196, 219, 208, 84, 83, 39, 247, 255, 234, 119, 219, 14, 30, 98, 192, 225, 241, 34, 143, 167, 101, 59, 122, 187, 236, 94, 60, 164, 21, 190, 142, 32, 12, 52, 134, 235, 17, 116, 135, 7, 232, 209, 172, 121, 218, 9, 209, 192, 90, 248, 125, 199, 49, 37, 170, 91, 151, 135, 126, 170, 230, 49, 169, 91, 240, 36, 215, 129, 68, 97, 151, 205, 255, 206, 31, 197, 80, 44, 160, 103, 139, 97, 3, 83, 35, 189, 215, 134, 8, 163, 252, 107, 73, 17, 37, 21, 214, 170, 74, 29, 142, 40, 151, 7, 16, 212, 113, 136, 225, 158, 123, 233, 153, 15, 0, 188, 245, 48, 223, 53, 135, 46, 189, 49, 26, 194, 189, 2, 48, 24, 150, 224, 2, 235, 219, 113, 82, 229, 57, 77, 232, 120, 168, 147, 169, 49, 248, 131, 138, 240, 74, 42, 107, 103, 244, 178, 162, 187, 156, 118, 85, 166, 107, 189, 185, 89, 22, 34, 233, 56, 234, 129, 146, 121, 71, 95, 192, 222, 111, 233, 50, 157, 101, 168, 214, 232, 218, 231, 175, 43, 3, 78, 38, 109, 156, 88, 106, 187, 170, 113, 14, 10, 30, 172, 88, 143, 58, 99, 153, 3, 92, 228, 220, 42, 170, 109, 80, 79, 142, 235, 31, 235, 25, 170, 202, 95, 159, 227, 89, 174, 15, 172, 206, 219, 47, 14, 217, 245, 201, 210, 27, 176, 174, 239 };
//LOW
static unsigned char private_buffer_low[] = {179, 241, 235, 177, 149, 15, 153, 168, 187, 92, 249, 137, 97, 190, 216, 117, 148, 124, 60, 5, 230, 209, 41, 251, 58, 170, 250, 251, 67, 254, 26, 2, 92, 219, 24, 236, 84, 60, 175, 50, 251, 59, 176, 236, 42, 92, 56, 143, 150, 107, 220, 234, 151, 126, 1, 62, 103, 252, 225, 65, 161, 62, 233, 112, 135, 220, 61, 33, 65, 116, 130, 14, 17, 84, 180, 155, 198, 205, 178, 171, 212, 94, 233, 88, 23, 5, 93, 37, 90, 163, 88, 49, 183, 13, 50, 102, 154, 201, 159, 51, 99, 46, 90, 118, 141, 231, 232, 27, 248, 84, 194, 124, 70, 227, 251, 242, 171, 186, 205, 41, 236, 74, 255, 81, 115, 114, 101, 39,
                                             177, 236, 193, 254, 169, 235, 83, 83, 228, 87, 235, 170, 153, 239, 233, 247, 237, 106, 99, 210, 137, 235, 135, 220, 26, 235, 71, 24, 156, 15, 178, 183, 70, 214, 175, 86, 6, 251, 104, 57, 189, 255, 192, 165, 254, 131, 148, 30, 220, 120, 78, 173, 208, 156, 153, 2, 79, 59, 101, 228, 200, 220, 11, 236, 211, 179, 237, 205, 61, 104, 121, 24, 1, 61, 17, 227, 167, 31, 208, 50, 167, 178, 20, 210, 81, 97, 152, 102, 110, 137, 220, 220, 12, 88, 3, 6, 118, 133, 80, 37, 107, 60, 10, 33, 153, 246, 15, 112, 116, 34, 29, 213, 96, 183, 57, 234, 243, 18, 137, 146, 125, 132, 221, 9, 229, 129, 102, 59,
                                             16, 215, 7, 184, 8, 58, 148, 214, 218, 116, 212, 252, 96, 0, 145, 64, 49, 65, 153, 36, 215, 72, 124, 161, 134, 151, 143, 120, 37, 121, 193, 8, 174, 170, 225, 213, 158, 176, 42, 176, 207, 149, 213, 126, 52, 19, 85, 203, 56, 79, 220, 28, 239, 177, 97, 201, 231, 44, 93, 137, 63, 136, 207, 243, 130, 163, 5, 73, 104, 155, 175, 146, 10, 65, 249, 227, 70, 153, 157, 177, 186, 1, 184, 218, 78, 163, 154, 198, 234, 246, 155, 140, 208, 203, 190, 47, 53, 95, 31, 97, 166, 118, 55, 19, 170, 212, 195, 101, 158, 227, 235, 2, 216, 228, 75, 69, 69, 12, 30, 26, 6, 59, 19, 216, 50, 125, 167, 13,
                                             66, 180, 77, 12, 178, 100, 247, 123, 239, 209, 218, 241, 33, 79, 19, 222, 134, 132, 11, 253, 214, 212, 56, 77, 161, 217, 0, 176, 234, 62, 194, 62, 155, 105, 63, 228, 197, 234, 192, 18, 1, 252, 136, 66, 24, 224, 198, 186, 58, 153, 25, 84, 91, 184, 255, 145, 236, 56, 79, 252, 169, 253, 182, 166, 34, 198, 180, 197, 61, 226, 111, 14, 83, 255, 239, 247, 140, 112, 246, 235, 251, 28, 242, 40, 116, 236, 25, 251, 80, 233, 101, 243, 120, 236, 28, 210, 156, 15, 96, 16, 120, 76, 42, 139, 183, 98, 205, 61, 27, 39, 56, 67, 220, 245, 226, 54, 182, 29, 38, 22, 139, 137, 161, 43, 94, 214, 88, 179,
                                             42, 2, 1, 211, 19, 173, 193, 146, 190, 82, 165, 9, 94, 163, 249, 137, 45, 186, 108, 253, 26, 170, 75, 199, 18, 86, 131, 187, 226, 63, 68, 97, 254, 159, 104, 187, 42, 186, 253, 118, 255, 235, 255, 230, 24, 163, 145, 71, 6, 232, 17, 185, 100, 60, 49, 65, 248, 41, 226, 115, 27, 23, 220, 76, 46, 119, 251, 245, 199, 30, 144, 235, 121, 58, 241, 133, 213, 138, 39, 102, 157, 1, 219, 249, 49, 124, 28, 151, 58, 67, 147, 101, 168, 234, 46, 243, 174, 74, 168, 177, 27, 225, 47, 251, 33, 55, 226, 167, 123, 4, 231, 86, 98, 216, 45, 188, 228, 197, 249, 113, 59, 136, 244, 205, 55, 170, 0, 60 };

static unsigned char public_buffer_low[] = {125, 16, 175, 87, 115, 238, 13, 111, 248, 49, 15, 91, 26, 98, 108, 56, 202, 156, 8, 200, 19, 151, 142, 65, 51, 117, 225, 96, 139, 195, 86, 149, 56, 165, 89, 4, 106, 104, 58, 248, 220, 197, 133, 23, 164, 78, 90, 76, 131, 124, 61, 181, 169, 133, 35, 226, 71, 238, 187, 69, 3, 35, 74, 121, 63, 173, 83, 28, 217, 122, 0, 168, 144, 126, 82, 6, 162, 81, 148, 83, 246, 168, 110, 193, 216, 195, 138, 208, 86, 126, 55, 33, 171, 151, 100, 162, 59, 5, 170, 226, 29, 246, 18, 181, 161, 58, 181, 205, 174, 3, 89, 71, 81, 78, 249, 142, 230, 21, 121, 183, 153, 165, 102, 127, 202, 54, 185, 180, 197, 197, 231, 230, 102, 105, 160, 212, 222, 202, 82, 206, 209, 123, 63, 72, 205, 67, 13, 240, 122, 250, 238, 221, 231, 170, 70, 179, 105, 206, 177, 156, 220, 54, 35, 100, 141, 126, 2, 11, 117, 91, 209, 61, 192, 9, 70, 133, 83, 3, 160, 91, 120, 28, 143, 94, 217, 106, 34, 105, 160, 38, 154, 130, 211, 26, 244, 63, 72, 87, 179, 234, 222, 70, 150, 221, 129, 143, 170, 35, 12, 251, 210, 92, 15, 156, 128, 217, 182, 44, 197, 59, 171, 5, 218, 94, 97, 240, 219, 50, 58, 153, 229, 3, 8, 145, 206, 159, 223, 221, 223, 185, 220, 48, 76, 191, 141, 211, 97, 34, 222, 200, 6, 69, 11, 81, 217, 253,
                                            95, 220, 12, 23, 61, 49, 69, 230, 231, 48, 58, 187, 176, 98, 125, 87, 25, 192, 210, 120, 188, 209, 97, 108, 113, 226, 203, 247, 156, 182, 178, 197, 206, 41, 58, 197, 25, 71, 14, 153, 140, 47, 115, 205, 230, 251, 210, 111, 189, 171, 206, 185, 241, 99, 226, 67, 64, 231, 152, 107, 191, 82, 242, 201, 166, 3, 40, 33, 170, 0, 93, 173, 126, 65, 36, 195, 204, 8, 179, 146, 51, 99, 220, 57, 202, 130, 206, 82, 231, 232, 168, 255, 235, 144, 241, 139, 42, 197, 132, 190, 148, 133, 138, 51, 19, 19, 47, 246, 226, 80, 10, 91, 214, 202, 90, 12, 186, 218, 185, 55, 50, 122, 164, 144, 126, 56, 117, 3, 42, 177, 255, 247, 52, 16, 88, 128, 44, 102, 44, 18, 112, 202, 66, 19, 51, 129, 168, 243, 255, 107, 58, 38, 51, 233, 155, 199, 75,22, 107, 221, 108, 240, 150, 175, 168, 217, 96, 238, 223, 128, 248, 227, 15, 124, 241, 27, 183, 11, 248, 82, 227, 40, 184, 80, 121, 74, 50, 34, 97, 106, 108, 124, 91, 14, 123, 44, 178, 170, 217, 135, 31, 63, 55, 150, 6, 195, 20, 72, 198, 81, 114, 229, 73, 19, 117, 41, 243, 113, 246, 196, 151, 4, 205, 14, 167, 2, 46, 27, 44, 96, 45, 84, 235, 126, 18, 58, 18,177, 254, 0, 121, 40, 52, 176, 125, 18, 153, 97, 220, 35, 120, 11, 151, 168, 100, 241 };


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

void generateHighRSA(br_rsa_private_key *pk, br_rsa_public_key * pbk) {
    pk->p = private_buffer_high;
    pk->plen = 128;
    pk->q = private_buffer_high + 128;
    pk->qlen = 128;
    pk->iq = private_buffer_high + 128*4;
    pk->iqlen = 128;
    pk->dp = private_buffer_high + 128*2;
    pk->dplen = 128;
    pk->dq = private_buffer_high + 128*3;
    pk->dqlen = 128;
    pk->n_bitlen = 2048;

    pbk->e = public_buffer_high + 256;
    pbk->elen = 256;
    pbk->n = public_buffer_high;
    pbk->nlen = 256;
}

void generateLowRSA(br_rsa_private_key *pk, br_rsa_public_key * pbk) {
    pk->p = private_buffer_low;
    pk->plen = 128;
    pk->q = private_buffer_low + 128;
    pk->qlen = 128;
    pk->iq = private_buffer_low + 128*4;
    pk->iqlen = 128;
    pk->dp = private_buffer_low + 128*2;
    pk->dplen = 128;
    pk->dq = private_buffer_low+ 128*3;
    pk->dqlen = 128;
    pk->n_bitlen = 2048;

    pbk->e = public_buffer_low + 256;
    pbk->elen = 256;
    pbk->n = public_buffer_low;
    pbk->nlen = 256;
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

    FILE *  file = fopen("rsa_random_message_sig.txt", "w");
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

    FILE *  file = fopen("rsa_random_exp_sig.txt", "w");
    fprintf(file,"ID;HW;LENGTH;TIME\n");
    for (int i = 0; i < tries; i++) {
        br_rsa_private_key pk;
        br_rsa_public_key pbk;
        unsigned char buffer_priv[BR_RSA_KBUF_PRIV_SIZE(bits)];
        unsigned char buffer_pub[BR_RSA_KBUF_PUB_SIZE(bits)];
        generateRSA(ctx, &pk, &pbk, buffer_priv, buffer_pub, bits);

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
    unsigned char *buffer_priv = calloc(BR_RSA_KBUF_PRIV_SIZE(bits), sizeof(unsigned char));

    unsigned char * buffer_pub = calloc(BR_RSA_KBUF_PUB_SIZE(bits), sizeof(unsigned char));

    br_rsa_private_key pk;
    br_rsa_public_key pbk;

    generateRSA(ctx,&pk, &pbk, buffer_priv, buffer_pub, bits);

    struct timespec tstart={0,0}, tend={0,0};
    // FIXED EXPONENT, RANDOM MESSAGES
    FILE *  file = fopen("rsa_random_msg_dec.txt", "w");
    fprintf(file,"ID;HW;LENGTH;TIME\n");
    for (int i = 0; i < tries; i++) {
        size_t bytes = (size_t) rand() % 190;
        unsigned char encMessage[bytes];
        for (int j = 0; j < bytes; j++) {
            encMessage[j] = (unsigned char) (rand() % 256);
        }
        int hW = hammingWeight(encMessage, bytes);
        encryptDecrypt(ctx, &pk, &pbk,encMessage, bytes, i, &tstart, &tend );
        fprintf(file, "%d;%d;%u;",i,hW,bytes);
        fprintf(file,"%.5f ns;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);

    }
    free(buffer_priv);
    free(buffer_pub);
    fclose(file);
}

void fixedMessageRandomExpRSA(br_hmac_drbg_context* ctx, size_t tries, size_t bits) {
    struct timespec tstart={0,0}, tend={0,0};

    FILE *  file = fopen("rsa_random_exp_dec.txt", "w");
    fprintf(file,"ID;HW;TIME\n");

    size_t bytes = 190;
    unsigned char encMessage[bytes];
    for (int j = 0; j < bytes; j++) {
        encMessage[j] = (unsigned char) (rand() % 256);
    }

    for (int i = 0; i < tries; i++) {
        br_rsa_private_key pk;
        br_rsa_public_key pbk;
        unsigned char buffer_priv[BR_RSA_KBUF_PRIV_SIZE(bits)];
        unsigned char buffer_pub[BR_RSA_KBUF_PUB_SIZE(bits)];
        generateRSA(ctx, &pk, &pbk, buffer_priv, buffer_pub, bits);
        br_rsa_compute_pubexp pubFun = br_rsa_compute_pubexp_get_default();
        uint32_t pubExp = pubFun(&pk);

        br_rsa_compute_privexp privFun = br_rsa_compute_privexp_get_default();
        size_t privLength = privFun(NULL,&pk, pubExp);

        unsigned char privExp[privLength];
        privFun(privExp,&pk,pubExp);

        int hW = hammingWeight(privExp, bytes);

        encryptDecrypt(ctx, &pk, &pbk,encMessage, bytes, i, &tstart, &tend );

        fprintf(file, "%d;%d;",i,hW);
        fprintf(file,"%.5f ns;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);
    }
    fclose(file);
}

void highHammingWeightRSADec(br_hmac_drbg_context* ctx, size_t tries) {
/*
    size_t prime_size = (sizeof(prvlow) - 1) / 2;
    unsigned char dest[prime_size];
    hexStringToByteArray(prvlow, dest, prime_size);
    */


    struct timespec tstart={0,0}, tend={0,0};
    br_rsa_private_key pk;
    br_rsa_public_key pbk;
    generateHighRSA(&pk, &pbk);
    size_t bytes = 190;
    unsigned char encMessage[] = "Testovaci zprava";

    FILE *  file = fopen("rsa_high_hw_dec.txt", "w");
    fprintf(file,"ID;TIME\n");
    for (int i = 0; i < tries; i++) {
        encryptDecrypt(ctx, &pk, &pbk,encMessage, bytes, i, &tstart, &tend );
        fprintf(file, "%d;",i);
        fprintf(file,"%.5f ns;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);

    }
    fclose(file);
}


void highHammingWeightRSASign(br_hmac_drbg_context* ctx, size_t tries) {
    struct timespec tstart={0,0}, tend={0,0};
    size_t hashLength = 64;
    br_rsa_private_key pk;
    br_rsa_public_key pbk;
    generateHighRSA(&pk, &pbk);

    br_sha512_context ctn;
    br_sha512_init(&ctn);

    unsigned char hashedMsg[] = "Testovaci zprava";
    size_t length = sizeof(hashedMsg);

    br_sha512_update(&ctn, hashedMsg, length);
    unsigned char hash[hashLength];
    br_sha512_out(&ctn, hash);

    FILE *  file = fopen("rsa_high_hw_sign.txt", "w");
    fprintf(file,"ID;TIME\n");

    for (int i = 0; i < tries; i++) {
        signRSA(ctx, &pk, &pbk, hash, hashLength, i, &tstart, &tend);
        fprintf(file, "%d;",i);
        fprintf(file,"%.5f ns;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);
    }
    fclose(file);
}

void lowHammingWeightRSADec(br_hmac_drbg_context* ctx, size_t tries) {

    struct timespec tstart={0,0}, tend={0,0};
    br_rsa_private_key pk;
    br_rsa_public_key pbk;
    generateLowRSA(&pk, &pbk);

    size_t bytes = 190;
    unsigned char encMessage[] = "Testovaci zprava";

    FILE *  file = fopen("rsa_low_hw_dec.txt", "w");
    fprintf(file,"ID;TIME\n");
    for (int i = 0; i < tries; i++) {
        encryptDecrypt(ctx, &pk, &pbk,encMessage, bytes, i, &tstart, &tend );
        fprintf(file, "%d;",i);
        fprintf(file,"%.5f ns;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);

    }
    fclose(file);
}

void lowHammingWeightRSASign(br_hmac_drbg_context* ctx, size_t tries) {
    struct timespec tstart={0,0}, tend={0,0};
    size_t hashLength = 64;
    br_rsa_private_key pk;
    br_rsa_public_key pbk;
    generateLowRSA(&pk, &pbk);

    br_sha512_context ctn;
    br_sha512_init(&ctn);

    unsigned char hashedMsg[] = "Testovaci zprava";
    size_t length = sizeof(hashedMsg);

    br_sha512_update(&ctn, hashedMsg, length);
    unsigned char hash[hashLength];
    br_sha512_out(&ctn, hash);

    FILE *  file = fopen("rsa_low_hw_sign.txt", "w");
    fprintf(file,"ID;TIME\n");

    for (int i = 0; i < tries; i++) {
        signRSA(ctx, &pk, &pbk, hash, hashLength, i, &tstart, &tend);
        fprintf(file, "%d;",i);
        fprintf(file,"%.5f ns;\n",
                (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec))*1.0e9);
    }
    fclose(file);
}
