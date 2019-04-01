//
// Created by MrMCech on 30.03.2019.
//
#include "BearSSL/inc/bearssl.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "utils.h"

//static const unsigned char high_prime_p[] = "B3F1EBB1950F99A8BB5CF98961BED875947C3C05E6D129FB3AAAFAFB43FE1A025CDB18EC543CAF32FB3BB0EC2A5C388F966BDCEA977E013E67FCE141A13EE97087DC3D214174820E1154B49BC6CDB2ABD45EE95817055D255AA35831B70D32669AC99F33632E5A768DE7E81BF854C27C46E3FBF2ABBACD29EC4AFF5173726527";
//static const unsigned char high_prime_q[] = "B1ECC1FEA9EB5353E457EBAA99EFE9F7ED6A63D289EB87DC1AEB47189C0FB2B746D6AF5606FB6839BDFFC0A5FE83941EDC784EADD09C99024F3B65E4C8DC0BECD3B3EDCD3D687918013D11E3A71FD032A7B214D2516198666E89DCDC0C580306768550256B3C0A2199F60F7074221DD560B739EAF31289927D84DD09E581663B";
//static const unsigned char high_pk[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
//static const unsigned char high_pbk[] = "34DC98D4DC3495F57EB812D4C4DBD0545327F7FFEA77DB0E1E62C0E1F1228FA7653B7ABBEC5E3CA415BE8E200C3486EB11748707E8D1AC79DA09D1C05AF87DC73125AA5B97877EAAE631A95BF024D781446197CDFFCE1FC5502CA0678B61035323BDD78608A3FC6B49112515D6AA4A1D8E28970710D47188E19E7BE9990F00BCF530DF35872EBD311AC2BD02301896E002EBDB7152E5394DE878A893A931F8838AF04A2A6B67F4B2A2BB9C7655A66BBDB9591622E938EA819279475FC0DE6FE9329D65A8D6E8DAE7AF2B034E266D9C586ABBAA710E0A1EAC588F3A6399035CE4DC2AAA6D504F8EEB1FEB19AACA5F9FE359AE0FACCEDB2F0ED9F5C9D21BB0AEEF";
//static const unsigned char high_modulus[] = "7D10AF5773EE0D6FF8310F5B1A626C38CA9C08C813978E413375E1608BC3569538A559046A683AF8DCC58517A44E5A4C837C3DB5A98523E247EEBB4503234A793FAD531CD97A00A8907E5206A2519453F6A86EC1D8C38AD0567E3721AB9764A23B05AAE21DF612B5A13AB5CDAE035947514EF98EE61579B799A5667FCA36B9B4C5C5E7E66669A0D4DECA52CED17B3F48CD430DF07AFAEEDDE7AA46B369CEB19CDC3623648D7E020B755BD13DC00946855303A05B781C8F5ED96A2269A0269A82D31AF43F4857B3EADE4696DD818FAA230CFBD25C0F9C80D9B62CC53BAB05DA5E61F0DB323A99E5030891CE9FDFDDDFB9DC304CBF8DD36122DEC806450B51D9FD";
//static const unsigned char high_dp[] = "688F6BC3D38AE9C0AC35CD06BA0703BF5DF71FCD1AC50F65568E318B5F7BBB74E11970B72F82D8A09B9D8CFB105A68A9C7565DE3ADE58D505604D8B69AAA2DF2D0F2BD7EFFD1478A17BAC0B39FDC3FEF3CC35805E69FC436B3A563F6FD91E5C6B5955CBD49D322F096156F63906627478D6DB93F7775CF65AA4BBB0DB01ECB69";
//static const unsigned char high_dq[] = "65D41D9A0EE7579F698C9650019673FD0BA7742B761157B52A25F03BEEC2306D7FC2E265F22A76EDD4EFBC32F4A79E92CF1322895E26A2C9F67BD7DCF664B61FF6F2EC5113EC6697C289C6E3CB3575B69596C6D32FCDC22FB218D91F876E28746AFBEFE1C7B51A3773D561B8AA06BB1528B227FB15A7DD585F5EC619C0E46519";
//static const unsigned char high_iq[] = "2A0201D313ADC192BE52A5095EA3F9892DBA6CFD1AAA4BC7125683BBE23F4461FE9F68BB2ABAFD76FFEBFFE618A3914706E811B9643C3141F829E2731B17DC4C2E77FBF5C71E90EB793AF185D58A27669D01DBF9317C1C973A439365A8EA2EF3AE4AA8B11BE12FFB2137E2A77B04E75662D82DBCE4C5F9713B88F4CD37AA003C";

static const unsigned char high_dp2[] = "6CDED2842A32C91BC68479E0E85E55EFD82588536821A49727AE4DAF5F5C4E2D2A3BBD6A52E509E6CD1B2C8303B1E68660175567226E1556011B98CFBD9A34A925908ABC7C52269FEF7CA4681A551230713F401C2D29D2F177069D6510F26F426FD588C1A5BF9757A3FAE24BD91980547443AFFC233C28DA4F79A5A7CF150197";
static const unsigned char high_dq2[] = "725070BEC92FEDCA981FC0B57190F40EAE9088B604CD902930592A8D6E37657F778C99F58A61B57178EB542C51AAFC90E257DD044B87B5EA413B9EE51A49D9FD9F9B4B68B49A8842EFE9D9D5EC0B1999166EC74686C09B19BFFB01AC724883AE879B79FC645A1CCA5B4DC60704A454CC259C52A9E3008E6CBDA12F887EE26CF7";


//p, q, dp, dq, iq

static unsigned char private_buffer_high[] = {179, 241, 235, 177, 149, 15, 153, 168, 187, 92, 249, 137, 97, 190, 216, 117, 148, 124, 60, 5, 230, 209, 41, 251, 58, 170, 250, 251, 67, 254, 26, 2, 92, 219, 24, 236, 84, 60, 175, 50, 251, 59, 176, 236, 42, 92, 56, 143, 150, 107, 220, 234, 151, 126, 1, 62, 103, 252, 225, 65, 161, 62, 233, 112, 135, 220, 61, 33, 65, 116, 130, 14, 17, 84, 180, 155, 198, 205, 178, 171, 212, 94, 233, 88, 23, 5, 93, 37, 90, 163, 88, 49, 183, 13, 50, 102, 154, 201, 159, 51, 99, 46, 90, 118, 141, 231, 232, 27, 248, 84, 194, 124, 70, 227, 251, 242, 171, 186, 205, 41, 236, 74, 255, 81, 115, 114, 101, 39,
                                              177, 236, 193, 254, 169, 235, 83, 83, 228, 87, 235, 170, 153, 239, 233, 247, 237, 106, 99, 210, 137, 235, 135, 220, 26, 235, 71, 24, 156, 15, 178, 183, 70, 214, 175, 86, 6, 251, 104, 57, 189, 255, 192, 165, 254, 131, 148, 30, 220, 120, 78, 173, 208, 156, 153, 2, 79, 59, 101, 228, 200, 220, 11, 236, 211, 179, 237, 205, 61, 104, 121, 24, 1, 61, 17, 227, 167, 31, 208, 50, 167, 178, 20, 210, 81, 97, 152, 102, 110, 137, 220, 220, 12, 88, 3, 6, 118, 133, 80, 37, 107, 60, 10, 33, 153, 246, 15, 112, 116, 34, 29, 213, 96, 183, 57, 234, 243, 18, 137, 146, 125, 132, 221, 9, 229, 129, 102, 59,
                                              108, 222, 210, 132, 42, 50, 201, 27, 198, 132, 121, 224, 232, 94, 85, 239, 216, 37, 136, 83, 104, 33, 164, 151, 39, 174, 77, 175, 95, 92, 78, 45, 42, 59, 189, 106, 82, 229, 9, 230, 205, 27, 44, 131, 3, 177, 230, 134, 96, 23, 85, 103, 34, 110, 21, 86, 1, 27, 152, 207, 189, 154, 52, 169, 37, 144, 138, 188, 124, 82, 38, 159, 239, 124, 164, 104, 26, 85, 18, 48,113, 63, 64, 28, 45, 41, 210, 241, 119, 6, 157, 101, 16, 242, 111, 66, 111, 213, 136, 193, 165, 191, 151, 87, 163, 250,226, 75, 217, 25, 128, 84, 116, 67, 175, 252, 35, 60, 40, 218, 79, 121, 165, 167, 207, 21, 1, 151,
                                              114, 80, 112, 190, 201, 47, 237, 202, 152, 31, 192, 181, 113, 144, 244, 14, 174, 144, 136, 182, 4, 205, 144, 41, 48, 89, 42, 141, 110, 55, 101, 127, 119, 140, 153, 245, 138, 97, 181, 113, 120, 235, 84, 44, 81, 170, 252, 144, 226, 87, 221,4, 75, 135, 181, 234, 65, 59, 158, 229, 26, 73, 217, 253, 159, 155, 75, 104, 180, 154, 136, 66, 239, 233, 217, 213, 236,11, 25, 153, 22, 110, 199, 70, 134, 192, 155, 25, 191, 251, 1, 172, 114, 72, 131, 174, 135, 155, 121, 252, 100, 90, 28,202, 91, 77, 198, 7, 4, 164, 84, 204, 37, 156, 82, 169, 227, 0, 142, 108, 189, 161, 47, 136, 126, 226, 108, 247,
                                              42, 2, 1, 211, 19, 173, 193, 146, 190, 82, 165, 9, 94, 163, 249, 137, 45, 186, 108, 253, 26, 170, 75, 199, 18, 86, 131, 187, 226, 63, 68, 97, 254, 159, 104, 187, 42, 186, 253, 118, 255, 235, 255, 230, 24, 163, 145, 71, 6, 232, 17, 185, 100, 60, 49, 65, 248, 41, 226, 115, 27, 23, 220, 76, 46, 119, 251, 245, 199, 30, 144, 235, 121, 58, 241, 133, 213, 138, 39, 102, 157, 1, 219, 249, 49, 124, 28, 151, 58, 67, 147, 101, 168, 234, 46, 243, 174, 74, 168, 177, 27, 225, 47, 251, 33, 55, 226, 167, 123, 4, 231, 86, 98, 216, 45, 188, 228, 197, 249, 113, 59, 136, 244, 205, 55, 170, 0, 60 };

static unsigned char public_buffer_high[]  = {125, 16, 175, 87, 115, 238, 13, 111, 248, 49, 15, 91, 26, 98, 108, 56, 202, 156, 8, 200, 19, 151, 142, 65, 51, 117, 225, 96, 139, 195, 86, 149, 56, 165, 89, 4, 106, 104, 58, 248, 220, 197, 133, 23, 164, 78, 90, 76, 131, 124, 61, 181, 169, 133, 35, 226, 71, 238, 187, 69, 3, 35, 74, 121, 63, 173, 83, 28, 217, 122, 0, 168, 144, 126, 82, 6, 162, 81, 148, 83, 246, 168, 110, 193, 216, 195, 138, 208, 86, 126, 55, 33, 171, 151, 100, 162, 59, 5, 170, 226, 29, 246, 18, 181, 161, 58, 181, 205, 174, 3, 89, 71, 81, 78, 249, 142, 230, 21, 121, 183, 153, 165, 102, 127, 202, 54, 185, 180, 197, 197, 231, 230, 102, 105, 160, 212, 222, 202, 82, 206, 209, 123, 63, 72, 205, 67, 13, 240, 122, 250, 238, 221, 231, 170, 70, 179, 105, 206, 177, 156, 220, 54, 35, 100, 141, 126, 2, 11, 117, 91, 209, 61, 192, 9, 70, 133, 83, 3, 160, 91, 120, 28, 143, 94, 217, 106, 34, 105, 160, 38, 154, 130, 211, 26, 244, 63, 72, 87, 179, 234, 222, 70, 150, 221, 129, 143, 170, 35, 12, 251, 210, 92, 15, 156, 128, 217, 182, 44, 197, 59, 171, 5, 218, 94, 97, 240, 219, 50, 58, 153, 229, 3, 8, 145, 206, 159, 223, 221, 223, 185, 220, 48, 76, 191, 141, 211, 97, 34, 222, 200, 6, 69, 11, 81, 217, 253,
                                              52, 220, 152, 212, 220, 52, 149, 245, 126, 184, 18, 212, 196, 219, 208, 84, 83, 39, 247, 255, 234, 119, 219, 14, 30, 98, 192, 225, 241, 34, 143, 167, 101, 59, 122, 187, 236, 94, 60, 164, 21, 190, 142, 32, 12, 52, 134, 235, 17, 116, 135, 7, 232, 209, 172, 121, 218, 9, 209, 192, 90, 248, 125, 199, 49, 37, 170, 91, 151, 135, 126, 170, 230, 49, 169, 91, 240, 36, 215, 129, 68, 97, 151, 205, 255, 206, 31, 197, 80, 44, 160, 103, 139, 97, 3, 83, 35, 189, 215, 134, 8, 163, 252, 107, 73, 17, 37, 21, 214, 170, 74, 29, 142, 40, 151, 7, 16, 212, 113, 136, 225, 158, 123, 233, 153, 15, 0, 188, 245, 48, 223, 53, 135, 46, 189, 49, 26, 194, 189, 2, 48, 24, 150, 224, 2, 235, 219, 113, 82, 229, 57, 77, 232, 120, 168, 147, 169, 49, 248, 131, 138, 240, 74, 42, 107, 103, 244, 178, 162, 187, 156, 118, 85, 166, 107, 189, 185, 89, 22, 34, 233, 56, 234, 129, 146, 121, 71, 95, 192, 222, 111, 233, 50, 157, 101, 168, 214, 232, 218, 231, 175, 43, 3, 78, 38, 109, 156, 88, 106, 187, 170, 113, 14, 10, 30, 172, 88, 143, 58, 99, 153, 3, 92, 228, 220, 42, 170, 109, 80, 79, 142, 235, 31, 235, 25, 170, 202, 95, 159, 227, 89, 174, 15, 172, 206, 219, 47, 14, 217, 245, 201, 210, 27, 176, 174, 239 };
static unsigned char p_high[] = {179, 241, 235, 177, 149, 15, 153, 168, 187, 92, 249, 137, 97, 190, 216, 117, 148, 124, 60, 5, 230, 209, 41, 251, 58, 170, 250, 251, 67, 254, 26, 2, 92, 219, 24, 236, 84, 60, 175, 50, 251, 59, 176, 236, 42, 92, 56, 143, 150, 107, 220, 234, 151, 126, 1, 62, 103, 252, 225, 65, 161, 62, 233, 112, 135, 220, 61, 33, 65, 116, 130, 14, 17, 84, 180, 155, 198, 205, 178, 171, 212, 94, 233, 88, 23, 5, 93, 37, 90, 163, 88, 49, 183, 13, 50, 102, 154, 201, 159, 51, 99, 46, 90, 118, 141, 231, 232, 27, 248, 84, 194, 124, 70, 227, 251, 242, 171, 186, 205, 41, 236, 74, 255, 81, 115, 114, 101, 39 };
static unsigned char q_high[] = {177, 236, 193, 254, 169, 235, 83, 83, 228, 87, 235, 170, 153, 239, 233, 247, 237, 106, 99, 210, 137, 235, 135, 220, 26, 235, 71, 24, 156, 15, 178, 183, 70, 214, 175, 86, 6, 251, 104, 57, 189, 255, 192, 165, 254, 131, 148, 30, 220, 120, 78, 173, 208, 156, 153, 2, 79, 59, 101, 228, 200, 220, 11, 236, 211, 179, 237, 205, 61, 104, 121, 24, 1, 61, 17, 227, 167, 31, 208, 50, 167, 178, 20, 210, 81, 97, 152, 102, 110, 137, 220, 220, 12, 88, 3, 6, 118, 133, 80, 37, 107, 60, 10, 33, 153, 246, 15, 112, 116, 34, 29, 213, 96, 183, 57, 234, 243, 18, 137, 146, 125, 132, 221, 9, 229, 129, 102, 59 };
static unsigned char private_high[] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 };
static unsigned char public_high[] = {52, 220, 152, 212, 220, 52, 149, 245, 126, 184, 18, 212, 196, 219, 208, 84, 83, 39, 247, 255, 234, 119, 219, 14, 30, 98, 192, 225, 241, 34, 143, 167, 101, 59, 122, 187, 236, 94, 60, 164, 21, 190, 142, 32, 12, 52, 134, 235, 17, 116, 135, 7, 232, 209, 172, 121, 218, 9, 209, 192, 90, 248, 125, 199, 49, 37, 170, 91, 151, 135, 126, 170, 230, 49, 169, 91, 240, 36, 215, 129, 68, 97, 151, 205, 255, 206, 31, 197, 80, 44, 160, 103, 139, 97, 3, 83, 35, 189, 215, 134, 8, 163, 252, 107, 73, 17, 37, 21, 214, 170, 74, 29, 142, 40, 151, 7, 16, 212, 113, 136, 225, 158, 123, 233, 153, 15, 0, 188, 245, 48, 223, 53, 135, 46, 189, 49, 26, 194, 189, 2, 48, 24, 150, 224, 2, 235, 219, 113, 82, 229, 57, 77, 232, 120, 168, 147, 169, 49, 248, 131, 138, 240, 74, 42, 107, 103, 244, 178, 162, 187, 156, 118, 85, 166, 107, 189, 185, 89, 22, 34, 233, 56, 234, 129, 146, 121, 71, 95, 192, 222, 111, 233, 50, 157, 101, 168, 214, 232, 218, 231, 175, 43, 3, 78, 38, 109, 156, 88, 106, 187, 170, 113, 14, 10, 30, 172, 88, 143, 58, 99, 153, 3, 92, 228, 220, 42, 170, 109, 80, 79, 142, 235, 31, 235, 25, 170, 202, 95, 159, 227, 89, 174, 15, 172, 206, 219, 47, 14, 217, 245, 201, 210, 27, 176, 174, 239 };
static unsigned char modulo_high[]= {125, 16, 175, 87, 115, 238, 13, 111, 248, 49, 15, 91, 26, 98, 108, 56, 202, 156, 8, 200, 19, 151, 142, 65, 51, 117, 225, 96, 139, 195, 86, 149, 56, 165, 89, 4, 106, 104, 58, 248, 220, 197, 133, 23, 164, 78, 90, 76, 131, 124, 61, 181, 169, 133, 35, 226, 71, 238, 187, 69, 3, 35, 74, 121, 63, 173, 83, 28, 217, 122, 0, 168, 144, 126, 82, 6, 162, 81, 148, 83, 246, 168, 110, 193, 216, 195, 138, 208, 86, 126, 55, 33, 171, 151, 100, 162, 59, 5, 170, 226, 29, 246, 18, 181, 161, 58, 181, 205, 174, 3, 89, 71, 81, 78, 249, 142, 230, 21, 121, 183, 153, 165, 102, 127, 202, 54, 185, 180, 197, 197, 231, 230, 102, 105, 160, 212, 222, 202, 82, 206, 209, 123, 63, 72, 205, 67, 13, 240, 122, 250, 238, 221, 231, 170, 70, 179, 105, 206, 177, 156, 220, 54, 35, 100, 141, 126, 2, 11, 117, 91, 209, 61, 192, 9, 70, 133, 83, 3, 160, 91, 120, 28, 143, 94, 217, 106, 34, 105, 160, 38, 154, 130, 211, 26, 244, 63, 72, 87, 179, 234, 222, 70, 150, 221, 129, 143, 170, 35, 12, 251, 210, 92, 15, 156, 128, 217, 182, 44, 197, 59, 171, 5, 218, 94, 97, 240, 219, 50, 58, 153, 229, 3, 8, 145, 206, 159, 223, 221, 223, 185, 220, 48, 76, 191, 141, 211, 97, 34, 222, 200, 6, 69, 11, 81, 217, 253 };
static unsigned char dp_high[] = {104, 143, 107, 195, 211, 138, 233, 192, 172, 53, 205, 6, 186, 7, 3, 191, 93, 247, 31, 205, 26, 197, 15, 101, 86, 142, 49, 139, 95, 123, 187, 116, 225, 25, 112, 183, 47, 130, 216, 160, 155, 157, 140, 251, 16, 90, 104, 169, 199, 86, 93, 227, 173, 229, 141, 80, 86, 4, 216, 182, 154, 170, 45, 242, 208, 242, 189, 126, 255, 209, 71, 138, 23, 186, 192, 179, 159, 220, 63, 239, 60, 195, 88, 5, 230, 159, 196, 54, 179, 165, 99, 246, 253, 145, 229, 198, 181, 149, 92, 189, 73, 211, 34, 240, 150, 21, 111, 99, 144, 102, 39, 71, 141, 109, 185, 63, 119, 117, 207, 101, 170, 75, 187, 13, 176, 30, 203, 105 };
static unsigned char dq_high[] = {101, 212, 29, 154, 14, 231, 87, 159, 105, 140, 150, 80, 1, 150, 115, 253, 11, 167, 116, 43, 118, 17, 87, 181, 42, 37, 240, 59, 238, 194, 48, 109, 127, 194, 226, 101, 242, 42, 118, 237, 212, 239, 188, 50, 244, 167, 158, 146, 207, 19, 34, 137, 94, 38, 162, 201, 246, 123, 215, 220, 246, 100, 182, 31, 246, 242, 236, 81, 19, 236, 102, 151, 194, 137, 198, 227, 203, 53, 117, 182, 149, 150, 198, 211, 47, 205, 194, 47, 178, 24, 217, 31, 135, 110, 40, 116, 106, 251, 239, 225, 199, 181, 26, 55, 115, 213, 97, 184, 170, 6, 187, 21, 40, 178, 39, 251, 21, 167, 221, 88, 95, 94, 198, 25, 192, 228, 101, 25 };
static unsigned char iq_high[] = {42, 2, 1, 211, 19, 173, 193, 146, 190, 82, 165, 9, 94, 163, 249, 137, 45, 186, 108, 253, 26, 170, 75, 199, 18, 86, 131, 187, 226, 63, 68, 97, 254, 159, 104, 187, 42, 186, 253, 118, 255, 235, 255, 230, 24, 163, 145, 71, 6, 232, 17, 185, 100, 60, 49, 65, 248, 41, 226, 115, 27, 23, 220, 76, 46, 119, 251, 245, 199, 30, 144, 235, 121, 58, 241, 133, 213, 138, 39, 102, 157, 1, 219, 249, 49, 124, 28, 151, 58, 67, 147, 101, 168, 234, 46, 243, 174, 74, 168, 177, 27, 225, 47, 251, 33, 55, 226, 167, 123, 4, 231, 86, 98, 216, 45, 188, 228, 197, 249, 113, 59, 136, 244, 205, 55, 170, 0, 60 };
static unsigned char dp_high2[] = {108, 222, 210, 132, 42, 50, 201, 27, 198, 132, 121, 224, 232, 94, 85, 239, 216, 37, 136, 83, 104, 33, 164, 151, 39, 174, 77, 175, 95, 92, 78, 45, 42, 59, 189, 106, 82, 229, 9, 230, 205, 27, 44, 131, 3, 177, 230, 134, 96, 23, 85, 103, 34, 110, 21, 86, 1, 27, 152, 207, 189, 154, 52, 169, 37, 144, 138, 188, 124, 82, 38, 159, 239, 124, 164, 104, 26, 85, 18, 48,113, 63, 64, 28, 45, 41, 210, 241, 119, 6, 157, 101, 16, 242, 111, 66, 111, 213, 136, 193, 165, 191, 151, 87, 163, 250,226, 75, 217, 25, 128, 84, 116, 67, 175, 252, 35, 60, 40, 218, 79, 121, 165, 167, 207, 21, 1, 151 };
static unsigned char dq_high2[] = {114, 80, 112, 190, 201, 47, 237, 202, 152, 31, 192, 181, 113, 144, 244, 14, 174, 144, 136, 182, 4, 205, 144, 41, 48, 89, 42, 141, 110, 55, 101, 127, 119, 140, 153, 245, 138, 97, 181, 113, 120, 235, 84, 44, 81, 170, 252, 144, 226, 87, 221,4, 75, 135, 181, 234, 65, 59, 158, 229, 26, 73, 217, 253, 159, 155, 75, 104, 180, 154, 136, 66, 239, 233, 217, 213, 236,11, 25, 153, 22, 110, 199, 70, 134, 192, 155, 25, 191, 251, 1, 172, 114, 72, 131, 174, 135, 155, 121, 252, 100, 90, 28,202, 91, 77, 198, 7, 4, 164, 84, 204, 37, 156, 82, 169, 227, 0, 142, 108, 189, 161, 47, 136, 126, 226, 108, 247 };


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
    size_t prime_size = (sizeof(high_dp2) - 1) / 2;
    unsigned char dest[prime_size];
    hexStringToByteArray(high_dp2, dest, prime_size);
*/
    struct timespec tstart={0,0}, tend={0,0};
    br_rsa_private_key pk;
    br_rsa_public_key pbk;
    generateHighRSA(&pk, &pbk);

    unsigned char dest[256];
    size_t encrypted;
    size_t bytes = 190;
    unsigned char encMessage[] = "Testovaci zprava";
    size_t messageLength = sizeof(encMessage);

    FILE *  file = fopen("rsa_high_hw.txt", "w");
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

    unsigned char dest[256];
    size_t encrypted;
    size_t bytes = 190;

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
    return;
}

void lowHammingWeightRSASign(br_hmac_drbg_context* ctx, size_t tries) {
    return;
}
