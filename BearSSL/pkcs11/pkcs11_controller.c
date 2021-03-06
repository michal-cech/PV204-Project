//
// Created by MrMCech on 13.04.2019.
//
#ifdef linux
#include <dlfcn.h>
#endif
#ifdef __WIN32
#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <stdint.h>
#include "inner.h"

#endif

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) \
returnType __declspec(dllexport) name
#define CK_DECLARE_FUNCTION(returnType, name) \
returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
//used for including pkcs#11 version 2.01

#include "pkcs11.h"

/* These data types are platform/implementation dependent. */
#define CK_ENTRY          __declspec( dllexport )
#define CK_PTR            *
#define NULL_PTR          0
#pragma pack(push, cryptoki, 1)

#include "pkcs11_ft.h"
#define PKCS11_LIB "\\SoftHSM2\\lib\\softhsm2-x64.dll"

int loadLibrary(HMODULE* dll_handle) {
    *dll_handle = LoadLibrary(PKCS11_LIB);
    if (!*dll_handle) {
        return 0;
    }
    return 1;
}

int initialize(HMODULE dll_handle) {
    FARPROC init = GetProcAddress(dll_handle, "C_Initialize");
    if (init(NULL) == CKR_OK) {
        return 1;
    } else {
        return 0;
    }
}

long getTokenByLabel(HMODULE dll_handle, const unsigned char * label) {
    FARPROC slotList = GetProcAddress(dll_handle, "C_GetSlotList");
    FARPROC tokenInfo = GetProcAddress(dll_handle, "C_GetTokenInfo");

    CK_TOKEN_INFO oneTokenInfo;

    DWORD pkcs11SlotCount = 0;
    CK_RV returnValue = 0;
    if ((returnValue = slotList(TRUE, NULL, &pkcs11SlotCount)) != CKR_OK) {
        return -1;
    }

    CK_SLOT_ID pkcs11Slots[pkcs11SlotCount];
    slotList(TRUE, pkcs11Slots, &pkcs11SlotCount );
    for (DWORD i = 0; i < pkcs11SlotCount; i++) {
        tokenInfo(pkcs11Slots[i], &oneTokenInfo);
        TCHAR * pos = 0;
        if ((pos = strstr((TCHAR*)oneTokenInfo.label, __T("   "))) != NULL) {
            memset(oneTokenInfo.label + (pos - (TCHAR*)oneTokenInfo.label) * sizeof(TCHAR), 0, sizeof(TCHAR));
        }

        if (strcmp((const char*)oneTokenInfo.label, label) == 0) {
            return pkcs11Slots[i];
        }
    }
    return -1;
}

int openLoggedSession(HMODULE dll_handle, long slotID, CK_SESSION_HANDLE* session ) {
    FARPROC getSession = GetProcAddress(dll_handle, "C_OpenSession");

    if (getSession(slotID,  CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, session) != CKR_OK) {
        return 0;
    }
    return 1;
}

int logToSession(HMODULE dll_handle, CK_SESSION_HANDLE session, CK_CHAR_PTR pin) {
    FARPROC login = GetProcAddress(dll_handle, "C_Login");
    unsigned long returnValue;
    if ((returnValue = login(session, CKU_USER, pin, strlen(pin))) != CKR_OK) {
        return 0;
    }
    return 1;
}

int logoutFromSession(HMODULE dll_handle, CK_SESSION_HANDLE session) {
    FARPROC logout = GetProcAddress(dll_handle, "C_Logout");
    logout(session);
}

int closeSession(HMODULE dll_handle, CK_SESSION_HANDLE session) {
    FARPROC close = GetProcAddress(dll_handle, "C_CloseSession");
    close(session);
}

int findExistingKey(HMODULE dll_handle, CK_SESSION_HANDLE session, CK_CHAR_PTR keyLabel, size_t keyLabelSize,
                    CK_OBJECT_HANDLE *key, CK_OBJECT_CLASS class, CK_KEY_TYPE type) {
    FARPROC findInit = GetProcAddress(dll_handle, "C_FindObjectsInit");
    FARPROC find = GetProcAddress(dll_handle, "C_FindObjects");
    FARPROC findFinish = GetProcAddress(dll_handle, "C_FindObjectsFinal");
    CK_ATTRIBUTE template[] = {
            {CKA_LABEL, keyLabel, keyLabelSize},
            {CKA_KEY_TYPE, &type, sizeof(type)},
            {CKA_CLASS, &class, sizeof(class)}
    };

    findInit(session, template ,3);
    CK_ULONG realCount = 0;
    find(session, key, 1, &realCount);
    findFinish(session);
    return realCount;
}

int generateRSAKeyPair(HMODULE dll_handle, CK_SESSION_HANDLE session,
                       unsigned size, uint32_t pubexp,
                       CK_OBJECT_HANDLE* pubKey, CK_OBJECT_HANDLE* privKey,
                       unsigned char * keyLabel, size_t keyLabelSize) {
    if (findExistingKey(dll_handle, session, keyLabel, keyLabelSize, privKey, CKO_PRIVATE_KEY, CKK_RSA)) {
         return 2;
    }

    CK_BYTE publicExponent;
    if (pubexp == 0) {
        publicExponent = 3;
    } else {
        publicExponent = (unsigned char) pubexp;
    }
    FARPROC generate = GetProcAddress(dll_handle, "C_GenerateKeyPair");
    CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_ULONG modulusBits = size;

    CK_OBJECT_CLASS public = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS private = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;

    CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_CLASS, &public, sizeof(public)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_LABEL, keyLabel, (CK_ULONG)keyLabelSize},
            {CKA_TOKEN, &true, sizeof(true)},
            {CKA_ENCRYPT, &true, sizeof(true)},
            {CKA_VERIFY, &true, sizeof(true)},
            {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, &publicExponent, sizeof (publicExponent)}
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_CLASS, &private, sizeof(private)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_TOKEN, &true, sizeof(true)},
            {CKA_PRIVATE, &true, sizeof(true)},
            {CKA_SENSITIVE, &true, sizeof(true)},
            {CKA_LABEL, keyLabel, (CK_ULONG)keyLabelSize},
            {CKA_DECRYPT, &true, sizeof(true)},
            {CKA_SIGN, &true, sizeof(true)}
    };
    unsigned long resultValue;
    if ((resultValue = generate(session, &mechanism, publicKeyTemplate, 8, privateKeyTemplate, 8, pubKey, privKey)) != CKR_OK) {
        return 0;
    }
    return 1;
}


int getRSAPublicKey(HMODULE dll_handle, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE publicKey,
                    br_rsa_public_key *pk, CK_BYTE *kbuf_pub) {
    FARPROC getAttribute = GetProcAddress(dll_handle, "C_GetAttributeValue");
    unsigned char pModulus[256];
    unsigned char pExponent[256];
    CK_ATTRIBUTE template[] = {
            {CKA_PUBLIC_EXPONENT, pExponent, 2048},
            {CKA_MODULUS, pModulus, 2048}
    };
    int rv = getAttribute(session, publicKey, template, 2);
    if (rv == CKR_OK) {

        pk->nlen = template[1].ulValueLen;
        pk->elen = template[0].ulValueLen;
        memcpy(kbuf_pub, pModulus, pk->nlen);
        memcpy(kbuf_pub+pk->nlen, pExponent,pk->elen);
        pk->n = kbuf_pub;
        pk->e = kbuf_pub + pk->nlen;
        return 1;
    } else {
        return 0;
    }

}

int getECCPublicKey(HMODULE dll_handle, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE publicKey,
                    br_ec_public_key *pk, CK_BYTE *kbuf_pub) {
    FARPROC getAttribute = GetProcAddress(dll_handle, "C_GetAttributeValue");
    CK_BYTE pExponent[2048];
    CK_ATTRIBUTE template[] = {
            {CKA_EC_POINT, pExponent, 2048}
    };
    int rv = getAttribute(session, publicKey, template, 1);
    if (rv == CKR_OK) {
        pk->qlen = template[0].ulValueLen - 2;
        memcpy(kbuf_pub, pExponent+2, pk->qlen);
        pk->q = kbuf_pub;
        return 1;
    } else {
        return 0;
    }

}

int getECCPrivateKey(HMODULE dll_handle, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE publicKey,
                    br_ec_public_key *pk, CK_BYTE *kbuf_pub) {
    FARPROC getAttribute = GetProcAddress(dll_handle, "C_GetAttributeValue");
    CK_BYTE pExponent[256] = {0};
    CK_ATTRIBUTE template[] = {
            {CKA_VALUE, pExponent, 256}
    };
    int rv = getAttribute(session, publicKey, template, 1);
    if (rv == CKR_OK) {
        pk->qlen = template[0].ulValueLen;
        memcpy(kbuf_pub, pExponent, pk->qlen);
        pk->q = kbuf_pub;
        return 1;
    } else {
        return 0;
    }

}

int decryptWithKeyOnToken(HMODULE dll_handle, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privateKey,
                          unsigned char * input, size_t inputSize,
                          unsigned char * output, size_t * outputSize) {
    FARPROC decryptInit = GetProcAddress(dll_handle, "C_DecryptInit");
    FARPROC decrypt = GetProcAddress(dll_handle,"C_Decrypt");

    CK_MECHANISM mechanism = {CKM_RSA_X_509, NULL, 0 };

/*    CK_RSA_PKCS_OAEP_PARAMS params = {
            CKM_SHA256, CKG_MGF1_SHA256,CKZ_DATA_SPECIFIED, NULL_PTR,0
    };
*/
//    CK_MECHANISM mechanism = {CKM_RSA_PKCS_OAEP, NULL, 0 };

    CK_RV rv = CKR_OK;

    rv = decryptInit(session, &mechanism, privateKey);
    rv = decrypt(session, input, inputSize, input, outputSize);
    if (rv != CKR_OK) {
        return 0;
    }
    return 1;
}

uint32_t generateRSASignature(HMODULE dll_handle, CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                              CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen,
                              CK_OBJECT_HANDLE privateKey) {

    FARPROC init = GetProcAddress(dll_handle, "C_SignInit");
    FARPROC generate = GetProcAddress(dll_handle, "C_Sign");

    CK_MECHANISM mechanism = {CKM_RSA_X_509, NULL, 0};

    unsigned long resultValue;
    if ((resultValue = init(hSession, &mechanism, privateKey)) != CKR_OK) {
        printf("\nC_SignInit: rv = 0x%.8X\n", resultValue);

        return 0;
    }
    if ((resultValue = generate(hSession, pData, ulDataLen, pSignature, pulSignatureLen)) != CKR_OK) {
        printf("\nC_Sign: rv = 0x%.8X\n", resultValue);

        return 0;
    }

    return 1;
}

int generateECCKeyPair(HMODULE dll_handle, CK_SESSION_HANDLE session,
                       CK_OBJECT_HANDLE* pubKey, CK_OBJECT_HANDLE* privKey,
                       unsigned char * keyLabel, size_t keyLabelSize) {

    if (findExistingKey(dll_handle, session, keyLabel, keyLabelSize, privKey, CKO_PRIVATE_KEY, CKK_EC)) {
        return 2;
    }

    FARPROC generate = GetProcAddress(dll_handle, "C_GenerateKeyPair");

    CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL, 0};
    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;

    CK_OBJECT_CLASS public = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS private = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC;

    CK_BYTE oidP256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
    CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_CLASS, &public, sizeof(public)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_VERIFY, &true, sizeof(true)},
            {CKA_LABEL, keyLabel, (CK_ULONG)keyLabelSize},
            {CKA_EC_PARAMS, oidP256, sizeof(oidP256)},
            {CKA_VERIFY, &true, sizeof(true)},
            {CKA_TOKEN, &true, sizeof(true)},
            {CKA_ENCRYPT, &false, sizeof(false)},
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_CLASS, &private, sizeof(private)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_TOKEN, &true, sizeof(true)},
         //   {CKA_PRIVATE, &false, sizeof(false)},
            {CKA_PRIVATE, &true, sizeof(true)},
         //   {CKA_SENSITIVE, &false, sizeof(false)},
            {CKA_SENSITIVE, &true, sizeof(true)},
            {CKA_LABEL, keyLabel, (CK_ULONG)keyLabelSize},
            {CKA_DECRYPT, &false, sizeof(false)},
        //    {CKA_EXTRACTABLE, &true, sizeof(true)},
            {CKA_SIGN, &true, sizeof(true)}
    };

    unsigned long resultValue;
    if ((resultValue = generate(session, &mechanism, publicKeyTemplate, 8, privateKeyTemplate, 8, pubKey, privKey)) != CKR_OK) {
        return 0;
    }
    return 1;
}

size_t generateECCSignature(HMODULE dll_handle, CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                         CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen,
                         CK_OBJECT_HANDLE privateKey) {

    FARPROC init = GetProcAddress(dll_handle, "C_SignInit");
    FARPROC generate = GetProcAddress(dll_handle, "C_Sign");

    CK_MECHANISM mechanism = {CKM_ECDSA, NULL, 0};

    unsigned long resultValue;
    if ((resultValue = init(hSession, &mechanism, privateKey)) != CKR_OK) {
        printf("\nC_SignInit: rv = 0x%.8X\n", resultValue);

        return 0;
    }
    if ((resultValue = generate(hSession, pData, ulDataLen, pSignature, pulSignatureLen)) != CKR_OK) {
        printf("\nC_Sign: rv = 0x%.8X\n", resultValue);

        return 0;
    }

    return 1;
}

