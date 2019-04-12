//
// Created by MrMCech on 09.04.2019.
//

#ifndef PV204_PROJECT_PKCS11_CONTROLLER_H
#define PV204_PROJECT_PKCS11_CONTROLLER_H
#ifdef linux
#include <dlfcn.h>
#endif
#ifdef __WIN32
#include <windows.h>
#include <tchar.h>

#endif

//used for including pkcs#11 version 2.01
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
#define PKCS11_LIB "C:\\SoftHSM2\\lib\\softhsm2-x64.dll"

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

int logToSession(HMODULE dll_handle, CK_SESSION_HANDLE session, void* pin) {
    FARPROC login = GetProcAddress(dll_handle, "C_Login");
    CK_CHAR* pinChar = (CK_CHAR*) pin;
    size_t pinLen = strlen(pinChar);
    unsigned long returnValue;
    if ((returnValue = login(session, CKU_USER, pinChar, strlen(pin))) != CKR_OK) {
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

int findKeyById(HMODULE dll_handle, CK_SESSION_HANDLE session, void * id, size_t idSize, CK_OBJECT_HANDLE * key) {
    FARPROC findInit = GetProcAddress(dll_handle, "C_FindObjectsInit");
    FARPROC find = GetProcAddress(dll_handle, "C_FindObjects");
    FARPROC findFinish = GetProcAddress(dll_handle, "C_FindObjectsFinal");
    CK_ATTRIBUTE template[] = {
            {CKA_ID, id, idSize}
    };
    findInit(session, template ,0);
    CK_ULONG realCount = 0;
    find(session, key, 1, &realCount);
    findFinish(session);
}

int generateRSAKeyPair(HMODULE dll_handle, CK_SESSION_HANDLE session,
        unsigned size, uint32_t pubexp,
        CK_OBJECT_HANDLE* pubKey, CK_OBJECT_HANDLE* privKey,
        unsigned char * id, size_t idSize,
        unsigned char* subject, size_t subSize) {
    CK_BYTE publicExponent;
    if (pubexp == 0) {
        publicExponent = 3;
    } else {
        publicExponent = (unsigned char) pubexp;
    }
    FARPROC generate = GetProcAddress(dll_handle, "C_GenerateKeyPair");
    CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
    CK_BBOOL true = 1;
    CK_ULONG modulusBits = size;

    CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_ENCRYPT, &true, sizeof(true)},
            {CKA_VERIFY, &true, sizeof(true)},
            {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, &publicExponent, sizeof (publicExponent)}
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_TOKEN, &true, sizeof(true)},
            {CKA_PRIVATE, &true, sizeof(true)},
            {CKA_SENSITIVE, &true, sizeof(true)},
            {CKA_ID, id, (CK_ULONG)idSize},
            {CKA_DECRYPT, &true, sizeof(true)},
            {CKA_SIGN, &true, sizeof(true)}
    };
    unsigned long resultValue;
    if ((resultValue = generate(session, &mechanism, publicKeyTemplate, 4, privateKeyTemplate, 6, pubKey, privKey)) != CKR_OK) {
        return 0;
    }
    return 1;
}


int getPublicKey(HMODULE dll_handle, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE publicKey,
        br_rsa_public_key * pk, CK_BYTE * kbuf_pub) {
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

int generateECCKeyPair(HMODULE dll_handle, CK_SESSION_HANDLE session,
                       unsigned size, uint32_t pubexp,
                       CK_OBJECT_HANDLE* pubKey, CK_OBJECT_HANDLE* privKey,
                       unsigned char * id, size_t idSize,
                       unsigned char* subject, size_t subSize) {
    FARPROC generate = GetProcAddress(dll_handle, "C_GenerateKeyPair");
    CK_BYTE publicExponent;
    if (pubexp == 0) {
        publicExponent = 3;
    } else {
        publicExponent = (unsigned char) pubexp;
    }
    CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
    CK_BBOOL true = 1;
    CK_ULONG modulusBits = size;

    CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_ENCRYPT, &true, sizeof(true)},
            {CKA_VERIFY, &true, sizeof(true)},
            {CKA_WRAP, &true, sizeof(true)},
            {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, &publicExponent, sizeof (publicExponent)}
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_TOKEN, &true, sizeof(true)},
            {CKA_PRIVATE, &true, sizeof(true)},
            {CKA_SENSITIVE, &true, sizeof(true)},
            {CKA_ID, id, (CK_ULONG)idSize},
            {CKA_DECRYPT, &true, sizeof(true)},
            {CKA_SIGN, &true, sizeof(true)},
            {CKA_UNWRAP, &true, sizeof(true)}
    };
    unsigned long resultValue;
    if ((resultValue = generate(session, &mechanism, publicKeyTemplate, 5, privateKeyTemplate, 7, pubKey, privKey)) != CKR_OK) {
        return 0;
    }
    return 1;
}






#endif //PV204_PROJECT_PKCS11_CONTROLLER_H