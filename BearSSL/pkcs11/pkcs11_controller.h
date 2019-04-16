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

int loadLibrary(HMODULE* dll_handle);

int initialize(HMODULE dll_handle);

long getTokenByLabel(HMODULE dll_handle, const unsigned char * label);

int openLoggedSession(HMODULE dll_handle, long slotID, CK_SESSION_HANDLE* session );

int logToSession(HMODULE dll_handle, CK_SESSION_HANDLE session, void* pin);

int logoutFromSession(HMODULE dll_handle, CK_SESSION_HANDLE session);

int closeSession(HMODULE dll_handle, CK_SESSION_HANDLE session);

int findKeyById(HMODULE dll_handle, CK_SESSION_HANDLE session, void * id, size_t idSize, CK_OBJECT_HANDLE * key);

int generateRSAKeyPair(HMODULE dll_handle, CK_SESSION_HANDLE session,
        unsigned size, uint32_t pubexp,
        CK_OBJECT_HANDLE* pubKey, CK_OBJECT_HANDLE* privKey,
        unsigned char * id, size_t idSize,
        unsigned char* subject, size_t subSize);


int getPublicKey(HMODULE dll_handle, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE publicKey,
        br_rsa_public_key * pk, CK_BYTE * kbuf_pub);

int getPublicKeyFromPrivateKey(HMODULE dll_handle, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privateKey,
                 br_rsa_public_key * pk, CK_BYTE * kbuf_pub);


int decryptWithKeyOnToken(HMODULE dll_handle, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privateKey,
        unsigned char * input, size_t inputSize,
        unsigned char * output, size_t * outputSize);

int generateECCKeyPair(HMODULE dll_handle, CK_SESSION_HANDLE session,
                       unsigned size, uint32_t pubexp,
                       CK_OBJECT_HANDLE* pubKey, CK_OBJECT_HANDLE* privKey,
                       unsigned char * id, size_t idSize,
                       unsigned char* subject, size_t subSize);

int generateRSASignature(HMODULE dll_handle, CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                         CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen,
                         CK_OBJECT_HANDLE privateKey);






#endif //PV204_PROJECT_PKCS11_CONTROLLER_H