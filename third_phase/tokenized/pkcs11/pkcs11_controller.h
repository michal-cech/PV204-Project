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






#endif //PV204_PROJECT_PKCS11_CONTROLLER_H