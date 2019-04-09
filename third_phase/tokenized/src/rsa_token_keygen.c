//
// Created by MrMCech on 09.04.2019.
//
#include <stdio.h>


#include "inner.h"
#include <string.h>
#include "../pkcs11/pkcs11_controller.h"
 // function types for PKCS#11 functions

/* see bearssl_rsa.h */

uint32_t
br_rsa_token_keygen(const br_prng_class **rng,
                    br_rsa_private_key *sk, void *kbuf_priv,
                    br_rsa_public_key *pk, void *kbuf_pub,
                    unsigned size, uint32_t pubexp)
{
    size_t labelSize = ((size_t*)kbuf_priv)[0];
    size_t pinSize = ((size_t*)kbuf_priv)[1];
    unsigned char label[labelSize];
    unsigned char pin[pinSize];

    memcpy(label, kbuf_pub,labelSize);
    memcpy(pin, kbuf_pub + labelSize*sizeof(unsigned char), pinSize);

#ifdef linux
    int dll_handle = dlopen(PKCS11_DLL)
#endif
#ifdef __WIN32
    HMODULE dll_handle = NULL;
    loadLibrary(&dll_handle);
    initialize(dll_handle);

    int slotID = getTokenByLabel(dll_handle,label);
    if (slotID == -1) {
        return 0;
    }

    CK_SESSION_HANDLE session;
    openLoggedSession(dll_handle, slotID, &session);
    logToSession(dll_handle,session, pin);

    logoutFromSession(dll_handle, session);
    closeSession(dll_handle, session);



#endif

    return 1;
}