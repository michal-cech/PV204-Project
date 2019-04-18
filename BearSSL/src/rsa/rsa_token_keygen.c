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
    unsigned char labelSize = sk->dplen;
    unsigned char label[labelSize];
    unsigned char pinSize = sk->dqlen;
    unsigned char pin[pinSize];
    unsigned char keyLabelSize = sk->iqlen;
    unsigned char keyLabel[keyLabelSize];

    memcpy(label, sk->dp,labelSize);
    memcpy(pin, sk->dq, pinSize);
    memcpy(keyLabel, sk->iq, keyLabelSize);

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
    if (!openLoggedSession(dll_handle, slotID, &session)) {
        return 0;
    }
    if (!logToSession(dll_handle,session, pin)) {
        closeSession(dll_handle, session);
        return 0;
    }

    CK_OBJECT_HANDLE pubKey;
    CK_OBJECT_HANDLE privKey;

    int rv = generateRSAKeyPair(dll_handle, session, size, pubexp, &pubKey, &privKey, keyLabel, sizeof(keyLabel));
    if (rv == 1) {
        getRSAPublicKey(dll_handle, session, pubKey, pk, kbuf_pub);
    } else if (rv == 2) {
        printf ("Key with this ID already exists, returning corresponding pub key");
        getRSAPublicKey(dll_handle, session, privKey, pk, kbuf_pub);
    } else {
        logoutFromSession(dll_handle, session);
        closeSession(dll_handle, session);
        return 0;
    }
    logoutFromSession(dll_handle, session);
    closeSession(dll_handle, session);
    return 1;


#endif
}