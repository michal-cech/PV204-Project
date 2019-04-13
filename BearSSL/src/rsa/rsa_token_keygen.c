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
    unsigned char idSize = sk->iqlen;
    unsigned char id[idSize];

    memcpy(label, sk->dp,labelSize);
    memcpy(pin, sk->dq, pinSize);
    memcpy(id, sk->iq, idSize);

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

    CK_OBJECT_HANDLE pubKey;
    CK_OBJECT_HANDLE privKey;

    unsigned char subject[] = "subject";


    int rv = generateRSAKeyPair(dll_handle, session, size, pubexp, &pubKey, &privKey, id, sizeof(id), subject, sizeof(subject));
    if (rv == 1) {
        getPublicKey(dll_handle, session, pubKey, pk, kbuf_pub);
    } else if (rv == 2) {
        printf ("Key with this ID already exists, returning corresponding pub key");
        getPublicKey(dll_handle, session, privKey, pk, kbuf_pub);
    }
    logoutFromSession(dll_handle, session);
    closeSession(dll_handle, session);



#endif

    return 1;
}