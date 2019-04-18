//
// Created by MrMCech on 12.04.2019.
//

/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
*/

#include "inner.h"
#include "../pkcs11/pkcs11_controller.h"


/* see bearssl_rsa.h */
uint32_t br_rsa_token_pkcs1_sign(const unsigned char *hash_oid,
                                 const unsigned char *hash, size_t hash_len,
                                 const br_rsa_private_key *sk, unsigned char *x)
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

    CK_OBJECT_HANDLE privateKey;
    if (!findExistingKey(dll_handle, session, keyLabel, keyLabelSize, &privateKey, CKO_PRIVATE_KEY, CKK_RSA)) {
        logoutFromSession(dll_handle, session);
        closeSession(dll_handle, session);
        return 0;
    }

    unsigned long xlen = (sk->n_bitlen + 7) >> 3;

    if (!br_rsa_pkcs1_sig_pad(hash_oid, hash, hash_len, sk->n_bitlen, x)) {
        logoutFromSession(dll_handle, session);
        closeSession(dll_handle, session);
        return 0;
    }

    uint32_t value = generateRSASignature(dll_handle, session, x,  sk->n_bitlen / 8,  x, &xlen, privateKey);

    logoutFromSession(dll_handle, session);
    closeSession(dll_handle, session);

    return value;

#endif
}
