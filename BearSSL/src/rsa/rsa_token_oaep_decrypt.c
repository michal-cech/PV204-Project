//
// Created by MrMCech on 13.04.2019.
//

/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org>
 *
 */

#include "inner.h"
#include "../pkcs11/pkcs11_controller.h"

/* see bearssl_rsa.h */
uint32_t
br_rsa_token_oaep_decrypt(const br_hash_class *dig,
                        const void *label, size_t label_len,
                        const br_rsa_private_key *sk, void *data, size_t *len)
{
    unsigned char labelSize = sk->dplen;
    unsigned char tokenLabel[labelSize];
    unsigned char pinSize = sk->dqlen;
    unsigned char pin[pinSize];
    unsigned char idSize = sk->iqlen;
    unsigned char id[idSize];

    memcpy(tokenLabel, sk->dp,labelSize);
    memcpy(pin, sk->dq, pinSize);
    memcpy(id, sk->iq, idSize);

#ifdef linux
    int dll_handle = dlopen(PKCS11_DLL)
#endif
#ifdef __WIN32
    HMODULE dll_handle = NULL;
    loadLibrary(&dll_handle);
    initialize(dll_handle);

    int slotID = getTokenByLabel(dll_handle,tokenLabel);
    if (slotID == -1) {
        return 0;
    }
    CK_SESSION_HANDLE session;
    openLoggedSession(dll_handle, slotID, &session);
    logToSession(dll_handle,session, pin);

    CK_OBJECT_HANDLE private_key;
    findKeyById(dll_handle, session, id, idSize, &private_key);
    size_t outputSize = 256;
    uint32_t r = 0;

    r = decryptWithKeyOnToken(dll_handle, session, private_key, data, *len, data, &outputSize);

    r &= br_rsa_oaep_unpad(dig, label, label_len, data, len);
    return r;
#endif
}
