//
// Created by MrMCech on 12.04.2019.
//

/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
*/

#include "inner.h"
#include "../pkcs11/pkcs11_controller.h"

const int BUFFERSIZE = 256;


/* see bearssl_rsa.h */
uint32_t
br_rsa_token_pkcs1_sign(const br_rsa_private_key *sk)
{
    unsigned char labelSize = sk->dplen;
    unsigned char label[labelSize];
    unsigned char pinSize = sk->dqlen;
    unsigned char pin[pinSize];
    unsigned char idSize = sk->iqlen;
    unsigned char id[idSize];

    unsigned char pData[] = "Simple message for signing & verifying.";
    CK_ULONG ulDataLen = strlen(pData);
    unsigned char pSignature[BUFFERSIZE];
    CK_ULONG pulSignatureLen = BUFFERSIZE;

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

    CK_OBJECT_HANDLE privateKey;
    findKeyById(dll_handle, session, id, idSize, &privateKey);

    generateRSASignature(dll_handle, session, (CK_BYTE_PTR) pData, ulDataLen, (CK_BYTE_PTR) pSignature, &pulSignatureLen, privateKey);

    logoutFromSession(dll_handle, session);
    closeSession(dll_handle, session);

    return 0;

    /*
    if (!br_rsa_pkcs1_sig_pad(hash_oid, hash, hash_len, sk->n_bitlen, x)) {
        return 0;
    }
    return br_rsa_i31_private(x, sk);
     */

#endif
}
