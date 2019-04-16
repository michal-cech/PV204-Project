//
// Created by MrMCech on 16.04.2019.
//

#include "inner.h"
#include "../pkcs11/pkcs11_controller.h"
size_t
br_ecdsa_token_sign_raw(const br_ec_impl *impl,
                      const br_hash_class *hf, const void *hash_value,
                      const br_ec_private_key *sk, void *sig) {
    int index = 0;
    unsigned char tokenSize = ((unsigned char*) sk->x)[index];
    index += sizeof(tokenSize);

    unsigned char token[tokenSize];
    memcpy(token, sk->x+index, tokenSize);
    index += tokenSize;

    unsigned char labelSize = ((unsigned char*) sk->x)[index];
    index += sizeof(labelSize);

    unsigned char label[labelSize];
    memcpy(label, sk->x+index, labelSize);
    index += labelSize;

    unsigned char pinSize = ((unsigned char*) sk->x)[index];
    index += sizeof(pinSize);

    unsigned char pin[pinSize];
    memcpy(pin, sk->x+index, pinSize);
    index += pinSize;

    unsigned char keyLabelSize = ((unsigned char*) sk->x)[index];
    index += sizeof(keyLabelSize);

    unsigned char keyLabel[keyLabelSize];
    memcpy(keyLabel, sk->x+index, keyLabelSize);

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

    unsigned long xlen = 64;
    CK_SESSION_HANDLE session;
    openLoggedSession(dll_handle, slotID, &session);
    logToSession(dll_handle,session, pin);

    CK_OBJECT_HANDLE privateKey;
    findExistingKey(dll_handle, session, keyLabel, keyLabelSize, &privateKey, CKO_PRIVATE_KEY, CKK_EC);
    generateECCSignature(dll_handle, session, hash_value, 64, sig, &xlen, privateKey);

    logoutFromSession(dll_handle, session);
    closeSession(dll_handle, session);

    return xlen;
#endif
}