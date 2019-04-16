//
// Created by MrMCech on 16.04.2019.
//

#include "inner.h"
#include <string.h>
#include "../pkcs11/pkcs11_controller.h"

size_t
br_ec_token_compute_pub(const br_ec_impl *impl, br_ec_public_key *pk,
                  void *kbuf, const br_ec_private_key *sk) {
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

    CK_SESSION_HANDLE session;
    openLoggedSession(dll_handle, slotID, &session);
    logToSession(dll_handle,session, pin);

    CK_OBJECT_HANDLE publicKey;
    findExistingKey(dll_handle, session, keyLabel, keyLabelSize, &publicKey, CKO_PUBLIC_KEY, CKK_EC);
    getECCPublicKey(dll_handle, session, publicKey, pk, kbuf);
    logoutFromSession(dll_handle, session);
    closeSession(dll_handle, session);
#endif
}