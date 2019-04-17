//
// Created by MrMCech on 16.04.2019.
//

#include "inner.h"
#include "../pkcs11/pkcs11_controller.h"

#define I31_LEN     ((BR_MAX_EC_SIZE + 61) / 31)
#define POINT_LEN   (1 + (((BR_MAX_EC_SIZE + 7) >> 3) << 1))
#define ORDER_LEN   ((BR_MAX_EC_SIZE + 7) >> 3)
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
    if (!openLoggedSession(dll_handle, slotID, &session)) {
        return 0;
    }
    if (!logToSession(dll_handle, session, pin)) {
        closeSession(dll_handle, session);
        return 0;
    }

//Fiddle with hash

    uint32_t n[I31_LEN];
    uint32_t m[I31_LEN];
    size_t hash_len, nlen, ulen;
    hash_len = (hf->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
    br_ecdsa_i31_bits2int(m, hash_value, hash_len, n[0]);
    br_i31_sub(m, n, br_i31_sub(m, n, 0) ^ 1);

    CK_OBJECT_HANDLE privateKey;
    if (!findExistingKey(dll_handle, session, keyLabel, keyLabelSize, &privateKey, CKO_PRIVATE_KEY, CKK_EC)) {
        logoutFromSession(dll_handle, session);
        closeSession(dll_handle, session);
        return 0;
    }

    generateECCSignature(dll_handle, session, (CK_BYTE_PTR) hash_value, 64, sig, &xlen, privateKey);

    logoutFromSession(dll_handle, session);
    closeSession(dll_handle, session);

    return xlen;
#endif
}