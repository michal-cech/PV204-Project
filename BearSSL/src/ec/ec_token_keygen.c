/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inner.h"
#include <string.h>
#include "../pkcs11/pkcs11_controller.h"

/* see bearssl_ec.h */
size_t
br_ec_token_keygen(const br_prng_class **rng_ctx,
             const br_ec_impl *impl, br_ec_private_key *sk,
             void *kbuf, int curve)
{
    if (curve < 0 || curve >= 32
        || ((impl->supported_curves >> curve) & 1) == 0)
    {
        return 0;
    }
    int index = 0;
    unsigned char tokenSize = ((unsigned char*) kbuf)[index];
    index += sizeof(tokenSize);

    unsigned char token[tokenSize];
    memcpy(token, kbuf+index, tokenSize);
    index += tokenSize;

    unsigned char labelSize = ((unsigned char*) kbuf)[index];
    index += sizeof(labelSize);

    unsigned char label[labelSize];
    memcpy(label, kbuf+index, labelSize);
    index += labelSize;

    unsigned char pinSize = ((unsigned char*) kbuf)[index];
    index += sizeof(pinSize);

    unsigned char pin[pinSize];
    memcpy(pin, kbuf+index, pinSize);
    index += pinSize;

    unsigned char keyLabelSize = ((unsigned char*) kbuf)[index];
    index += sizeof(keyLabelSize);

    unsigned char keyLabel[keyLabelSize];
    memcpy(keyLabel, kbuf+index, keyLabelSize);

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

    generateECCKeyPair(dll_handle, session, &pubKey, &privKey, keyLabel, keyLabelSize);
    logoutFromSession(dll_handle, session);
    closeSession(dll_handle, session);
#endif
}
