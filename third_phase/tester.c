#include "../BearSSL/inc/bearssl.h"


#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#ifdef linux
#include <dlfcn.h>
    int dll_handle = dlopen(PKCS11_DLL)
#endif
#ifdef __WIN32
    #include <windows.h>
#endif




int main(int argc, char * argv[]) {
    unsigned char label[] = "test_token";
    size_t labelSize = sizeof(label);
    unsigned char pin[] = "123456";
    size_t pinSize = sizeof(pin);
    unsigned char params[labelSize + pinSize];
    memcpy(params, label, labelSize);
    memcpy(params+labelSize, pin, pinSize);
    size_t paramSizes[2] = {labelSize, pinSize};
    br_rsa_token_keygen(NULL,NULL,paramSizes,NULL,params,2048, 0);
}	
