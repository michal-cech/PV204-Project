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
    size_t labelSize = 6;
    unsigned char label[] = "labell";
    br_rsa_token_keygen(NULL,NULL,&labelSize,NULL,label,0, 0);
}	
