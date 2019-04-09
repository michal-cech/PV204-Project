#include "stdafx.h"

#include "Pkcs11Stub.h"	

#pragma warning (disable:4996)
#pragma warning (disable:4701)  // disable warning about potential unsued parameter - false alarm due to GETFUNCTIONPOINTERBYSESSION

#define GETFUNCTIONPOINTERBYSESSION(functName) CK_SESSION_HANDLE hRealSession; int sessionIndex; FT_##functName functPtr = NULL; if ((status = GetSessionIndex(hSession, &sessionIndex)) == CKR_OK) {if ((functPtr = (FT_##functName) GetProcAddress(m_sessionInfo[sessionIndex].dllLib, #functName)) == NULL) status = CKR_FUNCTION_NOT_SUPPORTED; hRealSession = m_sessionInfo[sessionIndex].realSessionHandle;}
#define GETFUNCTIONPOINTERBYSLOT(functName) CK_SLOT_ID realSlotID; FT_##functName functPtr = NULL; int slotIndex; if ((status = GetSlotIndex(slotID, &slotIndex)) == CKR_OK) {if ((functPtr = (FT_##functName) GetProcAddress(m_slotInfo[slotIndex].dllLib, #functName)) == NULL) status = CKR_FUNCTION_NOT_SUPPORTED; realSlotID = m_slotInfo[slotIndex].realSlotID;}

CPKCS11Stub::CPKCS11Stub() {
    memset(m_dllLibs, 0, sizeof(HINSTANCE) * MAX_DLL_LIBS);
    ClearSlotInfos();
    ClearSessionInfos();
}

CPKCS11Stub::~CPKCS11Stub() {
    int             i;
    FT_C_Finalize   fFinalize;

    for (i = 0; i < MAX_DLL_LIBS; i++) {
        if (m_dllLibs[i] != NULL) {
            // UNINITIALIZE LIBRARY
            fFinalize = NULL;
            if ((fFinalize = (FT_C_Finalize) GetProcAddress(m_dllLibs[i], "C_Finalize")) != NULL) {
                (fFinalize)(NULL);
            }
        }

    }
}

void CPKCS11Stub::ClearSlotInfos() {
    for (int i = 0; i < MAX_SLOTS; i++) m_slotInfo[i].clear();
}
void CPKCS11Stub::ClearSessionInfos() {
    for (int i = 0; i < MAX_SESSIONS; i++) m_sessionInfo[i].clear();
    m_nextVirtualSessionHandle = 1;
}

CK_RV CPKCS11Stub::GetSessionIndex(CK_SESSION_HANDLE virtSessionHandle, int* pSessionIndex) {
    CK_RV   status = CKR_SESSION_HANDLE_INVALID;
    int     i;
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (m_sessionInfo[i].valid && m_sessionInfo[i].virtualSessionHandle == virtSessionHandle) {
            *pSessionIndex = i;
            status = CKR_OK;
            break;
        }
    }

    return status;
}
CK_RV CPKCS11Stub::GetSlotIndex(CK_SLOT_ID virtSlotID, int* pSlotIndex) {
    CK_RV   status = CKR_SLOT_ID_INVALID;
    int     i;
    for (i = 0; i < MAX_SLOTS; i++) {
        if (m_slotInfo[i].valid && m_slotInfo[i].virtualSlotID == virtSlotID) {
            *pSlotIndex = i;
            status = CKR_OK;
            break;
        }
    }

    return status;
}


CK_RV CPKCS11Stub::Init(const TCHAR* dllPaths) {
    CK_RV   status = CKR_OK;
    size_t  pos1 = 0;
    size_t  pos2 = 0;
    int     actLib = 0;
    TCHAR   path[MAX_PATH];
    FT_C_Initialize fInitialize = NULL;


    // PARSE ';' SEPARATED ARRAY
    while ((pos2 = _tcscspn(dllPaths + pos1, _T(";"))) > 0) {
        memset(path, 0, MAX_PATH);
        _tcscpy_s(path, MAX_PATH, dllPaths + pos1);        

        pos1 += pos2 + 1;

        // TRY TO LOAD DLL's TO LIST
        if ((m_dllLibs[actLib] = LoadLibrary(path)) != NULL) {
            // INITIALIZE LIBRARY
            fInitialize = NULL;
            if ((fInitialize = (FT_C_Initialize) GetProcAddress(m_dllLibs[actLib], "C_Initialize")) != NULL) {
                (fInitialize)(NULL);
            }
            else status = GetLastError();

            actLib++;
        }
    }

    return CKR_OK; 
}

const char* CPKCS11Stub::GetMechanimsName(CK_MECHANISM_TYPE mechType) {
    switch (mechType) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN: return "CKM_RSA_PKCS_KEY_PAIR_GEN";      
        case CKM_RSA_PKCS: return "CKM_RSA_PKCS";                   
        case CKM_RSA_9796: return "CKM_RSA_9796";                   
        case CKM_RSA_X_509: return "CKM_RSA_X_509";                  

        /* CKM_MD2_RSA_PKCS, CKM_MD5_RSA_PKCS, and CKM_SHA1_RSA_PKCS
         * are new for v2.0.  They are mechanisms which hash and sign */
        case CKM_MD2_RSA_PKCS: return "CKM_MD2_RSA_PKCS";               
        case CKM_MD5_RSA_PKCS: return "CKM_MD5_RSA_PKCS";               
        case CKM_SHA1_RSA_PKCS: return "CKM_SHA1_RSA_PKCS";              

        case CKM_DSA_KEY_PAIR_GEN: return "CKM_DSA_KEY_PAIR_GEN";           
        case CKM_DSA: return "CKM_DSA";                        
        case CKM_DSA_SHA1: return "CKM_DSA_SHA1";                   
        case CKM_DH_PKCS_KEY_PAIR_GEN: return "CKM_DH_PKCS_KEY_PAIR_GEN";       
        case CKM_DH_PKCS_DERIVE: return "CKM_DH_PKCS_DERIVE";             
        case CKM_RC2_KEY_GEN: return "CKM_RC2_KEY_GEN";                
        case CKM_RC2_ECB: return "CKM_RC2_ECB";                    
        case CKM_RC2_CBC: return "CKM_RC2_CBC";                    
        case CKM_RC2_MAC: return "CKM_RC2_MAC";                    

        /* CKM_RC2_MAC_GENERAL and CKM_RC2_CBC_PAD are new for v2.0 */
        case CKM_RC2_MAC_GENERAL: return "CKM_RC2_MAC_GENERAL";            
        case CKM_RC2_CBC_PAD: return "CKM_RC2_CBC_PAD";                

        case CKM_RC4_KEY_GEN: return "CKM_RC4_KEY_GEN";                
        case CKM_RC4: return "CKM_RC4";                        
        case CKM_DES_KEY_GEN: return "CKM_DES_KEY_GEN";                
        case CKM_DES_ECB: return "CKM_DES_ECB";                    
        case CKM_DES_CBC: return "CKM_DES_CBC";                    
        case CKM_DES_MAC: return "CKM_DES_MAC";                    

        /* CKM_DES_MAC_GENERAL and CKM_DES_CBC_PAD are new for v2.0 */
        case CKM_DES_MAC_GENERAL: return "CKM_DES_MAC_GENERAL";            
        case CKM_DES_CBC_PAD: return "CKM_DES_CBC_PAD";                

        case CKM_DES2_KEY_GEN: return "CKM_DES2_KEY_GEN";               
        case CKM_DES3_KEY_GEN: return "CKM_DES3_KEY_GEN";               
        case CKM_DES3_ECB: return "CKM_DES3_ECB";                   
        case CKM_DES3_CBC: return "CKM_DES3_CBC";                   
        case CKM_DES3_MAC: return "CKM_DES3_MAC";                   

        /* CKM_DES3_MAC_GENERAL, CKM_DES3_CBC_PAD, CKM_CDMF_KEY_GEN,
         * CKM_CDMF_ECB, CKM_CDMF_CBC, CKM_CDMF_MAC,
         * CKM_CDMF_MAC_GENERAL, and CKM_CDMF_CBC_PAD are new for v2.0 */
        case CKM_DES3_MAC_GENERAL: return "CKM_DES3_MAC_GENERAL";           
        case CKM_DES3_CBC_PAD: return "CKM_DES3_CBC_PAD";               
        case CKM_CDMF_KEY_GEN: return "CKM_CDMF_KEY_GEN";               
        case CKM_CDMF_ECB: return "CKM_CDMF_ECB";                   
        case CKM_CDMF_CBC: return "CKM_CDMF_CBC";                   
        case CKM_CDMF_MAC: return "CKM_CDMF_MAC";                   
        case CKM_CDMF_MAC_GENERAL: return "CKM_CDMF_MAC_GENERAL";           
        case CKM_CDMF_CBC_PAD: return "CKM_CDMF_CBC_PAD";               

        case CKM_MD2: return "CKM_MD2";                        

        /* CKM_MD2_HMAC and CKM_MD2_HMAC_GENERAL are new for v2.0 */
        case CKM_MD2_HMAC: return "CKM_MD2_HMAC";                   
        case CKM_MD2_HMAC_GENERAL: return "CKM_MD2_HMAC_GENERAL";           

        case CKM_MD5: return "CKM_MD5";                        

        /* CKM_MD5_HMAC and CKM_MD5_HMAC_GENERAL are new for v2.0 */
        case CKM_MD5_HMAC: return "CKM_MD5_HMAC";                   
        case CKM_MD5_HMAC_GENERAL: return "CKM_MD5_HMAC_GENERAL";           

        case CKM_SHA_1: return "CKM_SHA_1";                      

        /* CKM_SHA_1_HMAC and CKM_SHA_1_HMAC_GENERAL are new for v2.0 */
        case CKM_SHA_1_HMAC: return "CKM_SHA_1_HMAC";                 
        case CKM_SHA_1_HMAC_GENERAL: return "CKM_SHA_1_HMAC_GENERAL";         

        /* All of the following mechanisms are new for v2.0 */
        /* Note that CAST128 and CAST5 are the same algorithm */
        case CKM_CAST_KEY_GEN: return "CKM_CAST_KEY_GEN";               
        case CKM_CAST_ECB: return "CKM_CAST_ECB";                   
        case CKM_CAST_CBC: return "CKM_CAST_CBC";                   
        case CKM_CAST_MAC: return "CKM_CAST_MAC";                   
        case CKM_CAST_MAC_GENERAL: return "CKM_CAST_MAC_GENERAL";           
        case CKM_CAST_CBC_PAD: return "CKM_CAST_CBC_PAD";               
        case CKM_CAST3_KEY_GEN: return "CKM_CAST3_KEY_GEN";              
        case CKM_CAST3_ECB: return "CKM_CAST3_ECB";                  
        case CKM_CAST3_CBC: return "CKM_CAST3_CBC";                  
        case CKM_CAST3_MAC: return "CKM_CAST3_MAC";                  
        case CKM_CAST3_MAC_GENERAL: return "CKM_CAST3_MAC_GENERAL";          
        case CKM_CAST3_CBC_PAD: return "CKM_CAST3_CBC_PAD";              
        case CKM_CAST128_KEY_GEN: return "CKM_CAST128_KEY_GEN";            
        case CKM_CAST128_ECB: return "CKM_CAST128_ECB";                
        case CKM_CAST128_CBC: return "CKM_CAST128_CBC";                
        case CKM_CAST128_MAC: return "CKM_CAST128_MAC";                
        case CKM_CAST128_MAC_GENERAL: return "CKM_CAST128_MAC_GENERAL";        
        case CKM_CAST128_CBC_PAD: return "CKM_CAST128_CBC_PAD";            
        case CKM_RC5_KEY_GEN: return "CKM_RC5_KEY_GEN";                
        case CKM_RC5_ECB: return "CKM_RC5_ECB";                    
        case CKM_RC5_CBC: return "CKM_RC5_CBC";                    
        case CKM_RC5_MAC: return "CKM_RC5_MAC";                    
        case CKM_RC5_MAC_GENERAL: return "CKM_RC5_MAC_GENERAL";            
        case CKM_RC5_CBC_PAD: return "CKM_RC5_CBC_PAD";                
        case CKM_IDEA_KEY_GEN: return "CKM_IDEA_KEY_GEN";               
        case CKM_IDEA_ECB: return "CKM_IDEA_ECB";                   
        case CKM_IDEA_CBC: return "CKM_IDEA_CBC";                   
        case CKM_IDEA_MAC: return "CKM_IDEA_MAC";                   
        case CKM_IDEA_MAC_GENERAL: return "CKM_IDEA_MAC_GENERAL";           
        case CKM_IDEA_CBC_PAD: return "CKM_IDEA_CBC_PAD";               
        case CKM_GENERIC_SECRET_KEY_GEN: return "CKM_GENERIC_SECRET_KEY_GEN";     
        case CKM_CONCATENATE_BASE_AND_KEY: return "CKM_CONCATENATE_BASE_AND_KEY";   
        case CKM_CONCATENATE_BASE_AND_DATA: return "CKM_CONCATENATE_BASE_AND_DATA";  
        case CKM_CONCATENATE_DATA_AND_BASE: return "CKM_CONCATENATE_DATA_AND_BASE";  
        case CKM_XOR_BASE_AND_DATA: return "CKM_XOR_BASE_AND_DATA";          
        case CKM_EXTRACT_KEY_FROM_KEY: return "CKM_EXTRACT_KEY_FROM_KEY";       
        case CKM_SSL3_PRE_MASTER_KEY_GEN: return "CKM_SSL3_PRE_MASTER_KEY_GEN";    
        case CKM_SSL3_MASTER_KEY_DERIVE: return "CKM_SSL3_MASTER_KEY_DERIVE";     
        case CKM_SSL3_KEY_AND_MAC_DERIVE: return "CKM_SSL3_KEY_AND_MAC_DERIVE";    
        case CKM_SSL3_MD5_MAC: return "CKM_SSL3_MD5_MAC";               
        case CKM_SSL3_SHA1_MAC: return "CKM_SSL3_SHA1_MAC";              
        case CKM_MD5_KEY_DERIVATION: return "CKM_MD5_KEY_DERIVATION";         
        case CKM_MD2_KEY_DERIVATION: return "CKM_MD2_KEY_DERIVATION";         
        case CKM_SHA1_KEY_DERIVATION: return "CKM_SHA1_KEY_DERIVATION";        
        case CKM_PBE_MD2_DES_CBC: return "CKM_PBE_MD2_DES_CBC";            
        case CKM_PBE_MD5_DES_CBC: return "CKM_PBE_MD5_DES_CBC";            
        case CKM_PBE_MD5_CAST_CBC: return "CKM_PBE_MD5_CAST_CBC";           
        case CKM_PBE_MD5_CAST3_CBC: return "CKM_PBE_MD5_CAST3_CBC";          
        case CKM_PBE_MD5_CAST128_CBC: return "CKM_PBE_MD5_CAST128_CBC";        
        case CKM_PBE_SHA1_CAST128_CBC: return "CKM_PBE_SHA1_CAST128_CBC";       
        case CKM_PBE_SHA1_RC4_128: return "CKM_PBE_SHA1_RC4_128";           
        case CKM_PBE_SHA1_RC4_40: return "CKM_PBE_SHA1_RC4_40";            
        case CKM_PBE_SHA1_DES3_EDE_CBC: return "CKM_PBE_SHA1_DES3_EDE_CBC";      
        case CKM_PBE_SHA1_DES2_EDE_CBC: return "CKM_PBE_SHA1_DES2_EDE_CBC";      
        case CKM_PBE_SHA1_RC2_128_CBC: return "CKM_PBE_SHA1_RC2_128_CBC";       
        case CKM_PBE_SHA1_RC2_40_CBC: return "CKM_PBE_SHA1_RC2_40_CBC";        
        case CKM_PBA_SHA1_WITH_SHA1_HMAC: return "CKM_PBA_SHA1_WITH_SHA1_HMAC";    
        case CKM_KEY_WRAP_LYNKS: return "CKM_KEY_WRAP_LYNKS";             
        case CKM_KEY_WRAP_SET_OAEP: return "CKM_KEY_WRAP_SET_OAEP";          

        /* Fortezza mechanisms */
        case CKM_SKIPJACK_KEY_GEN: return "CKM_SKIPJACK_KEY_GEN";           
        case CKM_SKIPJACK_ECB64: return "CKM_SKIPJACK_ECB64";             
        case CKM_SKIPJACK_CBC64: return "CKM_SKIPJACK_CBC64";             
        case CKM_SKIPJACK_OFB64: return "CKM_SKIPJACK_OFB64";             
        case CKM_SKIPJACK_CFB64: return "CKM_SKIPJACK_CFB64";             
        case CKM_SKIPJACK_CFB32: return "CKM_SKIPJACK_CFB32";             
        case CKM_SKIPJACK_CFB16: return "CKM_SKIPJACK_CFB16";             
        case CKM_SKIPJACK_CFB8: return "CKM_SKIPJACK_CFB8";              
        case CKM_SKIPJACK_WRAP: return "CKM_SKIPJACK_WRAP";              
        case CKM_SKIPJACK_PRIVATE_WRAP: return "CKM_SKIPJACK_PRIVATE_WRAP";      
        case CKM_SKIPJACK_RELAYX: return "CKM_SKIPJACK_RELAYX";            
        case CKM_KEA_KEY_PAIR_GEN: return "CKM_KEA_KEY_PAIR_GEN";           
        case CKM_KEA_KEY_DERIVE: return "CKM_KEA_KEY_DERIVE";             
        case CKM_FORTEZZA_TIMESTAMP: return "CKM_FORTEZZA_TIMESTAMP";         
        case CKM_BATON_KEY_GEN: return "CKM_BATON_KEY_GEN";              
        case CKM_BATON_ECB128: return "CKM_BATON_ECB128";               
        case CKM_BATON_ECB96: return "CKM_BATON_ECB96";                
        case CKM_BATON_CBC128: return "CKM_BATON_CBC128";               
        case CKM_BATON_COUNTER: return "CKM_BATON_COUNTER";              
        case CKM_BATON_SHUFFLE: return "CKM_BATON_SHUFFLE";              
        case CKM_BATON_WRAP: return "CKM_BATON_WRAP";                 
        case CKM_ECDSA_KEY_PAIR_GEN: return "CKM_ECDSA_KEY_PAIR_GEN";         
        case CKM_ECDSA: return "CKM_ECDSA";                      
        case CKM_ECDSA_SHA1: return "CKM_ECDSA_SHA1";                 
        case CKM_JUNIPER_KEY_GEN: return "CKM_JUNIPER_KEY_GEN";            
        case CKM_JUNIPER_ECB128: return "CKM_JUNIPER_ECB128";             
        case CKM_JUNIPER_CBC128: return "CKM_JUNIPER_CBC128";             
        case CKM_JUNIPER_COUNTER: return "CKM_JUNIPER_COUNTER";            
        case CKM_JUNIPER_SHUFFLE: return "CKM_JUNIPER_SHUFFLE";            
        case CKM_JUNIPER_WRAP: return "CKM_JUNIPER_WRAP";               
        case CKM_FASTHASH: return "CKM_FASTHASH";                   
        default: return "CKM_unknown";  
    }
}

const char* CPKCS11Stub::ErrorToString(CK_RV status) {
    switch (status) { 
        case CKR_OK: return "CKR_OK";                                
        case CKR_CANCEL: return "CKR_CANCEL";                            
        case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";                       
        case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";                   

        /* CKR_FLAGS_INVALID was removed for v2.0 */

        /* CKR_GENERAL_ERROR and CKR_FUNCTION_FAILED are new for v2.0 */
        case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";                     
        case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";                   

        /* CKR_ARGUMENTS_BAD, CKR_NO_EVENT, CKR_NEED_TO_CREATE_THREADS,
         * and CKR_CANT_LOCK are new for v2.01 */
        case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";                     
        case CKR_NO_EVENT: return "CKR_NO_EVENT";                          
        case CKR_NEED_TO_CREATE_THREADS: return "CKR_NEED_TO_CREATE_THREADS";            
        case CKR_CANT_LOCK: return "CKR_CANT_LOCK";                         

        case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";               
        case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";               
        case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";            
        case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";           
        case CKR_DATA_INVALID: return "CKR_DATA_INVALID";                      
        case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";                    
        case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";                      
        case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";                     
        case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";                    
        case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";            
        case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";          
        case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";                 
        case CKR_FUNCTION_NOT_PARALLEL: return "CKR_FUNCTION_NOT_PARALLEL";             

        /* CKR_FUNCTION_NOT_SUPPORTED is new for v2.0 */
        case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";            

        case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";                

        /* CKR_KEY_SENSITIVE was removed for v2.0 */

        case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";                    
        case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";             

        /* CKR_KEY_NOT_NEEDED, CKR_KEY_CHANGED, CKR_KEY_NEEDED,
         * CKR_KEY_INDIGESTIBLE, CKR_KEY_FUNCTION_NOT_PERMITTED,
         * CKR_KEY_NOT_WRAPPABLE, and CKR_KEY_UNEXTRACTABLE are new for
         * v2.0 */
        case CKR_KEY_NOT_NEEDED: return "CKR_KEY_NOT_NEEDED";                    
        case CKR_KEY_CHANGED: return "CKR_KEY_CHANGED";                       
        case CKR_KEY_NEEDED: return "CKR_KEY_NEEDED";                        
        case CKR_KEY_INDIGESTIBLE: return "CKR_KEY_INDIGESTIBLE";                  
        case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";        
        case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";                 
        case CKR_KEY_UNEXTRACTABLE: return "CKR_KEY_UNEXTRACTABLE";                 

        case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";                 
        case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";           

        /* CKR_OBJECT_CLASS_INCONSISTENT and CKR_OBJECT_CLASS_INVALID
         * were removed for v2.0 */
        case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";             
        case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";                  
        case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";         
        case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";                     
        case CKR_PIN_INVALID: return "CKR_PIN_INVALID";                       
        case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";                     

        /* CKR_PIN_EXPIRED and CKR_PIN_LOCKED are new for v2.0 */
        case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";                       
        case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";                        

        case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";                    
        case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";                     
        case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";            
        case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";    
        case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";                 
        case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";                    

        /* CKR_SESSION_READ_ONLY_EXISTS and
         * CKR_SESSION_READ_WRITE_SO_EXISTS are new for v2.0 */
        case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";          
        case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";      

        case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";                 
        case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";               
        case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";               
        case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";             
        case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";                 
        case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";              
        case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";             
        case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";     
        case CKR_UNWRAPPING_KEY_SIZE_RANGE: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";         
        case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";  
        case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";            
        case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";                
        case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";          
        case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";                 

        /* CKR_USER_ANOTHER_ALREADY_LOGGED_IN and CKR_USER_TOO_MANY_TYPES
         * are new to v2.01 */
        case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";    
        case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";               

        case CKR_WRAPPED_KEY_INVALID: return "CKR_WRAPPED_KEY_INVALID";               
        case CKR_WRAPPED_KEY_LEN_RANGE: return "CKR_WRAPPED_KEY_LEN_RANGE";             
        case CKR_WRAPPING_KEY_HANDLE_INVALID: return "CKR_WRAPPING_KEY_HANDLE_INVALID";       
        case CKR_WRAPPING_KEY_SIZE_RANGE: return "CKR_WRAPPING_KEY_SIZE_RANGE";           
        case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";    
        case CKR_RANDOM_SEED_NOT_SUPPORTED: return "CKR_RANDOM_SEED_NOT_SUPPORTED";         

        /* These are new to v2.0 */
        case CKR_RANDOM_NO_RNG: return "CKR_RANDOM_NO_RNG";                     
        case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";                  
        case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";               
        case CKR_INFORMATION_SENSITIVE: return "CKR_INFORMATION_SENSITIVE";             
        case CKR_STATE_UNSAVEABLE: return "CKR_STATE_UNSAVEABLE";                  

        /* These are new to v2.01 */
        case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";         
        case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";      
        case CKR_MUTEX_BAD: return "CKR_MUTEX_BAD";                         
        case CKR_MUTEX_NOT_LOCKED: return "CKR_MUTEX_NOT_LOCKED";                  
        default: return "CKR_unknown"; 
    }
}

CK_RV CPKCS11Stub::C_GetSlotList(
		CK_BBOOL tokenPresent,
		CK_SLOT_ID_PTR pSlotList,
        CK_ULONG_PTR pusCount) {
    CK_RV   status = CKR_OK;
    CK_RV   retStat;
    
    CK_SLOT_ID      pSlots[MAX_SLOTS];
    CK_ULONG        slotCount = MAX_SLOTS;
    int             virtualID = SLOT_VIRTUAL_ID_BASE;
    int             slotInfoIndex = 0;
    CK_ULONG        i;
    CK_ULONG        j;
    FT_C_GetSlotList    fGetSlotList;

    // CLEAR PREVIOUS SLOT ID STRUCT
    ClearSlotInfos();

    // PROCESS ALL LOADED LIBRARIES
    for (i = 0; i < MAX_DLL_LIBS; i++) {
        if (m_dllLibs[i] != NULL) {
            // GET SLOTS FOR ACTUAL LIBRARY
            fGetSlotList = NULL;
            if ((fGetSlotList = (FT_C_GetSlotList) GetProcAddress(m_dllLibs[i], "C_GetSlotList")) != NULL) {
                slotCount = MAX_SLOTS;
                memset(pSlots, 0, sizeof(CK_SLOT_ID) * MAX_SLOTS);
                if ((retStat = (fGetSlotList)(tokenPresent, pSlots, &slotCount)) == CKR_OK) {
                
                    // ASSIGN VIRTUAL ID AND STORE REAL ONE
                    for (j = 0; j < slotCount; j++) {
                        m_slotInfo[slotInfoIndex].valid = TRUE;
                        m_slotInfo[slotInfoIndex].dllLib = m_dllLibs[i];
                        m_slotInfo[slotInfoIndex].realSlotID = pSlots[j];                            
                        m_slotInfo[slotInfoIndex].virtualSlotID = virtualID;                            

                        virtualID++;
                        slotInfoIndex++;
                    }
                }
            }
        }
    }

    if (status == CKR_OK) {
        DWORD   numValidSlots = 0;
        // COUNT NUMBER OF VALID SLOTS
        for (int i = 0; i < MAX_SLOTS; i++) {
            if (m_slotInfo[i].valid) numValidSlots++;
        }
        
        // ASSIGN TO RETURN STRUCTURE IF ENOUGH SPACE
        if (pSlotList == NULL) {
            *pusCount = numValidSlots;
        }
        else {
            DWORD   virtualIDAssigned = 0;
            if (numValidSlots <= *pusCount) { 
                for (int i = 0; i < MAX_SLOTS; i++) {
                    if (m_slotInfo[i].valid) {
                        pSlotList[virtualIDAssigned] = m_slotInfo[i].virtualSlotID;
                        virtualIDAssigned++;
                    }
                }
                
                *pusCount = virtualIDAssigned;
            }
            else {
                status = CKR_BUFFER_TOO_SMALL;
                *pusCount = numValidSlots;
            }
        }
    }

    return status;
}

CK_RV  CPKCS11Stub::C_GetSlotInfo(
	CK_SLOT_ID slotID,
    CK_SLOT_INFO_PTR pInfo) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSLOT(C_GetSlotInfo);
    if (status == CKR_OK) status = (functPtr)(realSlotID, pInfo); 
    return status;
}

CK_RV  CPKCS11Stub::C_GetTokenInfo(
	CK_SLOT_ID slotID,
	CK_TOKEN_INFO_PTR pInfo) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSLOT(C_GetTokenInfo);
    if (status == CKR_OK) status = (functPtr)(realSlotID, pInfo); 
    return status;
}
CK_RV CPKCS11Stub::C_GetMechanismList(
  CK_SLOT_ID            slotID,          
  CK_MECHANISM_TYPE_PTR pMechanismList,  
  CK_ULONG_PTR          pulCount         
  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSLOT(C_GetMechanismList);
    if (status == CKR_OK) status = (functPtr)(realSlotID, pMechanismList, pulCount); 
    return status;
}

CK_RV  CPKCS11Stub::C_GetMechanismInfo(
	CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE type,
	CK_MECHANISM_INFO_PTR pInfo) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSLOT(C_GetMechanismInfo);
    if (status == CKR_OK) status = (functPtr)(realSlotID, type, pInfo); 
    return status;
}

CK_RV  CPKCS11Stub::C_OpenSession(
	CK_SLOT_ID slotID,
	CK_FLAGS flags,
	CK_VOID_PTR pApplication,
	CK_NOTIFY Notify,
    CK_SESSION_HANDLE_PTR phSession) {
    
    CK_RV               status = CKR_OK;
    int                 i;
    int                 slotIndex;
    FT_C_OpenSession    fOpenSession;

    if ((status = GetSlotIndex(slotID, &slotIndex)) == CKR_OK) {
        //_ASSERT(m_slotInfo[slotIndex].virtualSlotID == slotID);

         // FIND FREE SESSION ENTRY
        for (i = 0; i < MAX_SESSIONS; i++) {
            if (m_sessionInfo[i].valid == FALSE) break;
        }

        if (i == MAX_SESSIONS) status = CKR_TOO_MANY_SESSIONS;
        else {
            // USE LIBRARY BY GIVEN VIRTUAL SLOT ID 
            fOpenSession = NULL;
            if ((fOpenSession = (FT_C_OpenSession) GetProcAddress(m_slotInfo[slotIndex].dllLib, "C_OpenSession")) != NULL) {
                status = (fOpenSession)(m_slotInfo[slotIndex].realSlotID, flags, pApplication, Notify, &(m_sessionInfo[i].realSessionHandle));
                
                // FILL NEW SESSION STRUCT
                if (status == CKR_OK) {
                    m_sessionInfo[i].valid = TRUE;
                    m_sessionInfo[i].dllLib = m_slotInfo[slotIndex].dllLib;
                    m_sessionInfo[i].virtualSessionHandle = m_nextVirtualSessionHandle;
                    m_sessionInfo[i].virtualSlotID = slotID;
                    *phSession = m_nextVirtualSessionHandle;
                    m_nextVirtualSessionHandle++;
                }
            }
            else status = CKR_FUNCTION_NOT_SUPPORTED;
        }
    }
        
    return status;
}

CK_RV  CPKCS11Stub::C_CloseSession(
    CK_SESSION_HANDLE hSession) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_CloseSession);
    if (status == CKR_OK) status = (functPtr)(hRealSession); 

    // INVALIDATE SESSION STRUCT        
    m_sessionInfo[sessionIndex].clear();

    return status;
}


CK_RV CPKCS11Stub::C_InitToken(
  CK_SLOT_ID     slotID,    
  CK_CHAR_PTR    pPin,      
  CK_ULONG       ulPinLen,  
  CK_CHAR_PTR    pLabel     ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSLOT(C_InitToken);
    if (status == CKR_OK) status = (functPtr)(realSlotID, pPin, ulPinLen, pLabel); 
    return status;

}

CK_RV CPKCS11Stub::C_InitPIN(
  CK_SESSION_HANDLE hSession,  
  CK_CHAR_PTR       pPin,      
  CK_ULONG          ulPinLen   ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_InitPIN);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pPin, ulPinLen); 
    return status;

}

CK_RV CPKCS11Stub::C_SetPIN(
  CK_SESSION_HANDLE hSession,  
  CK_CHAR_PTR       pOldPin,   
  CK_ULONG          ulOldLen,  
  CK_CHAR_PTR       pNewPin,   
  CK_ULONG          ulNewLen   ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_SetPIN);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pOldPin, ulOldLen, pNewPin, ulNewLen); 
    return status;

}

CK_RV CPKCS11Stub::C_CloseAllSessions(
  CK_SLOT_ID     slotID  ) {

    CK_RV       status = CKR_OK;
    int         i;

    for (i = 0; i < MAX_SESSIONS; i++) {
        if (m_sessionInfo[i].valid) {
            C_CloseSession(m_sessionInfo[i].virtualSessionHandle);
        }
    }
    return status;
}

CK_RV CPKCS11Stub::C_GetSessionInfo(
  CK_SESSION_HANDLE   hSession,  
  CK_SESSION_INFO_PTR pInfo      ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_GetSessionInfo);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pInfo); 
    return status;

}

CK_RV CPKCS11Stub::C_GetOperationState(
  CK_SESSION_HANDLE hSession,             
  CK_BYTE_PTR       pOperationState,      
  CK_ULONG_PTR      pulOperationStateLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_GetOperationState);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pOperationState, pulOperationStateLen); 
    return status;

}

CK_RV CPKCS11Stub::C_SetOperationState(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR      pOperationState,      
  CK_ULONG         ulOperationStateLen,  
  CK_OBJECT_HANDLE hEncryptionKey,       
  CK_OBJECT_HANDLE hAuthenticationKey    ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_SetOperationState);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey); 
    return status;

}

CK_RV CPKCS11Stub::C_Login(
  CK_SESSION_HANDLE hSession,  
  CK_USER_TYPE      userType,  
  CK_CHAR_PTR       pPin,      
  CK_ULONG          ulPinLen   ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_Login);
    if (status == CKR_OK) status = (functPtr)(hRealSession, userType, pPin, ulPinLen); 
    return status;

}

CK_RV CPKCS11Stub::C_Logout(
  CK_SESSION_HANDLE hSession  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_Logout);
    if (status == CKR_OK) status = (functPtr)(hRealSession); 
    return status;

}

CK_RV CPKCS11Stub::C_CreateObject(
  CK_SESSION_HANDLE hSession,    
  CK_ATTRIBUTE_PTR  pTemplate,   
  CK_ULONG          ulCount,     
  CK_OBJECT_HANDLE_PTR phObject  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_CreateObject);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pTemplate, ulCount, phObject); 
    return status;

}

CK_RV CPKCS11Stub::C_CopyObject(
  CK_SESSION_HANDLE    hSession,    
  CK_OBJECT_HANDLE     hObject,     
  CK_ATTRIBUTE_PTR     pTemplate,   
  CK_ULONG             ulCount,     
  CK_OBJECT_HANDLE_PTR phNewObject  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_CopyObject);
    if (status == CKR_OK) status = (functPtr)(hRealSession, hObject, pTemplate, ulCount, phNewObject); 
    return status;

}

CK_RV CPKCS11Stub::C_DestroyObject(
  CK_SESSION_HANDLE hSession,  
  CK_OBJECT_HANDLE  hObject    ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_DestroyObject);
    if (status == CKR_OK) status = (functPtr)(hRealSession, hObject); 
    return status;

}

CK_RV CPKCS11Stub::C_GetObjectSize(
  CK_SESSION_HANDLE hSession,  
  CK_OBJECT_HANDLE  hObject,   
  CK_ULONG_PTR      pulSize    ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_GetObjectSize);
    if (status == CKR_OK) status = (functPtr)(hRealSession, hObject, pulSize); 
    return status;

}

CK_RV CPKCS11Stub::C_GetAttributeValue(
  CK_SESSION_HANDLE hSession,   
  CK_OBJECT_HANDLE  hObject,    
  CK_ATTRIBUTE_PTR  pTemplate,  
  CK_ULONG          ulCount     ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_GetAttributeValue);
    if (status == CKR_OK) status = (functPtr)(hRealSession, hObject, pTemplate, ulCount); 
    return status;

}

CK_RV CPKCS11Stub::C_SetAttributeValue(
  CK_SESSION_HANDLE hSession,   
  CK_OBJECT_HANDLE  hObject,    
  CK_ATTRIBUTE_PTR  pTemplate,  
  CK_ULONG          ulCount     ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_SetAttributeValue);
    if (status == CKR_OK) status = (functPtr)(hRealSession, hObject, pTemplate, ulCount); 
    return status;

}

CK_RV CPKCS11Stub::C_FindObjectsInit(
  CK_SESSION_HANDLE hSession,   
  CK_ATTRIBUTE_PTR  pTemplate,  
  CK_ULONG          ulCount     ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_FindObjectsInit);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pTemplate, ulCount); 
    return status;

}

CK_RV CPKCS11Stub::C_FindObjects(
 CK_SESSION_HANDLE    hSession,          
 CK_OBJECT_HANDLE_PTR phObject,          
 CK_ULONG             ulMaxObjectCount,  
 CK_ULONG_PTR         pulObjectCount     ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_FindObjects);
    if (status == CKR_OK) status = (functPtr)(hRealSession, phObject, ulMaxObjectCount, pulObjectCount); 
    return status;

}

CK_RV CPKCS11Stub::C_FindObjectsFinal(
  CK_SESSION_HANDLE hSession  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_FindObjectsFinal);
    if (status == CKR_OK) status = (functPtr)(hRealSession); 
    return status;

}

CK_RV CPKCS11Stub::C_EncryptInit(
  CK_SESSION_HANDLE hSession,    
  CK_MECHANISM_PTR  pMechanism,  
  CK_OBJECT_HANDLE  hKey         ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_EncryptInit);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pMechanism, hKey); 
    return status;

}

CK_RV CPKCS11Stub::C_Encrypt(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR       pData,               
  CK_ULONG          ulDataLen,           
  CK_BYTE_PTR       pEncryptedData,      
  CK_ULONG_PTR      pulEncryptedDataLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_Encrypt);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen); 
    return status;

}

CK_RV CPKCS11Stub::C_EncryptUpdate(
  CK_SESSION_HANDLE hSession,           
  CK_BYTE_PTR       pPart,              
  CK_ULONG          ulPartLen,          
  CK_BYTE_PTR       pEncryptedPart,     
  CK_ULONG_PTR      pulEncryptedPartLen ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_EncryptUpdate);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen); 
    return status;

}

CK_RV CPKCS11Stub::C_EncryptFinal(
  CK_SESSION_HANDLE hSession,                
  CK_BYTE_PTR       pLastEncryptedPart,      
  CK_ULONG_PTR      pulLastEncryptedPartLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_EncryptFinal);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pLastEncryptedPart, pulLastEncryptedPartLen); 
    return status;

}

CK_RV CPKCS11Stub::C_DecryptInit(
  CK_SESSION_HANDLE hSession,    
  CK_MECHANISM_PTR  pMechanism,  
  CK_OBJECT_HANDLE  hKey         ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_DecryptInit);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pMechanism, hKey); 
    return status;

}

CK_RV CPKCS11Stub::C_Decrypt(
  CK_SESSION_HANDLE hSession,           
  CK_BYTE_PTR       pEncryptedData,     
  CK_ULONG          ulEncryptedDataLen, 
  CK_BYTE_PTR       pData,              
  CK_ULONG_PTR      pulDataLen          ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_Decrypt);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen); 
    return status;

}

CK_RV CPKCS11Stub::C_DecryptUpdate(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR       pEncryptedPart,      
  CK_ULONG          ulEncryptedPartLen,  
  CK_BYTE_PTR       pPart,               
  CK_ULONG_PTR      pulPartLen           ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_DecryptUpdate);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen); 
    return status;

}

CK_RV CPKCS11Stub::C_DecryptFinal(
  CK_SESSION_HANDLE hSession,       
  CK_BYTE_PTR       pLastPart,      
  CK_ULONG_PTR      pulLastPartLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_DecryptFinal);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pLastPart, pulLastPartLen); 
    return status;

}

CK_RV CPKCS11Stub::C_DigestInit(
  CK_SESSION_HANDLE hSession,   
  CK_MECHANISM_PTR  pMechanism  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_DigestInit);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pMechanism); 
    return status;

}

CK_RV CPKCS11Stub::C_Digest(
  CK_SESSION_HANDLE hSession,     
  CK_BYTE_PTR       pData,        
  CK_ULONG          ulDataLen,    
  CK_BYTE_PTR       pDigest,      
  CK_ULONG_PTR      pulDigestLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_Digest);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pData, ulDataLen, pDigest, pulDigestLen); 
    return status;

}

CK_RV CPKCS11Stub::C_DigestUpdate(
  CK_SESSION_HANDLE hSession,  
  CK_BYTE_PTR       pPart,     
  CK_ULONG          ulPartLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_DigestUpdate);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pPart, ulPartLen); 
    return status;

}

CK_RV CPKCS11Stub::C_DigestKey(
  CK_SESSION_HANDLE hSession,  
  CK_OBJECT_HANDLE  hKey       ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_DigestKey);
    if (status == CKR_OK) status = (functPtr)(hRealSession, hKey); 
    return status;

}



CK_RV CPKCS11Stub::C_DigestFinal(
  CK_SESSION_HANDLE hSession,     
  CK_BYTE_PTR       pDigest,      
  CK_ULONG_PTR      pulDigestLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_DigestFinal);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pDigest, pulDigestLen); 
    return status;

}


CK_RV CPKCS11Stub::C_SignInit(
  CK_SESSION_HANDLE hSession,    
  CK_MECHANISM_PTR  pMechanism,  
  CK_OBJECT_HANDLE  hKey         ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_SignInit);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pMechanism, hKey); 
    return status;

}

CK_RV CPKCS11Stub::C_Sign(
  CK_SESSION_HANDLE hSession,        
  CK_BYTE_PTR       pData,           
  CK_ULONG          ulDataLen,       
  CK_BYTE_PTR       pSignature,      
  CK_ULONG_PTR      pulSignatureLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_Sign);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pData, ulDataLen, pSignature, pulSignatureLen); 
    return status;

}

CK_RV CPKCS11Stub::C_SignUpdate(
  CK_SESSION_HANDLE hSession,  
  CK_BYTE_PTR       pPart,     
  CK_ULONG          ulPartLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_SignUpdate);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pPart, ulPartLen); 
    return status;

}

CK_RV CPKCS11Stub::C_SignFinal(
  CK_SESSION_HANDLE hSession,        
  CK_BYTE_PTR       pSignature,      
  CK_ULONG_PTR      pulSignatureLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_SignFinal);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pSignature, pulSignatureLen); 
    return status;

}

CK_RV CPKCS11Stub::C_SignRecoverInit(
  CK_SESSION_HANDLE hSession,   
  CK_MECHANISM_PTR  pMechanism, 
  CK_OBJECT_HANDLE  hKey        ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_SignRecoverInit);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pMechanism, hKey); 
    return status;

}

CK_RV CPKCS11Stub::C_SignRecover(
  CK_SESSION_HANDLE hSession,        
  CK_BYTE_PTR       pData,           
  CK_ULONG          ulDataLen,       
  CK_BYTE_PTR       pSignature,      
  CK_ULONG_PTR      pulSignatureLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_SignRecover);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pData, ulDataLen, pSignature, pulSignatureLen); 
    return status;

}

CK_RV CPKCS11Stub::C_VerifyInit(
  CK_SESSION_HANDLE hSession,    
  CK_MECHANISM_PTR  pMechanism,  
  CK_OBJECT_HANDLE  hKey          ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_VerifyInit);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pMechanism, hKey); 
    return status;

}

CK_RV CPKCS11Stub::C_Verify(
  CK_SESSION_HANDLE hSession,       
  CK_BYTE_PTR       pData,          
  CK_ULONG          ulDataLen,      
  CK_BYTE_PTR       pSignature,     
  CK_ULONG          ulSignatureLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_Verify);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pData, ulDataLen, pSignature, ulSignatureLen); 
    return status;

}

CK_RV CPKCS11Stub::C_VerifyUpdate(
  CK_SESSION_HANDLE hSession,  
  CK_BYTE_PTR       pPart,     
  CK_ULONG          ulPartLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_VerifyUpdate);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pPart, ulPartLen); 
    return status;

}

CK_RV CPKCS11Stub::C_VerifyFinal(
  CK_SESSION_HANDLE hSession,       
  CK_BYTE_PTR       pSignature,     
  CK_ULONG          ulSignatureLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_VerifyFinal);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pSignature, ulSignatureLen); 
    return status;

}

CK_RV CPKCS11Stub::C_VerifyRecoverInit(
  CK_SESSION_HANDLE hSession,    
  CK_MECHANISM_PTR  pMechanism,  
  CK_OBJECT_HANDLE  hKey         ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_VerifyRecoverInit);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pMechanism, hKey); 
    return status;

}

CK_RV CPKCS11Stub::C_VerifyRecover(
  CK_SESSION_HANDLE hSession,        
  CK_BYTE_PTR       pSignature,      
  CK_ULONG          ulSignatureLen,  
  CK_BYTE_PTR       pData,           
  CK_ULONG_PTR      pulDataLen       ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_VerifyRecover);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pSignature, ulSignatureLen, pData, pulDataLen); 
    return status;

}

CK_RV CPKCS11Stub::C_DigestEncryptUpdate(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR       pPart,               
  CK_ULONG          ulPartLen,           
  CK_BYTE_PTR       pEncryptedPart,      
  CK_ULONG_PTR      pulEncryptedPartLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_DigestEncryptUpdate);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen); 
    return status;

}

CK_RV CPKCS11Stub::C_DecryptDigestUpdate(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR       pEncryptedPart,      
  CK_ULONG          ulEncryptedPartLen,  
  CK_BYTE_PTR       pPart,               
  CK_ULONG_PTR      pulPartLen           ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_DecryptDigestUpdate);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen); 
    return status;

}

CK_RV CPKCS11Stub::C_SignEncryptUpdate(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR       pPart,               
  CK_ULONG          ulPartLen,           
  CK_BYTE_PTR       pEncryptedPart,      
  CK_ULONG_PTR      pulEncryptedPartLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_SignEncryptUpdate);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen); 
    return status;

}

CK_RV CPKCS11Stub::C_DecryptVerifyUpdate(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR       pEncryptedPart,      
  CK_ULONG          ulEncryptedPartLen,  
  CK_BYTE_PTR       pPart,               
  CK_ULONG_PTR      pulPartLen           ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_DecryptVerifyUpdate);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen); 
    return status;

}

CK_RV CPKCS11Stub::C_GenerateKey(
  CK_SESSION_HANDLE    hSession,    
  CK_MECHANISM_PTR     pMechanism,  
  CK_ATTRIBUTE_PTR     pTemplate,   
  CK_ULONG             ulCount,     
  CK_OBJECT_HANDLE_PTR phKey        ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_GenerateKey);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pMechanism, pTemplate, ulCount, phKey); 
    return status;

}

CK_RV CPKCS11Stub::C_GenerateKeyPair(
  CK_SESSION_HANDLE    hSession,                    
  CK_MECHANISM_PTR     pMechanism,                  
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          
  CK_ULONG             ulPublicKeyAttributeCount,   
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         
  CK_ULONG             ulPrivateKeyAttributeCount,  
  CK_OBJECT_HANDLE_PTR phPublicKey,                 
  CK_OBJECT_HANDLE_PTR phPrivateKey                 ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_GenerateKeyPair);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey); 
    return status;

}

CK_RV CPKCS11Stub::C_WrapKey(
  CK_SESSION_HANDLE hSession,        
  CK_MECHANISM_PTR  pMechanism,      
  CK_OBJECT_HANDLE  hWrappingKey,    
  CK_OBJECT_HANDLE  hKey,            
  CK_BYTE_PTR       pWrappedKey,     
  CK_ULONG_PTR      pulWrappedKeyLen ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_WrapKey);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen); 
    return status;

}

CK_RV CPKCS11Stub::C_UnwrapKey(
  CK_SESSION_HANDLE    hSession,          
  CK_MECHANISM_PTR     pMechanism,        
  CK_OBJECT_HANDLE     hUnwrappingKey,    
  CK_BYTE_PTR          pWrappedKey,       
  CK_ULONG             ulWrappedKeyLen,   
  CK_ATTRIBUTE_PTR     pTemplate,         
  CK_ULONG             ulAttributeCount,  
  CK_OBJECT_HANDLE_PTR phKey              ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_UnwrapKey);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey); 
    return status;

}

CK_RV CPKCS11Stub::C_DeriveKey(
  CK_SESSION_HANDLE    hSession,          
  CK_MECHANISM_PTR     pMechanism,        
  CK_OBJECT_HANDLE     hBaseKey,          
  CK_ATTRIBUTE_PTR     pTemplate,         
  CK_ULONG             ulAttributeCount,  
  CK_OBJECT_HANDLE_PTR phKey              ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_DeriveKey);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey); 
    return status;

}

CK_RV CPKCS11Stub::C_SeedRandom(
  CK_SESSION_HANDLE hSession,  
  CK_BYTE_PTR       pSeed,     
  CK_ULONG          ulSeedLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_SeedRandom);
    if (status == CKR_OK) status = (functPtr)(hRealSession, pSeed, ulSeedLen); 
    return status;

}

CK_RV CPKCS11Stub::C_GenerateRandom(
  CK_SESSION_HANDLE hSession,    
  CK_BYTE_PTR       RandomData,  
  CK_ULONG          ulRandomLen  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_GenerateRandom);
    if (status == CKR_OK) status = (functPtr)(hRealSession, RandomData, ulRandomLen); 
    return status;

}


CK_RV CPKCS11Stub::C_GetFunctionStatus(
  CK_SESSION_HANDLE hSession  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_GetFunctionStatus);
    if (status == CKR_OK) status = (functPtr)(hRealSession); 
    return status;

}

CK_RV CPKCS11Stub::C_CancelFunction(
  CK_SESSION_HANDLE hSession  ) {

    CK_RV       status = CKR_OK;
    GETFUNCTIONPOINTERBYSESSION(C_CancelFunction);
    if (status == CKR_OK) status = (functPtr)(hRealSession); 
    return status;

}
