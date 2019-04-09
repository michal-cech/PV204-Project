



typedef CK_RV CK_ENTRY (*FT_C_Initialize)(
  CK_VOID_PTR   pInitArgs  
);
typedef CK_RV CK_ENTRY (*FT_C_Finalize)(
  CK_VOID_PTR   pReserved  
);


typedef CK_RV CK_ENTRY (*FT_C_GetInfo)(
  CK_INFO_PTR   pInfo  
);

typedef CK_RV CK_ENTRY (*FT_C_GetFunctionList)(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList  
                                           
);

typedef CK_RV CK_ENTRY (*FT_C_GetSlotList)(
  CK_BBOOL       tokenPresent,  
  CK_SLOT_ID_PTR pSlotList,     
  CK_ULONG_PTR   pulCount       
);

typedef CK_RV CK_ENTRY (*FT_C_GetSlotInfo)(
  CK_SLOT_ID       slotID,  
  CK_SLOT_INFO_PTR pInfo    
);

typedef CK_RV CK_ENTRY (*FT_C_GetTokenInfo)(
  CK_SLOT_ID        slotID,  
  CK_TOKEN_INFO_PTR pInfo    
);

typedef CK_RV CK_ENTRY (*FT_C_GetMechanismList)(
  CK_SLOT_ID            slotID,          
  CK_MECHANISM_TYPE_PTR pMechanismList,  
  CK_ULONG_PTR          pulCount         
);

typedef CK_RV CK_ENTRY (*FT_C_GetMechanismInfo)(
  CK_SLOT_ID            slotID,  
  CK_MECHANISM_TYPE     type,    
  CK_MECHANISM_INFO_PTR pInfo    
);

typedef CK_RV CK_ENTRY (*FT_C_InitToken)(
  CK_SLOT_ID     slotID,    
  CK_CHAR_PTR    pPin,      
  CK_ULONG       ulPinLen,  
  CK_CHAR_PTR    pLabel     
);

typedef CK_RV CK_ENTRY (*FT_C_InitPIN)(
  CK_SESSION_HANDLE hSession,  
  CK_CHAR_PTR       pPin,      
  CK_ULONG          ulPinLen   
);

typedef CK_RV CK_ENTRY (*FT_C_SetPIN)(
  CK_SESSION_HANDLE hSession,  
  CK_CHAR_PTR       pOldPin,   
  CK_ULONG          ulOldLen,  
  CK_CHAR_PTR       pNewPin,   
  CK_ULONG          ulNewLen   
);

typedef CK_RV CK_ENTRY (*FT_C_OpenSession)(
  CK_SLOT_ID            slotID,        
  CK_FLAGS              flags,         
  CK_VOID_PTR           pApplication,  
  CK_NOTIFY             Notify,        
  CK_SESSION_HANDLE_PTR phSession      
);

typedef CK_RV CK_ENTRY (*FT_C_CloseSession)(
  CK_SESSION_HANDLE hSession  
);

typedef CK_RV CK_ENTRY (*FT_C_CloseAllSessions)(
  CK_SLOT_ID     slotID  
);

typedef CK_RV CK_ENTRY (*FT_C_GetSessionInfo)(
  CK_SESSION_HANDLE   hSession,  
  CK_SESSION_INFO_PTR pInfo      
);

typedef CK_RV CK_ENTRY (*FT_C_GetOperationState)(
  CK_SESSION_HANDLE hSession,             
  CK_BYTE_PTR       pOperationState,      
  CK_ULONG_PTR      pulOperationStateLen  
);

typedef CK_RV CK_ENTRY (*FT_C_SetOperationState)(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR      pOperationState,      
  CK_ULONG         ulOperationStateLen,  
  CK_OBJECT_HANDLE hEncryptionKey,       
  CK_OBJECT_HANDLE hAuthenticationKey    
);

typedef CK_RV CK_ENTRY (*FT_C_Login)(
  CK_SESSION_HANDLE hSession,  
  CK_USER_TYPE      userType,  
  CK_CHAR_PTR       pPin,      
  CK_ULONG          ulPinLen   
);

typedef CK_RV CK_ENTRY (*FT_C_Logout)(
  CK_SESSION_HANDLE hSession  
);

typedef CK_RV CK_ENTRY (*FT_C_CreateObject)(
  CK_SESSION_HANDLE hSession,    
  CK_ATTRIBUTE_PTR  pTemplate,   
  CK_ULONG          ulCount,     
  CK_OBJECT_HANDLE_PTR phObject  
);

typedef CK_RV CK_ENTRY (*FT_C_CopyObject)(
  CK_SESSION_HANDLE    hSession,    
  CK_OBJECT_HANDLE     hObject,     
  CK_ATTRIBUTE_PTR     pTemplate,   
  CK_ULONG             ulCount,     
  CK_OBJECT_HANDLE_PTR phNewObject  
);

typedef CK_RV CK_ENTRY (*FT_C_DestroyObject)(
  CK_SESSION_HANDLE hSession,  
  CK_OBJECT_HANDLE  hObject    
);

typedef CK_RV CK_ENTRY (*FT_C_GetObjectSize)(
  CK_SESSION_HANDLE hSession,  
  CK_OBJECT_HANDLE  hObject,   
  CK_ULONG_PTR      pulSize    
);

typedef CK_RV CK_ENTRY (*FT_C_GetAttributeValue)(
  CK_SESSION_HANDLE hSession,   
  CK_OBJECT_HANDLE  hObject,    
  CK_ATTRIBUTE_PTR  pTemplate,  
  CK_ULONG          ulCount     
);

typedef CK_RV CK_ENTRY (*FT_C_SetAttributeValue)(
  CK_SESSION_HANDLE hSession,   
  CK_OBJECT_HANDLE  hObject,    
  CK_ATTRIBUTE_PTR  pTemplate,  
  CK_ULONG          ulCount     
);

typedef CK_RV CK_ENTRY (*FT_C_FindObjectsInit)(
  CK_SESSION_HANDLE hSession,   
  CK_ATTRIBUTE_PTR  pTemplate,  
  CK_ULONG          ulCount     
);

typedef CK_RV CK_ENTRY (*FT_C_FindObjects)(
 CK_SESSION_HANDLE    hSession,          
 CK_OBJECT_HANDLE_PTR phObject,          
 CK_ULONG             ulMaxObjectCount,  
 CK_ULONG_PTR         pulObjectCount     
);

typedef CK_RV CK_ENTRY (*FT_C_FindObjectsFinal)(
  CK_SESSION_HANDLE hSession  
);

typedef CK_RV CK_ENTRY (*FT_C_EncryptInit)(
  CK_SESSION_HANDLE hSession,    
  CK_MECHANISM_PTR  pMechanism,  
  CK_OBJECT_HANDLE  hKey         
);

typedef CK_RV CK_ENTRY (*FT_C_Encrypt)(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR       pData,               
  CK_ULONG          ulDataLen,           
  CK_BYTE_PTR       pEncryptedData,      
  CK_ULONG_PTR      pulEncryptedDataLen  
);

typedef CK_RV CK_ENTRY (*FT_C_EncryptUpdate)(
  CK_SESSION_HANDLE hSession,           
  CK_BYTE_PTR       pPart,              
  CK_ULONG          ulPartLen,          
  CK_BYTE_PTR       pEncryptedPart,     
  CK_ULONG_PTR      pulEncryptedPartLen 
);

typedef CK_RV CK_ENTRY (*FT_C_EncryptFinal)(
  CK_SESSION_HANDLE hSession,                
  CK_BYTE_PTR       pLastEncryptedPart,      
  CK_ULONG_PTR      pulLastEncryptedPartLen  
);

typedef CK_RV CK_ENTRY (*FT_C_DecryptInit)(
  CK_SESSION_HANDLE hSession,    
  CK_MECHANISM_PTR  pMechanism,  
  CK_OBJECT_HANDLE  hKey         
);

typedef CK_RV CK_ENTRY (*FT_C_Decrypt)(
  CK_SESSION_HANDLE hSession,           
  CK_BYTE_PTR       pEncryptedData,     
  CK_ULONG          ulEncryptedDataLen, 
  CK_BYTE_PTR       pData,              
  CK_ULONG_PTR      pulDataLen          
);

typedef CK_RV CK_ENTRY (*FT_C_DecryptUpdate)(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR       pEncryptedPart,      
  CK_ULONG          ulEncryptedPartLen,  
  CK_BYTE_PTR       pPart,               
  CK_ULONG_PTR      pulPartLen           
);

typedef CK_RV CK_ENTRY (*FT_C_DecryptFinal)(
  CK_SESSION_HANDLE hSession,       
  CK_BYTE_PTR       pLastPart,      
  CK_ULONG_PTR      pulLastPartLen  
);

typedef CK_RV CK_ENTRY (*FT_C_DigestInit)(
  CK_SESSION_HANDLE hSession,   
  CK_MECHANISM_PTR  pMechanism  
);

typedef CK_RV CK_ENTRY (*FT_C_Digest)(
  CK_SESSION_HANDLE hSession,     
  CK_BYTE_PTR       pData,        
  CK_ULONG          ulDataLen,    
  CK_BYTE_PTR       pDigest,      
  CK_ULONG_PTR      pulDigestLen  
);

typedef CK_RV CK_ENTRY (*FT_C_DigestUpdate)(
  CK_SESSION_HANDLE hSession,  
  CK_BYTE_PTR       pPart,     
  CK_ULONG          ulPartLen  
);

typedef CK_RV CK_ENTRY (*FT_C_DigestKey)(
  CK_SESSION_HANDLE hSession,  
  CK_OBJECT_HANDLE  hKey       
);



typedef CK_RV CK_ENTRY (*FT_C_DigestFinal)(
  CK_SESSION_HANDLE hSession,     
  CK_BYTE_PTR       pDigest,      
  CK_ULONG_PTR      pulDigestLen  
);






typedef CK_RV CK_ENTRY (*FT_C_SignInit)(
  CK_SESSION_HANDLE hSession,    
  CK_MECHANISM_PTR  pMechanism,  
  CK_OBJECT_HANDLE  hKey         
);



typedef CK_RV CK_ENTRY (*FT_C_Sign)(
  CK_SESSION_HANDLE hSession,        
  CK_BYTE_PTR       pData,           
  CK_ULONG          ulDataLen,       
  CK_BYTE_PTR       pSignature,      
  CK_ULONG_PTR      pulSignatureLen  
);



typedef CK_RV CK_ENTRY (*FT_C_SignUpdate)(
  CK_SESSION_HANDLE hSession,  
  CK_BYTE_PTR       pPart,     
  CK_ULONG          ulPartLen  
);



typedef CK_RV CK_ENTRY (*FT_C_SignFinal)(
  CK_SESSION_HANDLE hSession,        
  CK_BYTE_PTR       pSignature,      
  CK_ULONG_PTR      pulSignatureLen  
);



typedef CK_RV CK_ENTRY (*FT_C_SignRecoverInit)(
  CK_SESSION_HANDLE hSession,   
  CK_MECHANISM_PTR  pMechanism, 
  CK_OBJECT_HANDLE  hKey        
);



typedef CK_RV CK_ENTRY (*FT_C_SignRecover)(
  CK_SESSION_HANDLE hSession,        
  CK_BYTE_PTR       pData,           
  CK_ULONG          ulDataLen,       
  CK_BYTE_PTR       pSignature,      
  CK_ULONG_PTR      pulSignatureLen  
);






typedef CK_RV CK_ENTRY (*FT_C_VerifyInit)(
  CK_SESSION_HANDLE hSession,    
  CK_MECHANISM_PTR  pMechanism,  
  CK_OBJECT_HANDLE  hKey          
);



typedef CK_RV CK_ENTRY (*FT_C_Verify)(
  CK_SESSION_HANDLE hSession,       
  CK_BYTE_PTR       pData,          
  CK_ULONG          ulDataLen,      
  CK_BYTE_PTR       pSignature,     
  CK_ULONG          ulSignatureLen  
);



typedef CK_RV CK_ENTRY (*FT_C_VerifyUpdate)(
  CK_SESSION_HANDLE hSession,  
  CK_BYTE_PTR       pPart,     
  CK_ULONG          ulPartLen  
);



typedef CK_RV CK_ENTRY (*FT_C_VerifyFinal)(
  CK_SESSION_HANDLE hSession,       
  CK_BYTE_PTR       pSignature,     
  CK_ULONG          ulSignatureLen  
);



typedef CK_RV CK_ENTRY (*FT_C_VerifyRecoverInit)(
  CK_SESSION_HANDLE hSession,    
  CK_MECHANISM_PTR  pMechanism,  
  CK_OBJECT_HANDLE  hKey         
);



typedef CK_RV CK_ENTRY (*FT_C_VerifyRecover)(
  CK_SESSION_HANDLE hSession,        
  CK_BYTE_PTR       pSignature,      
  CK_ULONG          ulSignatureLen,  
  CK_BYTE_PTR       pData,           
  CK_ULONG_PTR      pulDataLen       
);






typedef CK_RV CK_ENTRY (*FT_C_DigestEncryptUpdate)(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR       pPart,               
  CK_ULONG          ulPartLen,           
  CK_BYTE_PTR       pEncryptedPart,      
  CK_ULONG_PTR      pulEncryptedPartLen  
);



typedef CK_RV CK_ENTRY (*FT_C_DecryptDigestUpdate)(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR       pEncryptedPart,      
  CK_ULONG          ulEncryptedPartLen,  
  CK_BYTE_PTR       pPart,               
  CK_ULONG_PTR      pulPartLen           
);



typedef CK_RV CK_ENTRY (*FT_C_SignEncryptUpdate)(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR       pPart,               
  CK_ULONG          ulPartLen,           
  CK_BYTE_PTR       pEncryptedPart,      
  CK_ULONG_PTR      pulEncryptedPartLen  
);



typedef CK_RV CK_ENTRY (*FT_C_DecryptVerifyUpdate)(
  CK_SESSION_HANDLE hSession,            
  CK_BYTE_PTR       pEncryptedPart,      
  CK_ULONG          ulEncryptedPartLen,  
  CK_BYTE_PTR       pPart,               
  CK_ULONG_PTR      pulPartLen           
);






typedef CK_RV CK_ENTRY (*FT_C_GenerateKey)(
  CK_SESSION_HANDLE    hSession,    
  CK_MECHANISM_PTR     pMechanism,  
  CK_ATTRIBUTE_PTR     pTemplate,   
  CK_ULONG             ulCount,     
  CK_OBJECT_HANDLE_PTR phKey        
);



typedef CK_RV CK_ENTRY (*FT_C_GenerateKeyPair)(
  CK_SESSION_HANDLE    hSession,                    
                                                    
  CK_MECHANISM_PTR     pMechanism,                  
                                                    
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          
                                                    
                                                    
  CK_ULONG             ulPublicKeyAttributeCount,   
                                                    
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         
                                                    
                                                    
  CK_ULONG             ulPrivateKeyAttributeCount,  
                                                    
  CK_OBJECT_HANDLE_PTR phPublicKey,                 
                                                    
                                                    
  CK_OBJECT_HANDLE_PTR phPrivateKey                 
                                                    
                                                    
);



typedef CK_RV CK_ENTRY (*FT_C_WrapKey)(
  CK_SESSION_HANDLE hSession,        
  CK_MECHANISM_PTR  pMechanism,      
  CK_OBJECT_HANDLE  hWrappingKey,    
  CK_OBJECT_HANDLE  hKey,            
  CK_BYTE_PTR       pWrappedKey,     
  CK_ULONG_PTR      pulWrappedKeyLen 
);



typedef CK_RV CK_ENTRY (*FT_C_UnwrapKey)(
  CK_SESSION_HANDLE    hSession,          
  CK_MECHANISM_PTR     pMechanism,        
  CK_OBJECT_HANDLE     hUnwrappingKey,    
  CK_BYTE_PTR          pWrappedKey,       
  CK_ULONG             ulWrappedKeyLen,   
  CK_ATTRIBUTE_PTR     pTemplate,         
  CK_ULONG             ulAttributeCount,  
  CK_OBJECT_HANDLE_PTR phKey              
);



typedef CK_RV CK_ENTRY (*FT_C_DeriveKey)(
  CK_SESSION_HANDLE    hSession,          
  CK_MECHANISM_PTR     pMechanism,        
  CK_OBJECT_HANDLE     hBaseKey,          
  CK_ATTRIBUTE_PTR     pTemplate,         
  CK_ULONG             ulAttributeCount,  
  CK_OBJECT_HANDLE_PTR phKey              
);






typedef CK_RV CK_ENTRY (*FT_C_SeedRandom)(
  CK_SESSION_HANDLE hSession,  
  CK_BYTE_PTR       pSeed,     
  CK_ULONG          ulSeedLen  
);




typedef CK_RV CK_ENTRY (*FT_C_GenerateRandom)(
  CK_SESSION_HANDLE hSession,    
  CK_BYTE_PTR       RandomData,  
  CK_ULONG          ulRandomLen  
);






typedef CK_RV CK_ENTRY (*FT_C_GetFunctionStatus)(
  CK_SESSION_HANDLE hSession  
);



typedef CK_RV CK_ENTRY (*FT_C_CancelFunction)(
  CK_SESSION_HANDLE hSession  
);




typedef CK_RV CK_ENTRY (*FT_C_WaitForSlotEvent)(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  
  CK_VOID_PTR pRserved   
);

