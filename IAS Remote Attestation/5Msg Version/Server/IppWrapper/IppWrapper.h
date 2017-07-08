//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

#ifndef _IPP_WRAPPER_API_H_
#define _IPP_WRAPPER_API_H_

#include <Windows.h>
#include <string>
#include <cstdlib>
#include <cstdint>

#ifdef IPPWRAPPER_DLL_BUILD
#ifdef IPPWRAPPER_EXPORTS
#define IPPWRAPPER_CALL  __declspec(dllexport)
#else
#define IPPWRAPPER_CALL  __declspec(dllimport)
#endif
#else
#define IPPWRAPPER_CALL
#endif


#ifdef __cplusplus
extern "C" {
#endif

//API Calls

/**
*
*
*
*/
IPPWRAPPER_CALL bool ippWrapperInitDiffieHellman();
IPPWRAPPER_CALL bool ippWrapperGetDHPublicKey(char * gbXptr, char * gbYptr, int * gblen);
IPPWRAPPER_CALL bool ippWrapperGetDHSharedSecret(const char * gaXLEstr, const char * gaYLEstr, char * sharedPtr, int * sharedLen);
IPPWRAPPER_CALL bool ippWrapperEncryptData(uint8_t *pSrcMsg, uint8_t *pKey, int IVLen, uint8_t *pIV, int AADLen, uint8_t *pAAD, int MsgLen, char *pEncryptedMessageOut, char* pTag);
IPPWRAPPER_CALL bool ippWrapperDecryptData(uint8_t *pEncryptedMsg, uint8_t *pKey, int IVLen, uint8_t *pIV, int AADLen, uint8_t *pAAD, int MsgLen, char *pDecryptedMessage, char* pTag);

#ifdef __cplusplus
}
#endif



#endif