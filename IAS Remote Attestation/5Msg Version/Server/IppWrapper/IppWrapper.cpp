// INTEL CONFIDENTIAL
// Copyright 2015 2016 Intel Corporation All Rights Reserved.
//
// The source code contained or described herein and all documents related to the source code 
// ("Material") are owned by Intel Corporation or its suppliers or licensors. Title to the
// Material remains with Intel Corporation or its suppliers and licensors. The Material contains 
// trade secrets and proprietary and confidential information of Intel or its suppliers and 
// licensors. The Material is protected by worldwide copyright and trade secret laws and treaty 
// provisions. No part of the Material may be used, copied, reproduced, modified, published, 
// uploaded, posted, transmitted, distributed, or disclosed in any way without Intel’s prior 
// express written permission.
//
// No license under any patent, copyright, trade secret or other intellectual property right is 
// granted to or conferred upon you by disclosure or delivery of the Materials, either expressly, 
// by implication, inducement, estoppel or otherwise. Any license under such intellectual property 
// rights must be express and approved by Intel in writing.
// IppWrapper.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "IppWrapper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "ipp.h"
#include "ippcore.h"
#include "ippcp.h"
#include "ippcpdefs.h"
#include <errno.h>

#include "sample_libcrypto.h"

#define SAMPLE_AESGCM_MAC_SIZE          16
#define SAMPLE_AESGCM_KEY_SIZE          16
#define SAMPLE_AESGCM_IV_SIZE			12
#define DH_HALF_KEY_LEN					32
#define DH_SHARED_KEY_LEN				32
#define AAD_BUFFER_SIZE 				32

#define CHECK_IPP_STATUS(st) \
    if( st != ippStsNoErr ) printf( "Warning: IPP function returns status = %d\n", (int)st );

sample_ecc_state_handle_t ecc_state = NULL;
sample_ec256_public_t pub_key = {{0},{0}};
sample_ec256_public_t client_pub_key = {{0},{0}};
sample_ec256_private_t priv_key = {{0}};
sample_ec256_dh_shared_t dh_key = {{0}};

IPPWRAPPER_CALL bool ippWrapperInitDiffieHellman()
{
//	printf("Entering ippWrapperInitDiffieHellman\n");
	sample_status_t result = sample_ecc256_open_context(&ecc_state);
//	printf("sample_ecc256_open_context: %d\n", result);
	return true;


}

IPPWRAPPER_CALL bool ippWrapperGetDHPublicKey(char * gbXptr, char * gbYptr, int * gblen)
{
	sample_status_t result = sample_ecc256_create_key_pair(&priv_key, &pub_key, ecc_state);
//	printf("sample_ecc256_create_key_pair: %d\n", result);
	int x = 0;
	while (x < DH_HALF_KEY_LEN) {
            gbXptr[x] = pub_key.gx[x];
            gbYptr[x] = pub_key.gy[x];
			x++;
    }
	*gblen = DH_HALF_KEY_LEN;
	return true;

}

IPPWRAPPER_CALL bool ippWrapperGetDHSharedSecret(const char * gaXLE, const char * gaYLE, char * sharedPtr, int * sharedLen)
{
	int x = 0;
	while (x < DH_SHARED_KEY_LEN) {
            client_pub_key.gx[x] = gaXLE[x];
            client_pub_key.gy[x] = gaYLE[x];
			x++;
    }
	sample_status_t result = sample_ecc256_compute_shared_dhkey(&priv_key, &client_pub_key, &dh_key, ecc_state);
//	printf("sample_ecc256_compute_shared_dhkey: %d\n", result);
    x = 0;
	while (x < DH_SHARED_KEY_LEN) {
            sharedPtr[x] = dh_key.s[x];
			x++;
    }
	*sharedLen = DH_SHARED_KEY_LEN;
	return true;

}


IPPWRAPPER_CALL bool ippWrapperEncryptData( uint8_t *pSrcMsg,
                                            uint8_t *pKey,
                                            int IVLen,
                                            uint8_t *pIV,
                                            int AADLen,
                                            uint8_t *pAddAD,
                                            int MsgLen,
                                            char *pEncryptedMessageOut,
                                            char* pTag)
{
//	printf("Entered ippWrapperEncryptData\n");
	
    IppStatus status = ippStsNoErr;
    IppsAES_GCMState* pState = NULL;
    int ippStateSize = 0;

	status = ippsAES_GCMGetSize(&ippStateSize);
	if (status != ippStsNoErr)
	{
		printf("Error when calling GCMGetSize: %d", (int)status);
		return false;
	}

	pState = (IppsAES_GCMState*)malloc(ippStateSize);
	status = ippsAES_GCMInit((const Ipp8u*)pKey, SAMPLE_AESGCM_KEY_SIZE, pState, ippStateSize);	//Initialize context with the key
	if (status != ippStsNoErr)
	{
		printf("Error when calling GCMInit: %d", (int)status);
		return false;
	}

	status = ippsAES_GCMReset(pState);
	status = ippsAES_GCMProcessIV(pIV, IVLen, pState);
	int i = 0;
	for (i = 0; i <= AADLen-AAD_BUFFER_SIZE; i += AAD_BUFFER_SIZE)
		status = ippsAES_GCMProcessAAD(pAddAD + i, AAD_BUFFER_SIZE, pState);
	status = ippsAES_GCMProcessAAD(pAddAD+i, AADLen-i, pState);
	if (status != ippStsNoErr)
	{
		printf("Error when calling GCMProcessAAD: %d", (int)status);
		return false;
	}

	status = ippsAES_GCMEncrypt(pSrcMsg, (Ipp8u *)pEncryptedMessageOut, MsgLen, pState);
	if (status != ippStsNoErr)
	{
		printf("Error when calling GCMEncrypt: %d", (int)status);
		return false;
	}

	status = ippsAES_GCMGetTag((Ipp8u *)pTag, SAMPLE_AESGCM_MAC_SIZE, pState);
	if (status != ippStsNoErr)
	{
		printf("Error when calling GCMGetTag: %d", (int)status);
		return false;
	}

	std::memset(pState, 0, ippStateSize);
	free(pState);
	
	if (status == ippStsNoErr)
		return true;

	return false;
}

IPPWRAPPER_CALL bool ippWrapperDecryptData( uint8_t *pEncryptedMsg,
                                            uint8_t *pKey,
                                            int IVLen,
                                            uint8_t *pIV,
                                            int AADLen,
                                            uint8_t *pAddAD,
                                            int MsgLen,
                                            char *pDecryptedMessage,
                                            char* pTag )
{
	IppStatus status = ippStsNoErr;
    uint8_t l_tag[SAMPLE_AESGCM_MAC_SIZE];
    IppsAES_GCMState* pState = NULL;
    int ippStateSize = 0;

    status = ippsAES_GCMGetSize(&ippStateSize);
	if (status != ippStsNoErr)
	{
		printf("Error when calling GCMGetSize: %d", (int)status);
		return false;
	}

	pState = (IppsAES_GCMState*)malloc(ippStateSize);
	if (pState == NULL)
	{
		printf("Error allocating State Context");
		return false;
	}
	
	status = ippsAES_GCMInit((const Ipp8u *)pKey, SAMPLE_AESGCM_KEY_SIZE, pState, ippStateSize);
	if (status != ippStsNoErr)
	{
		printf("Error when calling GCMInit: %d", (int)status);
		return false;
	}

    // Since we only have 1 pointer to IV and 1 pointer to AAD,
    // we can use this API instead
    status = ippsAES_GCMStart(pIV, IVLen, pAddAD, AADLen, pState);
    if (status != ippStsNoErr)
    {
        printf("Error when calling GCMStart: %d", (int)status);
        return false;
    }


    status = ippsAES_GCMDecrypt(pEncryptedMsg, (Ipp8u *)pDecryptedMessage, MsgLen, pState);
	if (status != ippStsNoErr)
	{
		printf("Error when calling GCMDecrypt: %d", (int)status);
		return false;
	}

	memset(&l_tag, 0, SAMPLE_AESGCM_MAC_SIZE);
    status = ippsAES_GCMGetTag((Ipp8u *)l_tag, SAMPLE_AESGCM_MAC_SIZE, pState);
	if (status != ippStsNoErr)
	{
		printf("Error when calling GCMGetTag: %d", (int)status);
		return false;
	}

    if (memcmp(pTag, &l_tag, SAMPLE_AESGCM_MAC_SIZE) != 0)
    {
        memset(pDecryptedMessage, 0, MsgLen);
        memset(&l_tag, 0, SAMPLE_AESGCM_MAC_SIZE);
        return false; // MAC mismatch
    }

	if (status == ippStsNoErr)
		return true;

	return false;
}
