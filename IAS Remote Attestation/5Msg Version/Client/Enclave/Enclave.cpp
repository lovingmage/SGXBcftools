//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.
/***************************************************************************************************
FILENAME:     Enclave.cpp
Description:  An application developer needs to use this file to put the trusted implementations.
Holds all the enclave related implementations to initialize an enclave,
get the attestation status, and to seal and unseal the secrets.
*******************************************************************************************************/
#include "Enclave_t.h"
#include "sgx_tkey_exchange.h" // supports sgx_ra_init(), sgx_ra_close(),sgx_ra_get_keys APIs
#include "string.h" //supports memcpy,memset_s functions

typedef uint8_t BYTE;
#define SECRET_SIZE 32
#define SEALED_DATA_SIZE 632

#define TIMESOURCE_CHANGED          0xF004
#define LEASE_EXPIRED               0xF006
#define TIMESOURCE_UNTRUSTED		0xF007
#define TEMPORARY_TRUST				0xF008

//structure for the secret that will be sealed and unsealed in the enclave
typedef struct _time_based_pay_load{
	sgx_time_source_nonce_t nonce;
	sgx_time_t secret_expire_time;
	uint8_t secret[SECRET_SIZE];
} time_based_pay_load;

time_based_pay_load g;
bool pseTrusted = true;
int pseLeaseCount = 0;
int b_pse = 0;

/*ECDSA public key generated. Note the 8 magic bytes are removed and
x and y component are changed to little endian . The public key is hard coded in the enclave */
static const sgx_ec256_public_t g_sp_pub_key = { {
		0xC0, 0x8C, 0x9F, 0x45, 0x59, 0x1A, 0x9F, 0xAE,
		0xC5, 0x1F, 0xBC, 0x3E, 0xFB, 0x4F, 0x67, 0xB1,
		0x93, 0x61, 0x45, 0x9E, 0x30, 0x27, 0x10, 0xC4,
		0x92, 0x0F, 0xBB, 0xB2, 0x69, 0xB0, 0x16, 0x039
	}, {
		0x5D, 0x98, 0x6B, 0x24, 0x2B, 0x52, 0x46, 0x72,
		0x2A, 0x35, 0xCA, 0xE0, 0xA9, 0x1A, 0x6A, 0xDC,
		0xB8, 0xEB, 0x32, 0xC8, 0x1C, 0x2B, 0x5A, 0xF1,
		0x23, 0x1F, 0x6C, 0x6E, 0x30, 0x00, 0x96, 0x4F }
};

/*
This ecall is a wrapper of sgx_ra_init to create the trusted
KE exchange key context needed for the remote attestation
SIGMA API's. Input pointers aren't checked since the trusted stubs
copy them into EPC memory.
@param b_pse Indicates whether the ISV app is using the
platform services.
@param p_context Pointer to the location where the returned
key context is to be copied.
@return Any error return from the create PSE session if b_pse
is true.
@return Any error returned from the trusted key exchange API
for creating a key context.
*/
sgx_status_t enclave_init_ra(
	int bpse,
	sgx_ra_context_t *p_context){
	// isv enclave call to trusted key exchange library.
	sgx_status_t ret;

	/* clear the enclave time_based_pay_load content */
	memset_s(&g, sizeof(g), 0,
		sizeof(time_based_pay_load));
	b_pse = bpse;

	if (b_pse){
		if (!pseTrusted)
			return (sgx_status_t)TIMESOURCE_UNTRUSTED;

		int busy_retry_times = 2;
		do{
			ret = sgx_create_pse_session();
		} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
		if (ret != SGX_SUCCESS)
			return ret;
	}

	/*sgx initialization function where the ECDSA generated
	public key is passed as one of the parameters
	returns the context to the application
	*/
	ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
	if (b_pse){
		sgx_close_pse_session();
		return ret;
	}
	return ret;
}

/*
After M4 is received on the client side, the received cmac is validated to
eliminate the chances of spoofing
mk_key is generated using sgx_ra_get_keys, if computed cmac matches with the cmacStatus
the function returns 0 else 1 (which means spoofed M4)
@param input context returned by sgx_ra_init()
@param input cmacStatus arrray that the app receives from the server through M4
@returns 0 or 1
*/
sgx_status_t getAttestationStatus(sgx_ra_context_t context, uint8_t* attestationStatus, uint8_t*cmacStatus){
	sgx_status_t ret = SGX_SUCCESS;
	sgx_ec_key_128bit_t mk_key = { 0 };
	uint8_t computedCmac[16] = { 0 };
	ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
	if (SGX_SUCCESS != ret)
		return ret;
	ret = sgx_rijndael128_cmac_msg(&mk_key, attestationStatus, 4, &computedCmac);

	if (SGX_SUCCESS != ret)
		return ret;
	// compare the CMACSMK
	for (int i = 0; i < 16; i++){
		if (cmacStatus[i] == computedCmac[i])
			;
		else{
			ret = SGX_ERROR_MAC_MISMATCH;
		}
	}
	if (ret == SGX_SUCCESS){
		uint8_t enclaveStatus = attestationStatus[0] & 3;
		bool enclaveTrusted = (enclaveStatus == 0 || enclaveStatus == 1);
		uint32_t leaseDuration = (*(uint32_t*)&attestationStatus[0]) >> 8;
		pseTrusted = (enclaveStatus == 0 && leaseDuration > 0);
		if (!pseTrusted){
			// Allow two uses of secret data before reattestation is required but do not seal the secret
			pseLeaseCount = 2;
		}
		if (!enclaveTrusted)
			ret = SGX_ERROR_INVALID_ENCLAVE;
		else
			ret = SGX_SUCCESS;
	}
	return ret;
}

/**
* Process attestation response from RA Server.
* Input pointers aren't checked since the trusted stubs copy
* them into EPC memory. This call completes the remote attestation session,
* thus it always ends with sgx_ra_close
*
* @param context The trusted KE library key context.
* @param attestationStatus The 16-byte status obtained from RA server.
* @param cmacStatus We check this value to ensure attestationStatus is valid.
* @param p_secret Message containing the secret.
* @param p_gcm_mac The pointer the the AESGCM MAC for the message.
* @param p_IV Initialization vector to be used to decrypt ISV key
*                 NOTE: this must be 12 bytes.
* @param @aad The pointer to an optional additional authentication
data buffer which is used in the GCM MAC calculation.
The data in this buffer will not be encrypted.
The field is optional and could be NULL.
* @return SGX_ERROR_INVALID_PARAMETER - secret size if incorrect.
* @return Any error produced by sgx_ra_get_keys.
* @return Any error produced by the AESGCM function.
* @return SGX_ERROR_UNEXPECTED - the secret doesn't match the expected value.
*/
sgx_status_t process_RA_status(sgx_ra_context_t context, uint8_t* attestationStatus, uint8_t* cmacStatus, uint8_t *p_payload,
	int payloadLen, int cryptLen, uint8_t *p_IV, uint8_t *sealedSecret){
	sgx_status_t ret = SGX_SUCCESS;
	sgx_ec_key_128bit_t sk_key;
	int busy_retry_times = 2;
	sgx_aes_gcm_128bit_tag_t tag;
	uint8_t iv[12];

	memcpy(tag, p_IV + 12, 16);
	memcpy(iv, p_IV, 12);
	do{
		ret = getAttestationStatus(context, attestationStatus, cmacStatus);
		if (ret != SGX_SUCCESS)
			break;

		ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
		if (SGX_SUCCESS != ret)
			break;

		uint8_t* pAAD = NULL;
		uint32_t aad_len = 0;
		if (payloadLen > cryptLen){
			aad_len = payloadLen - cryptLen;
			pAAD = p_payload + cryptLen;
		}

		//performs a Rijndael AES-GCM decryption operation

		ret = sgx_rijndael128GCM_decrypt(&sk_key, p_payload, cryptLen, (uint8_t *)&g.secret, iv,
			sizeof(iv), pAAD, aad_len, &tag);

		if (SGX_SUCCESS != ret)
			break;

		// Set expire time and seal the secret if we have Trusted Time
		if (!pseTrusted){
			ret = (sgx_status_t)TEMPORARY_TRUST;
		}
		else{
			do{
				ret = sgx_create_pse_session();
			} while (ret == SGX_ERROR_BUSY && busy_retry_times--);

			if (ret != SGX_SUCCESS)
				break;

			sgx_time_t current_timestamp;
			ret = sgx_get_trusted_time(&current_timestamp,
				&g.nonce);
			if (ret != SGX_SUCCESS){
				switch (ret){
				case SGX_ERROR_SERVICE_UNAVAILABLE:
					/* Architecture Enclave Service Manager is not installed or not
					working properly.*/
					break;
				case SGX_ERROR_SERVICE_TIMEOUT:
					/* retry the operation*/
					break;
				case SGX_ERROR_BUSY:
					/* retry the operation later*/
					break;
				default:
					/*other errors*/
					break;
				}
				break;
			}
			sgx_close_pse_session();
			uint32_t leaseDuration = (*(uint32_t*)&attestationStatus[0]) >> 8;
			g.secret_expire_time = current_timestamp + leaseDuration;
			uint32_t sealedDataSize = sgx_calc_sealed_data_size(0, sizeof(g));
			if (sealedDataSize != SEALED_DATA_SIZE){
				ret = SGX_ERROR_UNEXPECTED;
				break;
			}
			// Once the client has the shared secret and time reference, these should be sealed to
			// persistent storage for future use. This will prevent having to
			// perform remote attestation until the secret goes stale. Once the
			// enclave is created again, the secret and time reference can be unsealed.

			ret = sgx_seal_data(0, NULL,
				sizeof(time_based_pay_load), (uint8_t*)&g,
				sealedDataSize, (sgx_sealed_data_t*)sealedSecret);
		}
	} while (0);
	sgx_ra_close(context);
	return ret;
}

sgx_status_t IsSecretValid(){
	int busy_retry_times = 2;
	sgx_status_t ret;
	sgx_time_source_nonce_t nonce = { 0 };
	sgx_time_t current_timestamp;

	// If we don't currently have any secret we are in the same state as if lease is expired
	if (g.secret == 0){
		return (sgx_status_t)LEASE_EXPIRED;
	}
	if (!pseTrusted){
		if (pseLeaseCount == 0)	{
			// Clear the time_based_pay_load since no longer valid
			memset_s(&g, sizeof(g), 0,
				sizeof(time_based_pay_load));
			return (sgx_status_t)TIMESOURCE_UNTRUSTED;
		}
		pseLeaseCount--;
		return SGX_SUCCESS;
	}

	do{
		ret = sgx_create_pse_session();
	} while (ret == SGX_ERROR_BUSY && busy_retry_times--);

	do {
		if (ret != SGX_SUCCESS)
			break;

		ret = sgx_get_trusted_time(&current_timestamp,
			&nonce);
		if (ret != SGX_SUCCESS){
			switch (ret){
			case SGX_ERROR_SERVICE_UNAVAILABLE:
				/* Architecture Enclave Service Manager is not installed or not
				working properly.*/
				break;
			case SGX_ERROR_SERVICE_TIMEOUT:
				/* retry the operation*/
				break;
			case SGX_ERROR_BUSY:
				/* retry the operation later*/
				break;
			default:
				/*other errors*/
				break;
			}
			break;
		}

		/*source nonce must be the same, otherwise time source is changed and
		the two timestamps are not comparable.*/
		if (memcmp(&nonce, &g.nonce,
			sizeof(sgx_time_source_nonce_t))){
			ret = (sgx_status_t)TIMESOURCE_CHANGED;
			break;
		}

		/*compare lease_duration and timestamp_diff
		if lease_duration is less than difference of current time and base time,
		lease tern has expired.*/
		if (current_timestamp > g.secret_expire_time){
			ret = (sgx_status_t)LEASE_EXPIRED;
			break;
		}
	} while (0);
	sgx_close_pse_session();
	return ret;
}

sgx_status_t encryptWithSecretKey(uint32_t length, uint8_t *clear, uint8_t *crypt, uint8_t* crypt_mac, uint8_t* iv){
	sgx_status_t ret = IsSecretValid();
	if (SGX_SUCCESS == ret){
		/* secret is still valid -- use it now*/
		ret = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t *)g.secret, clear, length, crypt,
			iv, 12, NULL, 0, (sgx_aes_gcm_128bit_tag_t *)crypt_mac);
	}
	else{
		// The secret is not available to use.
	}
	return ret;
}



/*
A wrapper function to Unseal the secret , reads the secret from the file, unseals it
and prints to the console through ocall function only when debug mode is enabled
*/
sgx_status_t unsealSecret(uint8_t* sealedSecret){
	//optional additional mac text is taken as NUll and length is taken as 0
	uint32_t unsealedSecretLen = sizeof(g);
	int busy_retry_times = 2;
	time_based_pay_load unsealed_data;
	sgx_status_t ret;
	if (!pseTrusted)
		return (sgx_status_t)TIMESOURCE_UNTRUSTED;

	do{
		ret = sgx_create_pse_session();
	} while (ret == SGX_ERROR_BUSY && busy_retry_times--);

	do{
		sgx_time_source_nonce_t nonce = { 0 };
		sgx_time_t current_timestamp;
		ret = sgx_get_trusted_time(&current_timestamp, &nonce);
		if (ret != SGX_SUCCESS){
			switch (ret){
			case SGX_ERROR_SERVICE_UNAVAILABLE:
				/* Architecture Enclave Service Manager is not installed or not
				working properly.*/
				break;
			case SGX_ERROR_SERVICE_TIMEOUT:
				/* retry the operation*/
				break;
			case SGX_ERROR_BUSY:
				/* retry the operation later*/
				break;
			default:
				/*other errors*/
				break;
			}
			break;
		}
		if (ret != SGX_SUCCESS){
			memset_s(&unsealed_data, sizeof(unsealed_data), 0,
				sizeof(time_based_pay_load));
			return ret;
		}

		// if time_based_pay_load memory is currently valid, reject the request to unseal secret (it is either old, mistake, or a spoof attack)
		if (g.secret_expire_time != 0)	{
			// time_based_pay_load has been written to and not reset to zero.... check if still valid
			/*source nonce must be the same, otherwise time source is changed and
			the two timestamps are not comparable.*/
			if (memcmp(&nonce, &g.nonce,
				sizeof(sgx_time_source_nonce_t))){
				//ret = (sgx_status_t)TIMESOURCE_CHANGED;
				return SGX_ERROR_UNEXPECTED;
			}

			/*compare lease_duration and timestamp_diff
			if lease_duration is less than difference of current time and base time,
			lease tern has expired.*/
			if (current_timestamp <= g.secret_expire_time){
				// The current secret and timestamp are still valid -- don't unseal!
				return SGX_ERROR_UNEXPECTED;
			}
		}
		uint8_t enclaveSealedSecret[SEALED_DATA_SIZE];
		memcpy(enclaveSealedSecret, sealedSecret, SEALED_DATA_SIZE);
		ret = sgx_unseal_data((sgx_sealed_data_t*)enclaveSealedSecret, NULL, 0, (uint8_t*)&unsealed_data, &unsealedSecretLen);

		if (ret != SGX_SUCCESS){
			switch (ret){
			case SGX_ERROR_INVALID_PARAMETER:
				/* Bad parameter */
				break;
			case SGX_ERROR_MAC_MISMATCH:
				/* MAC of the sealed data is incorrect. the sealed data has been
				tampered.*/
				break;
			case SGX_ERROR_INVALID_ATTRIBUTE:
				/*Indicates attribute field of the sealed data is incorrect.*/
				break;
			case SGX_ERROR_INVALID_ISVSVN:
				/* Indicates isv_svn field of the sealed data is greater than the
				enclave’s ISVSVN. This is a downgraded enclave.*/
				break;
			case SGX_ERROR_INVALID_CPUSVN:
				/* Indicates cpu_svn field of the sealed data is greater than the
				platform’s cpu_svn. enclave is  on a downgraded platform.*/
				break;
			case SGX_ERROR_INVALID_KEYNAME:
				/*Indicates key_name field of the sealed data is incorrect.*/
				break;
			default:
				/*other errors*/
				break;
			}
			return ret;
		}

		/*source nonce must be the same, otherwise time source is changed and
		the two timestamps are not comparable.*/
		if (memcmp(&nonce, &unsealed_data.nonce,
			sizeof(sgx_time_source_nonce_t))){
			ret = (sgx_status_t)TIMESOURCE_CHANGED;
			break;
		}

		/*compare lease_duration and timestamp_diff
		if lease_duration is less than difference of current time and base time,
		lease tern has expired.*/
		if (current_timestamp <= g.secret_expire_time){
			ret = (sgx_status_t)LEASE_EXPIRED;
			break;
		}
	} while (0);
	if (SGX_SUCCESS == ret){
		/* store the unsealed data in enclave memory */
		g.secret_expire_time = unsealed_data.secret_expire_time;
		memcpy(g.secret, unsealed_data.secret, sizeof(g.secret));
		memcpy(g.nonce, unsealed_data.nonce, sizeof(sgx_time_source_nonce_t));
	}
	else{
		// Clear the time_based_pay_load since no longer valid
		memset_s(&g, sizeof(g), 0,
			sizeof(time_based_pay_load));
	}

	/* clear the plaintext secret after used */
	memset_s(&unsealed_data, sizeof(unsealed_data), 0,
		sizeof(time_based_pay_load));
	sgx_close_pse_session();
	return ret;
}

//Decrypts the secret using the secret key using rijndael function
sgx_status_t decryptWithSecretKey(uint32_t length, uint8_t *clear, uint8_t *crypt, uint8_t* crypt_mac, uint8_t* iv){
	sgx_status_t ret = IsSecretValid();
	if (SGX_SUCCESS == ret){
		/* secret is still valid -- use it now*/
		ret = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t *)g.secret, crypt, length, clear,
			iv, 12, NULL, 0, (sgx_aes_gcm_128bit_tag_t *)crypt_mac);
	}
	else{
		// The secret is not available to use.
	}
	return ret;
}