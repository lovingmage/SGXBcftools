//  Copyright (C) Intel Corporation, 2015 All Rights Reserved
/**************************************************************************************************
FILENAME:       EnclaveManagement.cpp
DESCRIPTION:    Handles interaction with the enclave, including creation/deletion and working with secrets
******************************************************************************************************/
#include "stdafx.h"
#include "ISV-APP.h" // this header also includes EnclaveManagement.h

LPCWSTR filename = L"SealedSecret.bin";
uint8_t sealedSecret[sealedDataSize];
sgx_enclave_id_t eid = 0;
sgx_ra_context_t context = -1;
bool secretValid = false; // Initially: we don't have a valid secret
Converter converter;

#define ENCLAVE_FILE _T("Enclave.signed.dll")

void DestroyAndCreateEnclave(){
	DestroyEnclave();
	CreateEnclave();
}

sgx_status_t EncryptAndDecryptEnclaveCalls(std::string buf){
	sgx_status_t ret;
	sgx_status_t sgx_ret = SGX_SUCCESS;
	uint8_t * orig = (uint8_t*)buf.c_str();
	uint8_t decrypt[100] = { 0 };
	uint8_t crypt[100] = { 0 };
	uint8_t iv[12];
	uint32_t size = (uint32_t)buf.size();
	uint8_t crypt_mac[16];
	uint8_t i;
	uint8_t j;

	cout << "Original message: " << orig << endl;
	for (j = 0; j < 12; j++){
		i = rand() % 256;
		iv[j] = i;
	}

	// Go ahead and try to encypt data in case the secret is still valid from previous sessions
	ret = encryptWithSecretKey(eid, &sgx_ret, size, orig, crypt, crypt_mac, iv);
	// Handle power event
	if (ret == SGX_ERROR_ENCLAVE_LOST){
		// No need to automatically force remote attestation
		DestroyAndCreateEnclave();
		ret = encryptWithSecretKey(eid, &sgx_ret, size, orig, crypt, crypt_mac, iv);
	}
	if (sgx_ret != SGX_SUCCESS)
		return sgx_ret;
	cout << "Encrypted message: ";
	for (j = 0; j < size; j++)
		cout << std::hex << int(crypt[j]) << " ";
	cout << std::dec << endl;

	// Decrypt received response
	ret = decryptWithSecretKey(eid, &sgx_ret, size, decrypt, crypt, crypt_mac, iv);
	// Handle power event
	if (ret == SGX_ERROR_ENCLAVE_LOST){
		// No need to automatically force remote attestation
		DestroyAndCreateEnclave();
		ret = decryptWithSecretKey(eid, &sgx_ret, size, decrypt, crypt, crypt_mac, iv);
	}
	if (ret != SGX_SUCCESS)
		return ret;
	cout << "Decrypted message: " << decrypt << endl;
	return SGX_SUCCESS;

}

bool EncryptDecrypt(std::string buf){
	sgx_status_t sgx_ret = SGX_SUCCESS;
	bool result;
	if (eid == 0){
		cout << "Enclave will be created in order to complete EncryptDecrypt operation" << endl;
		// No need to force automatic attestation
		CreateEnclave();
	}
	if (secretValid){
		sgx_ret = EncryptAndDecryptEnclaveCalls(buf);
		if (sgx_ret == SGX_SUCCESS)	{
			//Secret still valid from before - no attestation was needed
			if (!keepEnclave)
				DestroyEnclave();
			return true;
		}
		else{
			secretValid = false;
			cout << endl << "EncryptDecrypt could not complete because: ";
			if (sgx_ret == LEASE_EXPIRED)
				cout << "Lease expired or secret never established" << endl;
			else if (sgx_ret == TIMESOURCE_CHANGED)
				cout << "Timesource changed" << endl;
		}
	}
	// Secret is invalid at this point
	RemoveFile(); // delete the sealed secret file if it exists
	// Require attestation to continue
	secretValid = RemoteAttestation();

	// Try again now that we have the secret
	if (secretValid){
		sgx_ret = EncryptAndDecryptEnclaveCalls(buf);
		if (sgx_ret == SGX_SUCCESS)
			result = true;
		else{
			cout << endl << "EncryptDecrypt should have completed now that secret is valid. Error code: " << sgx_ret << endl;
			result = false;
		}
	}
	else
		result = false;
	if (!keepEnclave)
		DestroyEnclave();
	return result;
}

void WriteToFile(){
	ofstream outputFile;
	//truncating the contents of the file if exists
	outputFile.open(filename, ofstream::binary | std::ofstream::trunc);
	outputFile.close();
	outputFile.open(filename, ofstream::binary);
	string str = "";
	std::ostringstream convert;
	for (int i = 0; i < sealedDataSize; i++){
		convert << (int)sealedSecret[i];
		outputFile << sealedSecret[i];
	}
	outputFile.close();
	SetFileAttributes(filename, FILE_ATTRIBUTE_READONLY);
}

bool ReadFromFile(){
	std::ifstream is(filename, std::ifstream::binary);
	if (is) {
		// get length of file:
		is.seekg(0, is.end);
		std::streamoff length = is.tellg();
		is.seekg(0, is.beg);
		if (length != sealedDataSize){
			std::cout << "File size error";
			return false;
		}
		if (verbose)
			std::cout << "Reading " << length << " characters... ";
		// read data as a block:
		is.read((char*)sealedSecret, length);
		if (is){
			if (verbose)
				std::cout << "all characters read successfully.";
		}
		else {
			is.close();
			std::cout << "error: only " << is.gcount() << " could be read";
			return false;
		}
		is.close();
		return true;
	}
	else {
		if (verbose)
			std::cout << "Unable to open file";
	}
	return false;
}

void RemoveFile(){
	SetFileAttributes(filename, FILE_ATTRIBUTE_NORMAL);
	DeleteFile(filename);
}

void DestroyEnclave(){
	if (eid != 0){
		sgx_destroy_enclave(eid);
		eid = 0;
		cout << endl << "*** Enclave destroyed" << endl;
	}
}

/* This function is run as the very first step in the attestation process to check the device status;
query the status of the SGX device.If not enabled before, enable it. If the device is not enabled,
SGX device not found error is expected when the enclave is created
*/
int query_sgx_status(){
	sgx_device_status_t sgx_device_status;
	sgx_status_t sgx_ret = sgx_enable_device(&sgx_device_status);
	if (sgx_ret != SGX_SUCCESS) {
		cout << " Failed to get SGX device status with error number  " << sgx_ret << endl;
		return -1;
	}
	else {
		switch (sgx_device_status) {
		case SGX_ENABLED:
			cout << "***** SGX device is enabled ******" << endl;
			return 0;
		case SGX_DISABLED_REBOOT_REQUIRED:
			printf("SGX device will be enabled after this machine is rebooted.\n");
			return -1;
		case SGX_DISABLED_LEGACY_OS:
			printf("SGX device can't be enabled on an OS that doesn't support EFI interface.\n");
			return -1;
		case SGX_DISABLED:
			printf("SGX device not found.\n");
			return -1;
		default:
			printf("Unexpected error.\n");
			return -1;
		}
	}
}

void CreateEnclave(){
	if (eid != 0){
		cout << "Enclave already created - will not create again";
		return;
	}

	/* Enclave id, used in communicating with enclave */
	int ret = 0;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	sgx_status_t sgx_ret = SGX_SUCCESS;
	uint32_t enclave_ret = 0;

	if (query_sgx_status() < 0) {
		/* In this case, either SGX is disabled, or a reboot is required to enable SGX */
		AbortProcess();
	}

	/** Creates the Enclave with above launch token.
	@param Input ENCLAVE_FILE is the signed enclave file, defined above.
	@param Input SGX_DEBUG_FLAG is set to 1 if the enclave is to be launched in debug mode else it is set to 0

	*/
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("App: error %#x, failed to create enclave.\n", ret);
		AbortProcess();
	}
	cout << endl << "******Succesfully Created the Enclave******" << endl;

	secretValid = false;

	//Get the secret locally if possible
	if (!b_pse){
		cout << endl << "No trusted time -- can't trust whether secret is still valid" << endl;
	}
	else{
		if (ReadFromFile()){
			cout << endl << "Retrieved sealed secret from file" << endl;
			ret = unsealSecret(eid, &sgx_ret, sealedSecret);
			if (ret == SGX_ERROR_ENCLAVE_LOST){
				// Set to true to avoid recursion
				DestroyAndCreateEnclave();
				ret = unsealSecret(eid, &sgx_ret, sealedSecret);
			}

			if (sgx_ret == SGX_SUCCESS){
				cout << endl << "Secret unsealed successfully" << endl;
				// This is the only path (besides secret valid already) that won't require remote attestation
				secretValid = true;
			}
			else{
				cout << endl << "Secret unsealing was unsuccessful because: ";
				if (sgx_ret == LEASE_EXPIRED)
					cout << "Lease expired" << endl;
				else if (sgx_ret == TIMESOURCE_CHANGED)
					cout << "Timesource changed" << endl;
				else if (sgx_ret == SGX_ERROR_MAC_MISMATCH)
					cout << "File data has been tampered" << endl;
				else
					cout << "SGX error: " << sgx_ret << endl;
			}
		}
		else{
			cout << endl << "Sealed secret file doesn't exist or couldn't be read" << endl;
		}
	}
	if (!secretValid)
		RemoveFile(); // delete the sealed secret file if it exists
	cout << endl << "*** Enclave Initialized successfully ***" << endl;
}
