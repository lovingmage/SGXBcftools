//  Copyright (C) Intel Corporation, 2015 All Rights Reserved.
/**************************************************************************************************
FILENAME:       EnclaveManagement.h
DESCRIPTION:    Header file for EnclaveManagement.cpp
				It Handles interaction with the enclave, including creation/deletion and working with secrets
******************************************************************************************************/
#include "sgx_urts.h"         //To create Enclave and perform ecalls
#include "sgx_uae_service.h"  //To access the services provided by the architectural enclaves sgx_report_attestation_status()
#include "RemoteAttestation.h" // To access Converter, output file to write the secret and other references
#include "Enclave_u.h"		  //include enclave untrusted header file

#pragma once

#define TIMESOURCE_CHANGED          0xF004
#define LEASE_EXPIRED               0xF006
#define TEMPORARY_TRUST				0xF008
#define sealedDataSize 632

using namespace std;
extern uint8_t sealedSecret[sealedDataSize];
extern sgx_enclave_id_t eid;
extern sgx_ra_context_t context;
extern Converter converter;

/* A wrapper function to encyrpt and decrypt the provided data buffer
depending on the validity of the secret at that point of time
@param - input : data buffer, buf of string type
@param - output : returns true if there exists a valid secret and attestation is not necessary
				 if there is no valid secret available, does the remote attestation process; 
				 and then if the secret is valid, returns true else returns false
*/
bool EncryptDecrypt(std::string buf);

/*A function that writes the sealed data to a file for later use
@param - output: sealedData byte array is written to a file named "SealedSecret.bin"
*/
void WriteToFile();

/*A function that reads the sealed data from a file named "SealedSecret.bin"
@param - output: if the file exists, the size of the file is compared with the SealedDataSize; 
                 if it matches, the secret is read as blocks and returns true
				 otherwise returns false
*/
bool ReadFromFile();

/* An API that deletes the sealed secret file
*/
void RemoveFile();

/*
An API that destroys the enclave if the enclave_id is 0.
It is a better practice to destroy an enclave when not in use
*/
void DestroyEnclave();

/*
An API that creates an enclave
If the enclave_id is not 0, it means an enclave already exists and so the API does
nothing, just returns; otherwise checks the device status using sgx_device_status.
If sgx is enabled, creates the enclave using sgx_create_enclave() API. 

*/
void CreateEnclave();

/*An API that encrypts and decrypts the given data buffer
* @param -input: buffer of string type. This buffer will be encrypted with the secret key and
decrypted using the secret key by this API
* output: Prints the decrypted message to the buffer and returns the status as SUCCESS if
the encryption and decryption operations go well if not the function aborts with
the related error message
*/
sgx_status_t EncryptAndDecryptEnclaveCalls(string);

//A wrapper function that destroys and creates enclave
void DestroyAndCreateEnclave();