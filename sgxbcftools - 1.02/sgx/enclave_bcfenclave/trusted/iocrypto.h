/*
 * sealedio.h
 *
 *  Created on: Jun 7, 2017
 *      Author: lovingmage
 */

#ifndef ENCLAVE_BCFENCLAVE_TRUSTED_IOCRYPTO_H_
#define ENCLAVE_BCFENCLAVE_TRUSTED_IOCRYPTO_H_

#include <stdint.h>
#include <stdlib.h>

#include "err.h"
#include "sgx_error.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "bcfenclave_t.h"


#include <sgx_tseal.h>

/* AES CTR mode counter size in bytes: 128 bit */
#define CTR_SIZE 16

/* number of bytes (most significant) to use as message nonce in counter */
#define CTR_NONCE_SIZE 8

/* number of bits (least significant) to increment */
#define CTR_INC_BITS (CTR_SIZE-CTR_NONCE_SIZE)*8

/* AES block size in bytes */
#define BLOCK_SIZE 16

uint32_t get_sealed_data_size(uint32_t plaintext_data_size);
int seal(const void* plaintext_buffer, uint32_t plaintext_data_size, sgx_sealed_data_t* sealed_buffer, size_t sealed_data_size);
int unseal(void* plaintext_buffer, uint32_t plaintext_data_size, sgx_sealed_data_t* sealed_buffer);


typedef struct {
  uint8_t ctr_nonce[CTR_NONCE_SIZE];
  uint8_t data[];
} sgx_lib_encrypted_data_t;
uint32_t get_encrypted_data_size(uint32_t plaintext_data_size);
int encrypt(const void* plaintext_buffer, uint32_t plaintext_data_size, sgx_lib_encrypted_data_t* encrypted_buffer, sgx_aes_ctr_128bit_key_t* key);
int decrypt(void* plaintext_buffer, uint32_t plaintext_data_size, sgx_lib_encrypted_data_t* encrypted_buffer, sgx_aes_ctr_128bit_key_t* key);


void log_msg(char* msg) {
  print_ocall(msg);
  print_ocall("\n");
}

void check(sgx_status_t rc) {
  if (rc != SGX_SUCCESS) {
    char* desc = get_error_description(rc);
    log_msg(desc);
  }
}


#endif /* ENCLAVE_BCFENCLAVE_TRUSTED_IOCRYPTO_H_ */
