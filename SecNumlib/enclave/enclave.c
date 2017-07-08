// this include is essential, otherwise the whole project won't compile (without a decent error message)
#include <stdlib.h>

#include "sgx_lib_stdio.h"
#include "sgx_lib_t_stdio.h"
#include "sgx_lib_t_debug.h"
#include "sgx_lib_t_util.h"
#include "sgx_lib_t_crypto.h"
#include "atomatrix.h"


#define FILE_NAME "test_file_in_application_dir.txt"


int add_s(void* _op1, void* _op2, void* _opout)
{
	sgx_matrix *MA = (sgx_matrix*)malloc(sizeof(sgx_matrix));
	sgx_matrix *MB = (sgx_matrix*)malloc(sizeof(sgx_matrix));

	sgx_matrix *MC = (sgx_matrix*)malloc(sizeof(sgx_matrix));


}

//------------< Test Stub Functions >-------------------------------
void set_key(uint8_t *key) {
  set_secure_io_key(key);
}

void dump_out(void* outbuffer)
{
	double num[9] = {2,3,4,5,6,7,8,9,10};
	const char sec[10] = "abcdefghi";
	sgx_matrix MA;
	memcpy(MA.data, num, sizeof(double));
	secmemcpy_out(MA.data, 10, 1, outbuffer);
}

void print_buffer(void* buffer)
{
	sgx_matrix MB;
	secmemcpy_in(MB.data, 10, 1, buffer);
	printf("Secret: %d %d %d\n", MB.data[0], MB.data[1], MB.data[2]);
}

void add_secret(int secret) {
  int sec = 25;
  FILE *file = fopen(FILE_NAME, "wb" /*delete existing file, binary*/);
  fwrite(&sec, sizeof(sec), 1, file);
  fclose(file);
}

void print_secrets() {
  int secret;
  FILE *file = fopen(FILE_NAME, "rb" /*binary*/);
  fread(&secret, sizeof(secret), 1, file);
  printf("Secret: %d\n", secret);
  fclose(file);
}

void test_encryption() {
  uint8_t plaintext[20] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19};
  uint8_t *encrypted, *decrypted;
  sgx_aes_ctr_128bit_key_t key = {0};
  int dec_bytes, i;

  encrypted = (uint8_t*) malloc(get_encrypted_data_size(sizeof(plaintext)));
  dec_bytes = 20 * BLOCK_SIZE; // better performance if block-aligned
  decrypted = (uint8_t*) malloc(dec_bytes);

  encrypt(plaintext, sizeof(plaintext), (sgx_lib_encrypted_data_t*) encrypted, &key);
  dec_bytes = decrypt(decrypted, dec_bytes, (sgx_lib_encrypted_data_t*) encrypted, &key);
  free(encrypted);
  free(decrypted);

  for (i=0; i<20; i++) {

      printf("Unexpected decrypted value: got %d, expected %d\n", decrypted[i], i);
    }
  
}