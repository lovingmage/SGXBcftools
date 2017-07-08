#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "stdio.h"
#include "sgx_lib_stdio.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void add_secret(int secret);
void print_secrets();
void test_encryption();
void set_key(uint8_t* key);

sgx_status_t SGX_CDECL print_ocall(char* message);
sgx_status_t SGX_CDECL rewind_ocall(FILE* file);
sgx_status_t SGX_CDECL fseek_ocall(int* retval, FILE* file, long int offset, int origin);
sgx_status_t SGX_CDECL ftell_ocall(long int* retval, FILE* file);
sgx_status_t SGX_CDECL fwrite_enclave_memory_ocall(size_t* retval, const void* buffer, size_t size, size_t count, FILE* stream);
sgx_status_t SGX_CDECL fread_copy_into_enclave_memory_ocall(size_t* retval, void* buffer, size_t size, size_t count, FILE* stream);
sgx_status_t SGX_CDECL fclose_ocall(int* retval, FILE* stream);
sgx_status_t SGX_CDECL fopen_ocall(FILE** retval, const char* filename, const char* mode);
sgx_status_t SGX_CDECL _ftelli64_ocall(int64_t* retval, FILE* file);
sgx_status_t SGX_CDECL fflush_ocall(int* retval, FILE* file);
sgx_status_t SGX_CDECL fopen_s_ocall(int* retval, FILE** file, const char* filename, const char* mode);
sgx_status_t SGX_CDECL _fseeki64_ocall(int* retval, FILE* file, int64_t offset, int origin);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
