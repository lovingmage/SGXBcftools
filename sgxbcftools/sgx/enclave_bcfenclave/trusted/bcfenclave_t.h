#ifndef BCFENCLAVE_T_H__
#define BCFENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


int ecall_bcfenclave_sample(char* refname, char* reffile, char* genomefile, char* outfile);

sgx_status_t SGX_CDECL ocall_bcfenclave_sample(const char* str);
sgx_status_t SGX_CDECL ocall_hfile_oflags(int* retval, const char* mode);
sgx_status_t SGX_CDECL ocall_open(int* retval, const char* filename, int mode);
sgx_status_t SGX_CDECL ocall_read(int* retval, int file, void* buf, unsigned int size);
sgx_status_t SGX_CDECL ocall_write(int* retval, int file, void* buf, unsigned int size);
sgx_status_t SGX_CDECL ocall_close(int* retval, int file);
sgx_status_t SGX_CDECL ocall_fsync(int* retval, int file);
sgx_status_t SGX_CDECL print_ocall(char* message);
sgx_status_t SGX_CDECL ocall_readmem(int* retval, void* file, void* buf, unsigned int size);
sgx_status_t SGX_CDECL ocall_drand48(double* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
