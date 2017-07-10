#ifndef BCFENCLAVE_U_H__
#define BCFENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_bcfenclave_sample, (const char* str));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_hfile_oflags, (const char* mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open, (const char* filename, int mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read, (int file, void* buf, unsigned int size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write, (int file, void* buf, unsigned int size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close, (int file));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fsync, (int file));
void SGX_UBRIDGE(SGX_NOCONVENTION, print_ocall, (char* message));

sgx_status_t ecall_bcfenclave_sample(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
