#ifndef BCFENCLAVE_U_H__
#define BCFENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "sgx_tprotected_fs.h"

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
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readmem, (void* file, void* buf, unsigned int size));
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_exclusive_file_open, (const char* filename, uint8_t read_only, int64_t* file_size, int32_t* error_code));
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_check_if_file_exists, (const char* filename));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fread_node, (void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fwrite_node, (void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fclose, (void* f));
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fflush, (void* f));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_remove, (const char* filename));
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_recovery_file_open, (const char* filename));
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fwrite_recovery_node, (void* f, uint8_t* data, uint32_t data_length));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_do_file_recovery, (const char* filename, const char* recovery_filename, uint32_t node_size));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, create_session_ocall, (uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, close_session_ocall, (uint32_t sid, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, invoke_service_ocall, (uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t ecall_bcfenclave_sample(sgx_enclave_id_t eid, int* retval, char* refname, char* reffile, char* genomefile, char* outfile);
sgx_status_t ecall_bcfenclave_ccall(sgx_enclave_id_t eid, int* retval, char* mlpfile, char* ccallfile);
sgx_status_t ecall_bcfenclave_fwr(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
