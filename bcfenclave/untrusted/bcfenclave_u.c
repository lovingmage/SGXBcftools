#include "bcfenclave_u.h"
#include <errno.h>

typedef struct ms_ecall_bcfenclave_sample_t {
	int ms_retval;
	char* ms_refname;
	size_t ms_refname_len;
	char* ms_reffile;
	size_t ms_reffile_len;
	char* ms_genomefile;
	size_t ms_genomefile_len;
	char* ms_outfile;
	size_t ms_outfile_len;
} ms_ecall_bcfenclave_sample_t;

typedef struct ms_ecall_bcfenclave_ccall_t {
	int ms_retval;
	char* ms_mlpfile;
	size_t ms_mlpfile_len;
	char* ms_ccallfile;
	size_t ms_ccallfile_len;
} ms_ecall_bcfenclave_ccall_t;

typedef struct ms_ecall_bcfenclave_fwr_t {
	int ms_retval;
} ms_ecall_bcfenclave_fwr_t;

typedef struct ms_ocall_bcfenclave_sample_t {
	char* ms_str;
} ms_ocall_bcfenclave_sample_t;

typedef struct ms_ocall_hfile_oflags_t {
	int ms_retval;
	char* ms_mode;
} ms_ocall_hfile_oflags_t;

typedef struct ms_ocall_open_t {
	int ms_retval;
	char* ms_filename;
	int ms_mode;
} ms_ocall_open_t;

typedef struct ms_ocall_read_t {
	int ms_retval;
	int ms_file;
	void* ms_buf;
	unsigned int ms_size;
} ms_ocall_read_t;

typedef struct ms_ocall_write_t {
	int ms_retval;
	int ms_file;
	void* ms_buf;
	unsigned int ms_size;
} ms_ocall_write_t;

typedef struct ms_ocall_close_t {
	int ms_retval;
	int ms_file;
} ms_ocall_close_t;

typedef struct ms_ocall_fsync_t {
	int ms_retval;
	int ms_file;
} ms_ocall_fsync_t;

typedef struct ms_print_ocall_t {
	char* ms_message;
} ms_print_ocall_t;

typedef struct ms_ocall_readmem_t {
	int ms_retval;
	void* ms_file;
	void* ms_buf;
	unsigned int ms_size;
} ms_ocall_readmem_t;

typedef struct ms_u_sgxprotectedfs_exclusive_file_open_t {
	void* ms_retval;
	char* ms_filename;
	uint8_t ms_read_only;
	int64_t* ms_file_size;
	int32_t* ms_error_code;
} ms_u_sgxprotectedfs_exclusive_file_open_t;

typedef struct ms_u_sgxprotectedfs_check_if_file_exists_t {
	uint8_t ms_retval;
	char* ms_filename;
} ms_u_sgxprotectedfs_check_if_file_exists_t;

typedef struct ms_u_sgxprotectedfs_fread_node_t {
	int32_t ms_retval;
	void* ms_f;
	uint64_t ms_node_number;
	uint8_t* ms_buffer;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_fread_node_t;

typedef struct ms_u_sgxprotectedfs_fwrite_node_t {
	int32_t ms_retval;
	void* ms_f;
	uint64_t ms_node_number;
	uint8_t* ms_buffer;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_fwrite_node_t;

typedef struct ms_u_sgxprotectedfs_fclose_t {
	int32_t ms_retval;
	void* ms_f;
} ms_u_sgxprotectedfs_fclose_t;

typedef struct ms_u_sgxprotectedfs_fflush_t {
	uint8_t ms_retval;
	void* ms_f;
} ms_u_sgxprotectedfs_fflush_t;

typedef struct ms_u_sgxprotectedfs_remove_t {
	int32_t ms_retval;
	char* ms_filename;
} ms_u_sgxprotectedfs_remove_t;

typedef struct ms_u_sgxprotectedfs_recovery_file_open_t {
	void* ms_retval;
	char* ms_filename;
} ms_u_sgxprotectedfs_recovery_file_open_t;

typedef struct ms_u_sgxprotectedfs_fwrite_recovery_node_t {
	uint8_t ms_retval;
	void* ms_f;
	uint8_t* ms_data;
	uint32_t ms_data_length;
} ms_u_sgxprotectedfs_fwrite_recovery_node_t;

typedef struct ms_u_sgxprotectedfs_do_file_recovery_t {
	int32_t ms_retval;
	char* ms_filename;
	char* ms_recovery_filename;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_do_file_recovery_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL bcfenclave_ocall_bcfenclave_sample(void* pms)
{
	ms_ocall_bcfenclave_sample_t* ms = SGX_CAST(ms_ocall_bcfenclave_sample_t*, pms);
	ocall_bcfenclave_sample((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_ocall_hfile_oflags(void* pms)
{
	ms_ocall_hfile_oflags_t* ms = SGX_CAST(ms_ocall_hfile_oflags_t*, pms);
	ms->ms_retval = ocall_hfile_oflags((const char*)ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_ocall_open(void* pms)
{
	ms_ocall_open_t* ms = SGX_CAST(ms_ocall_open_t*, pms);
	ms->ms_retval = ocall_open((const char*)ms->ms_filename, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_ocall_read(void* pms)
{
	ms_ocall_read_t* ms = SGX_CAST(ms_ocall_read_t*, pms);
	ms->ms_retval = ocall_read(ms->ms_file, ms->ms_buf, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_ocall_write(void* pms)
{
	ms_ocall_write_t* ms = SGX_CAST(ms_ocall_write_t*, pms);
	ms->ms_retval = ocall_write(ms->ms_file, ms->ms_buf, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_ocall_close(void* pms)
{
	ms_ocall_close_t* ms = SGX_CAST(ms_ocall_close_t*, pms);
	ms->ms_retval = ocall_close(ms->ms_file);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_ocall_fsync(void* pms)
{
	ms_ocall_fsync_t* ms = SGX_CAST(ms_ocall_fsync_t*, pms);
	ms->ms_retval = ocall_fsync(ms->ms_file);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_print_ocall(void* pms)
{
	ms_print_ocall_t* ms = SGX_CAST(ms_print_ocall_t*, pms);
	print_ocall(ms->ms_message);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_ocall_readmem(void* pms)
{
	ms_ocall_readmem_t* ms = SGX_CAST(ms_ocall_readmem_t*, pms);
	ms->ms_retval = ocall_readmem(ms->ms_file, ms->ms_buf, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_u_sgxprotectedfs_exclusive_file_open(void* pms)
{
	ms_u_sgxprotectedfs_exclusive_file_open_t* ms = SGX_CAST(ms_u_sgxprotectedfs_exclusive_file_open_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_exclusive_file_open((const char*)ms->ms_filename, ms->ms_read_only, ms->ms_file_size, ms->ms_error_code);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_u_sgxprotectedfs_check_if_file_exists(void* pms)
{
	ms_u_sgxprotectedfs_check_if_file_exists_t* ms = SGX_CAST(ms_u_sgxprotectedfs_check_if_file_exists_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_check_if_file_exists((const char*)ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_u_sgxprotectedfs_fread_node(void* pms)
{
	ms_u_sgxprotectedfs_fread_node_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fread_node_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fread_node(ms->ms_f, ms->ms_node_number, ms->ms_buffer, ms->ms_node_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_u_sgxprotectedfs_fwrite_node(void* pms)
{
	ms_u_sgxprotectedfs_fwrite_node_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fwrite_node_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fwrite_node(ms->ms_f, ms->ms_node_number, ms->ms_buffer, ms->ms_node_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_u_sgxprotectedfs_fclose(void* pms)
{
	ms_u_sgxprotectedfs_fclose_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fclose_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fclose(ms->ms_f);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_u_sgxprotectedfs_fflush(void* pms)
{
	ms_u_sgxprotectedfs_fflush_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fflush_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fflush(ms->ms_f);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_u_sgxprotectedfs_remove(void* pms)
{
	ms_u_sgxprotectedfs_remove_t* ms = SGX_CAST(ms_u_sgxprotectedfs_remove_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_remove((const char*)ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_u_sgxprotectedfs_recovery_file_open(void* pms)
{
	ms_u_sgxprotectedfs_recovery_file_open_t* ms = SGX_CAST(ms_u_sgxprotectedfs_recovery_file_open_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_recovery_file_open((const char*)ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_u_sgxprotectedfs_fwrite_recovery_node(void* pms)
{
	ms_u_sgxprotectedfs_fwrite_recovery_node_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fwrite_recovery_node_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fwrite_recovery_node(ms->ms_f, ms->ms_data, ms->ms_data_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_u_sgxprotectedfs_do_file_recovery(void* pms)
{
	ms_u_sgxprotectedfs_do_file_recovery_t* ms = SGX_CAST(ms_u_sgxprotectedfs_do_file_recovery_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_do_file_recovery((const char*)ms->ms_filename, (const char*)ms->ms_recovery_filename, ms->ms_node_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bcfenclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[28];
} ocall_table_bcfenclave = {
	28,
	{
		(void*)bcfenclave_ocall_bcfenclave_sample,
		(void*)bcfenclave_ocall_hfile_oflags,
		(void*)bcfenclave_ocall_open,
		(void*)bcfenclave_ocall_read,
		(void*)bcfenclave_ocall_write,
		(void*)bcfenclave_ocall_close,
		(void*)bcfenclave_ocall_fsync,
		(void*)bcfenclave_print_ocall,
		(void*)bcfenclave_ocall_readmem,
		(void*)bcfenclave_u_sgxprotectedfs_exclusive_file_open,
		(void*)bcfenclave_u_sgxprotectedfs_check_if_file_exists,
		(void*)bcfenclave_u_sgxprotectedfs_fread_node,
		(void*)bcfenclave_u_sgxprotectedfs_fwrite_node,
		(void*)bcfenclave_u_sgxprotectedfs_fclose,
		(void*)bcfenclave_u_sgxprotectedfs_fflush,
		(void*)bcfenclave_u_sgxprotectedfs_remove,
		(void*)bcfenclave_u_sgxprotectedfs_recovery_file_open,
		(void*)bcfenclave_u_sgxprotectedfs_fwrite_recovery_node,
		(void*)bcfenclave_u_sgxprotectedfs_do_file_recovery,
		(void*)bcfenclave_create_session_ocall,
		(void*)bcfenclave_exchange_report_ocall,
		(void*)bcfenclave_close_session_ocall,
		(void*)bcfenclave_invoke_service_ocall,
		(void*)bcfenclave_sgx_oc_cpuidex,
		(void*)bcfenclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)bcfenclave_sgx_thread_set_untrusted_event_ocall,
		(void*)bcfenclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)bcfenclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_bcfenclave_sample(sgx_enclave_id_t eid, int* retval, char* refname, char* reffile, char* genomefile, char* outfile)
{
	sgx_status_t status;
	ms_ecall_bcfenclave_sample_t ms;
	ms.ms_refname = (char*)refname;
	ms.ms_refname_len = refname ? strlen(refname) + 1 : 0;
	ms.ms_reffile = (char*)reffile;
	ms.ms_reffile_len = reffile ? strlen(reffile) + 1 : 0;
	ms.ms_genomefile = (char*)genomefile;
	ms.ms_genomefile_len = genomefile ? strlen(genomefile) + 1 : 0;
	ms.ms_outfile = (char*)outfile;
	ms.ms_outfile_len = outfile ? strlen(outfile) + 1 : 0;
	status = sgx_ecall(eid, 0, &ocall_table_bcfenclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_bcfenclave_ccall(sgx_enclave_id_t eid, int* retval, char* mlpfile, char* ccallfile)
{
	sgx_status_t status;
	ms_ecall_bcfenclave_ccall_t ms;
	ms.ms_mlpfile = (char*)mlpfile;
	ms.ms_mlpfile_len = mlpfile ? strlen(mlpfile) + 1 : 0;
	ms.ms_ccallfile = (char*)ccallfile;
	ms.ms_ccallfile_len = ccallfile ? strlen(ccallfile) + 1 : 0;
	status = sgx_ecall(eid, 1, &ocall_table_bcfenclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_bcfenclave_fwr(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_bcfenclave_fwr_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_bcfenclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

