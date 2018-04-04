#include "bcfenclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_ecall_bcfenclave_sample(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bcfenclave_sample_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_bcfenclave_sample_t* ms = SGX_CAST(ms_ecall_bcfenclave_sample_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_refname = ms->ms_refname;
	size_t _len_refname = ms->ms_refname_len ;
	char* _in_refname = NULL;
	char* _tmp_reffile = ms->ms_reffile;
	size_t _len_reffile = ms->ms_reffile_len ;
	char* _in_reffile = NULL;
	char* _tmp_genomefile = ms->ms_genomefile;
	size_t _len_genomefile = ms->ms_genomefile_len ;
	char* _in_genomefile = NULL;
	char* _tmp_outfile = ms->ms_outfile;
	size_t _len_outfile = ms->ms_outfile_len ;
	char* _in_outfile = NULL;

	CHECK_UNIQUE_POINTER(_tmp_refname, _len_refname);
	CHECK_UNIQUE_POINTER(_tmp_reffile, _len_reffile);
	CHECK_UNIQUE_POINTER(_tmp_genomefile, _len_genomefile);
	CHECK_UNIQUE_POINTER(_tmp_outfile, _len_outfile);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_refname != NULL && _len_refname != 0) {
		_in_refname = (char*)malloc(_len_refname);
		if (_in_refname == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_refname, _tmp_refname, _len_refname);
		_in_refname[_len_refname - 1] = '\0';
		if (_len_refname != strlen(_in_refname) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_reffile != NULL && _len_reffile != 0) {
		_in_reffile = (char*)malloc(_len_reffile);
		if (_in_reffile == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_reffile, _tmp_reffile, _len_reffile);
		_in_reffile[_len_reffile - 1] = '\0';
		if (_len_reffile != strlen(_in_reffile) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_genomefile != NULL && _len_genomefile != 0) {
		_in_genomefile = (char*)malloc(_len_genomefile);
		if (_in_genomefile == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_genomefile, _tmp_genomefile, _len_genomefile);
		_in_genomefile[_len_genomefile - 1] = '\0';
		if (_len_genomefile != strlen(_in_genomefile) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_outfile != NULL && _len_outfile != 0) {
		_in_outfile = (char*)malloc(_len_outfile);
		if (_in_outfile == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_outfile, _tmp_outfile, _len_outfile);
		_in_outfile[_len_outfile - 1] = '\0';
		if (_len_outfile != strlen(_in_outfile) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_bcfenclave_sample(_in_refname, _in_reffile, _in_genomefile, _in_outfile);
err:
	if (_in_refname) free(_in_refname);
	if (_in_reffile) free(_in_reffile);
	if (_in_genomefile) free(_in_genomefile);
	if (_in_outfile) free(_in_outfile);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_bcfenclave_ccall(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bcfenclave_ccall_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_bcfenclave_ccall_t* ms = SGX_CAST(ms_ecall_bcfenclave_ccall_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_mlpfile = ms->ms_mlpfile;
	size_t _len_mlpfile = ms->ms_mlpfile_len ;
	char* _in_mlpfile = NULL;
	char* _tmp_ccallfile = ms->ms_ccallfile;
	size_t _len_ccallfile = ms->ms_ccallfile_len ;
	char* _in_ccallfile = NULL;

	CHECK_UNIQUE_POINTER(_tmp_mlpfile, _len_mlpfile);
	CHECK_UNIQUE_POINTER(_tmp_ccallfile, _len_ccallfile);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_mlpfile != NULL && _len_mlpfile != 0) {
		_in_mlpfile = (char*)malloc(_len_mlpfile);
		if (_in_mlpfile == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_mlpfile, _tmp_mlpfile, _len_mlpfile);
		_in_mlpfile[_len_mlpfile - 1] = '\0';
		if (_len_mlpfile != strlen(_in_mlpfile) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_ccallfile != NULL && _len_ccallfile != 0) {
		_in_ccallfile = (char*)malloc(_len_ccallfile);
		if (_in_ccallfile == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_ccallfile, _tmp_ccallfile, _len_ccallfile);
		_in_ccallfile[_len_ccallfile - 1] = '\0';
		if (_len_ccallfile != strlen(_in_ccallfile) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_bcfenclave_ccall(_in_mlpfile, _in_ccallfile);
err:
	if (_in_mlpfile) free(_in_mlpfile);
	if (_in_ccallfile) free(_in_ccallfile);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_bcfenclave_fwr(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bcfenclave_fwr_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_bcfenclave_fwr_t* ms = SGX_CAST(ms_ecall_bcfenclave_fwr_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_bcfenclave_fwr();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_ecall_bcfenclave_sample, 0},
		{(void*)(uintptr_t)sgx_ecall_bcfenclave_ccall, 0},
		{(void*)(uintptr_t)sgx_ecall_bcfenclave_fwr, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[28][3];
} g_dyn_entry_table = {
	28,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_bcfenclave_sample(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_bcfenclave_sample_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_bcfenclave_sample_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_bcfenclave_sample_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_bcfenclave_sample_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		memcpy(__tmp, str, _len_str);
		__tmp = (void *)((size_t)__tmp + _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_hfile_oflags(int* retval, const char* mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_mode = mode ? strlen(mode) + 1 : 0;

	ms_ocall_hfile_oflags_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_hfile_oflags_t);
	void *__tmp = NULL;

	ocalloc_size += (mode != NULL && sgx_is_within_enclave(mode, _len_mode)) ? _len_mode : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_hfile_oflags_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_hfile_oflags_t));

	if (mode != NULL && sgx_is_within_enclave(mode, _len_mode)) {
		ms->ms_mode = (char*)__tmp;
		memcpy(__tmp, mode, _len_mode);
		__tmp = (void *)((size_t)__tmp + _len_mode);
	} else if (mode == NULL) {
		ms->ms_mode = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_open(int* retval, const char* filename, int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_ocall_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_open_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_open_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		memcpy(__tmp, filename, _len_filename);
		__tmp = (void *)((size_t)__tmp + _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_mode = mode;
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read(int* retval, int file, void* buf, unsigned int size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = size;

	ms_ocall_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_t));

	ms->ms_file = file;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size = size;
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write(int* retval, int file, void* buf, unsigned int size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = size;

	ms_ocall_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_t));

	ms->ms_file = file;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		memcpy(__tmp, buf, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size = size;
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_close(int* retval, int file)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_close_t));

	ms->ms_file = file;
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fsync(int* retval, int file)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fsync_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fsync_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fsync_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fsync_t));

	ms->ms_file = file;
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL print_ocall(char* message)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_message = message ? strlen(message) + 1 : 0;

	ms_print_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_print_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (message != NULL && sgx_is_within_enclave(message, _len_message)) ? _len_message : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_print_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_print_ocall_t));

	if (message != NULL && sgx_is_within_enclave(message, _len_message)) {
		ms->ms_message = (char*)__tmp;
		memcpy(__tmp, message, _len_message);
		__tmp = (void *)((size_t)__tmp + _len_message);
	} else if (message == NULL) {
		ms->ms_message = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(7, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_readmem(int* retval, void* file, void* buf, unsigned int size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file = size;
	size_t _len_buf = size;

	ms_ocall_readmem_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readmem_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	ocalloc_size += (file != NULL && sgx_is_within_enclave(file, _len_file)) ? _len_file : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readmem_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readmem_t));

	if (file != NULL && sgx_is_within_enclave(file, _len_file)) {
		ms->ms_file = (void*)__tmp;
		memcpy(__tmp, file, _len_file);
		__tmp = (void *)((size_t)__tmp + _len_file);
	} else if (file == NULL) {
		ms->ms_file = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size = size;
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_exclusive_file_open(void** retval, const char* filename, uint8_t read_only, int64_t* file_size, int32_t* error_code)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_file_size = sizeof(*file_size);
	size_t _len_error_code = sizeof(*error_code);

	ms_u_sgxprotectedfs_exclusive_file_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_exclusive_file_open_t);
	void *__tmp = NULL;

	void *__tmp_file_size = NULL;
	void *__tmp_error_code = NULL;
	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;
	ocalloc_size += (file_size != NULL && sgx_is_within_enclave(file_size, _len_file_size)) ? _len_file_size : 0;
	ocalloc_size += (error_code != NULL && sgx_is_within_enclave(error_code, _len_error_code)) ? _len_error_code : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_exclusive_file_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_exclusive_file_open_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		memcpy(__tmp, filename, _len_filename);
		__tmp = (void *)((size_t)__tmp + _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_read_only = read_only;
	if (file_size != NULL && sgx_is_within_enclave(file_size, _len_file_size)) {
		ms->ms_file_size = (int64_t*)__tmp;
		__tmp_file_size = __tmp;
		memset(__tmp_file_size, 0, _len_file_size);
		__tmp = (void *)((size_t)__tmp + _len_file_size);
	} else if (file_size == NULL) {
		ms->ms_file_size = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (error_code != NULL && sgx_is_within_enclave(error_code, _len_error_code)) {
		ms->ms_error_code = (int32_t*)__tmp;
		__tmp_error_code = __tmp;
		memset(__tmp_error_code, 0, _len_error_code);
		__tmp = (void *)((size_t)__tmp + _len_error_code);
	} else if (error_code == NULL) {
		ms->ms_error_code = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;
	if (file_size) memcpy((void*)file_size, __tmp_file_size, _len_file_size);
	if (error_code) memcpy((void*)error_code, __tmp_error_code, _len_error_code);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_check_if_file_exists(uint8_t* retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_u_sgxprotectedfs_check_if_file_exists_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_check_if_file_exists_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_check_if_file_exists_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_check_if_file_exists_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		memcpy(__tmp, filename, _len_filename);
		__tmp = (void *)((size_t)__tmp + _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(10, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fread_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = node_size;

	ms_u_sgxprotectedfs_fread_node_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fread_node_t);
	void *__tmp = NULL;

	void *__tmp_buffer = NULL;
	ocalloc_size += (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) ? _len_buffer : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fread_node_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fread_node_t));

	ms->ms_f = SGX_CAST(void*, f);
	ms->ms_node_number = node_number;
	if (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) {
		ms->ms_buffer = (uint8_t*)__tmp;
		__tmp_buffer = __tmp;
		memset(__tmp_buffer, 0, _len_buffer);
		__tmp = (void *)((size_t)__tmp + _len_buffer);
	} else if (buffer == NULL) {
		ms->ms_buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_node_size = node_size;
	status = sgx_ocall(11, ms);

	if (retval) *retval = ms->ms_retval;
	if (buffer) memcpy((void*)buffer, __tmp_buffer, _len_buffer);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = node_size;

	ms_u_sgxprotectedfs_fwrite_node_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fwrite_node_t);
	void *__tmp = NULL;

	ocalloc_size += (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) ? _len_buffer : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fwrite_node_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fwrite_node_t));

	ms->ms_f = SGX_CAST(void*, f);
	ms->ms_node_number = node_number;
	if (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) {
		ms->ms_buffer = (uint8_t*)__tmp;
		memcpy(__tmp, buffer, _len_buffer);
		__tmp = (void *)((size_t)__tmp + _len_buffer);
	} else if (buffer == NULL) {
		ms->ms_buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_node_size = node_size;
	status = sgx_ocall(12, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fclose(int32_t* retval, void* f)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sgxprotectedfs_fclose_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fclose_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fclose_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fclose_t));

	ms->ms_f = SGX_CAST(void*, f);
	status = sgx_ocall(13, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fflush(uint8_t* retval, void* f)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sgxprotectedfs_fflush_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fflush_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fflush_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fflush_t));

	ms->ms_f = SGX_CAST(void*, f);
	status = sgx_ocall(14, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_remove(int32_t* retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_u_sgxprotectedfs_remove_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_remove_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_remove_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_remove_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		memcpy(__tmp, filename, _len_filename);
		__tmp = (void *)((size_t)__tmp + _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(15, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_recovery_file_open(void** retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_u_sgxprotectedfs_recovery_file_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_recovery_file_open_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_recovery_file_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_recovery_file_open_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		memcpy(__tmp, filename, _len_filename);
		__tmp = (void *)((size_t)__tmp + _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(16, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_recovery_node(uint8_t* retval, void* f, uint8_t* data, uint32_t data_length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = data_length * sizeof(*data);

	ms_u_sgxprotectedfs_fwrite_recovery_node_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fwrite_recovery_node_t);
	void *__tmp = NULL;

	ocalloc_size += (data != NULL && sgx_is_within_enclave(data, _len_data)) ? _len_data : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fwrite_recovery_node_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fwrite_recovery_node_t));

	ms->ms_f = SGX_CAST(void*, f);
	if (data != NULL && sgx_is_within_enclave(data, _len_data)) {
		ms->ms_data = (uint8_t*)__tmp;
		memcpy(__tmp, data, _len_data);
		__tmp = (void *)((size_t)__tmp + _len_data);
	} else if (data == NULL) {
		ms->ms_data = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_data_length = data_length;
	status = sgx_ocall(17, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_do_file_recovery(int32_t* retval, const char* filename, const char* recovery_filename, uint32_t node_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_recovery_filename = recovery_filename ? strlen(recovery_filename) + 1 : 0;

	ms_u_sgxprotectedfs_do_file_recovery_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_do_file_recovery_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;
	ocalloc_size += (recovery_filename != NULL && sgx_is_within_enclave(recovery_filename, _len_recovery_filename)) ? _len_recovery_filename : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_do_file_recovery_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_do_file_recovery_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		memcpy(__tmp, filename, _len_filename);
		__tmp = (void *)((size_t)__tmp + _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (recovery_filename != NULL && sgx_is_within_enclave(recovery_filename, _len_recovery_filename)) {
		ms->ms_recovery_filename = (char*)__tmp;
		memcpy(__tmp, recovery_filename, _len_recovery_filename);
		__tmp = (void *)((size_t)__tmp + _len_recovery_filename);
	} else if (recovery_filename == NULL) {
		ms->ms_recovery_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_node_size = node_size;
	status = sgx_ocall(18, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(*sid);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	void *__tmp_sid = NULL;
	void *__tmp_dh_msg1 = NULL;
	ocalloc_size += (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) ? _len_sid : 0;
	ocalloc_size += (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) ? _len_dh_msg1 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));

	if (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) {
		ms->ms_sid = (uint32_t*)__tmp;
		__tmp_sid = __tmp;
		memset(__tmp_sid, 0, _len_sid);
		__tmp = (void *)((size_t)__tmp + _len_sid);
	} else if (sid == NULL) {
		ms->ms_sid = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) {
		ms->ms_dh_msg1 = (uint8_t*)__tmp;
		__tmp_dh_msg1 = __tmp;
		memset(__tmp_dh_msg1, 0, _len_dh_msg1);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
	} else if (dh_msg1 == NULL) {
		ms->ms_dh_msg1 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg1_size = dh_msg1_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(19, ms);

	if (retval) *retval = ms->ms_retval;
	if (sid) memcpy((void*)sid, __tmp_sid, _len_sid);
	if (dh_msg1) memcpy((void*)dh_msg1, __tmp_dh_msg1, _len_dh_msg1);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	void *__tmp_dh_msg3 = NULL;
	ocalloc_size += (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) ? _len_dh_msg2 : 0;
	ocalloc_size += (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) ? _len_dh_msg3 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));

	ms->ms_sid = sid;
	if (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) {
		ms->ms_dh_msg2 = (uint8_t*)__tmp;
		memcpy(__tmp, dh_msg2, _len_dh_msg2);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
	} else if (dh_msg2 == NULL) {
		ms->ms_dh_msg2 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg2_size = dh_msg2_size;
	if (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) {
		ms->ms_dh_msg3 = (uint8_t*)__tmp;
		__tmp_dh_msg3 = __tmp;
		memset(__tmp_dh_msg3, 0, _len_dh_msg3);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
	} else if (dh_msg3 == NULL) {
		ms->ms_dh_msg3 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg3_size = dh_msg3_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(20, ms);

	if (retval) *retval = ms->ms_retval;
	if (dh_msg3) memcpy((void*)dh_msg3, __tmp_dh_msg3, _len_dh_msg3);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));

	ms->ms_sid = sid;
	ms->ms_timeout = timeout;
	status = sgx_ocall(21, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	void *__tmp_pse_message_resp = NULL;
	ocalloc_size += (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) ? _len_pse_message_req : 0;
	ocalloc_size += (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) ? _len_pse_message_resp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));

	if (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) {
		ms->ms_pse_message_req = (uint8_t*)__tmp;
		memcpy(__tmp, pse_message_req, _len_pse_message_req);
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
	} else if (pse_message_req == NULL) {
		ms->ms_pse_message_req = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_req_size = pse_message_req_size;
	if (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) {
		ms->ms_pse_message_resp = (uint8_t*)__tmp;
		__tmp_pse_message_resp = __tmp;
		memset(__tmp_pse_message_resp, 0, _len_pse_message_resp);
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
	} else if (pse_message_resp == NULL) {
		ms->ms_pse_message_resp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_resp_size = pse_message_resp_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(22, ms);

	if (retval) *retval = ms->ms_retval;
	if (pse_message_resp) memcpy((void*)pse_message_resp, __tmp_pse_message_resp, _len_pse_message_resp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;
	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(23, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, __tmp_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(24, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(25, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(26, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		memcpy(__tmp, waiters, _len_waiters);
		__tmp = (void *)((size_t)__tmp + _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(27, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

