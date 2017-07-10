#include "logistic_u.h"
#include <errno.h>

typedef struct ms_ecall_logistic_sample_t {
	int ms_retval;
} ms_ecall_logistic_sample_t;

typedef struct ms_ocall_logistic_sample_t {
	char* ms_str;
} ms_ocall_logistic_sample_t;

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

static sgx_status_t SGX_CDECL logistic_ocall_logistic_sample(void* pms)
{
	ms_ocall_logistic_sample_t* ms = SGX_CAST(ms_ocall_logistic_sample_t*, pms);
	ocall_logistic_sample((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL logistic_ocall_open(void* pms)
{
	ms_ocall_open_t* ms = SGX_CAST(ms_ocall_open_t*, pms);
	ms->ms_retval = ocall_open((const char*)ms->ms_filename, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL logistic_ocall_read(void* pms)
{
	ms_ocall_read_t* ms = SGX_CAST(ms_ocall_read_t*, pms);
	ms->ms_retval = ocall_read(ms->ms_file, ms->ms_buf, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL logistic_ocall_write(void* pms)
{
	ms_ocall_write_t* ms = SGX_CAST(ms_ocall_write_t*, pms);
	ms->ms_retval = ocall_write(ms->ms_file, ms->ms_buf, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL logistic_ocall_close(void* pms)
{
	ms_ocall_close_t* ms = SGX_CAST(ms_ocall_close_t*, pms);
	ms->ms_retval = ocall_close(ms->ms_file);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL logistic_ocall_fsync(void* pms)
{
	ms_ocall_fsync_t* ms = SGX_CAST(ms_ocall_fsync_t*, pms);
	ms->ms_retval = ocall_fsync(ms->ms_file);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[6];
} ocall_table_logistic = {
	6,
	{
		(void*)logistic_ocall_logistic_sample,
		(void*)logistic_ocall_open,
		(void*)logistic_ocall_read,
		(void*)logistic_ocall_write,
		(void*)logistic_ocall_close,
		(void*)logistic_ocall_fsync,
	}
};
sgx_status_t ecall_logistic_sample(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_logistic_sample_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_logistic, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

