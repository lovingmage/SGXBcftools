#include "bcfenclave_u.h"
#include <errno.h>

typedef struct ms_ecall_bcfenclave_sample_t {
	int ms_retval;
	char* ms_refname;
	char* ms_reffile;
	char* ms_genomefile;
	char* ms_outfile;
} ms_ecall_bcfenclave_sample_t;

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

typedef struct ms_ocall_drand48_t {
	double ms_retval;
} ms_ocall_drand48_t;

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

static sgx_status_t SGX_CDECL bcfenclave_ocall_drand48(void* pms)
{
	ms_ocall_drand48_t* ms = SGX_CAST(ms_ocall_drand48_t*, pms);
	ms->ms_retval = ocall_drand48();

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[10];
} ocall_table_bcfenclave = {
	10,
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
		(void*)bcfenclave_ocall_drand48,
	}
};
sgx_status_t ecall_bcfenclave_sample(sgx_enclave_id_t eid, int* retval, char* refname, char* reffile, char* genomefile, char* outfile)
{
	sgx_status_t status;
	ms_ecall_bcfenclave_sample_t ms;
	ms.ms_refname = refname;
	ms.ms_reffile = reffile;
	ms.ms_genomefile = genomefile;
	ms.ms_outfile = outfile;
	status = sgx_ecall(eid, 0, &ocall_table_bcfenclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

