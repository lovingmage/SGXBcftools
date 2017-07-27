#include "bcfenclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

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
	char* ms_reffile;
	char* ms_genomefile;
	char* ms_outfile;
} ms_ecall_bcfenclave_sample_t;

typedef struct ms_ecall_bcfenclave_ccall_t {
	int ms_retval;
	char* ms_mlpfile;
	char* ms_ccallfile;
} ms_ecall_bcfenclave_ccall_t;

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

static sgx_status_t SGX_CDECL sgx_ecall_bcfenclave_sample(void* pms)
{
	ms_ecall_bcfenclave_sample_t* ms = SGX_CAST(ms_ecall_bcfenclave_sample_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_refname = ms->ms_refname;
	size_t _len_refname = _tmp_refname ? strlen(_tmp_refname) + 1 : 0;
	char* _in_refname = NULL;
	char* _tmp_reffile = ms->ms_reffile;
	size_t _len_reffile = _tmp_reffile ? strlen(_tmp_reffile) + 1 : 0;
	char* _in_reffile = NULL;
	char* _tmp_genomefile = ms->ms_genomefile;
	size_t _len_genomefile = _tmp_genomefile ? strlen(_tmp_genomefile) + 1 : 0;
	char* _in_genomefile = NULL;
	char* _tmp_outfile = ms->ms_outfile;
	size_t _len_outfile = _tmp_outfile ? strlen(_tmp_outfile) + 1 : 0;
	char* _in_outfile = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bcfenclave_sample_t));
	CHECK_UNIQUE_POINTER(_tmp_refname, _len_refname);
	CHECK_UNIQUE_POINTER(_tmp_reffile, _len_reffile);
	CHECK_UNIQUE_POINTER(_tmp_genomefile, _len_genomefile);
	CHECK_UNIQUE_POINTER(_tmp_outfile, _len_outfile);

	if (_tmp_refname != NULL) {
		_in_refname = (char*)malloc(_len_refname);
		if (_in_refname == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_refname, _tmp_refname, _len_refname);
		_in_refname[_len_refname - 1] = '\0';
	}
	if (_tmp_reffile != NULL) {
		_in_reffile = (char*)malloc(_len_reffile);
		if (_in_reffile == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_reffile, _tmp_reffile, _len_reffile);
		_in_reffile[_len_reffile - 1] = '\0';
	}
	if (_tmp_genomefile != NULL) {
		_in_genomefile = (char*)malloc(_len_genomefile);
		if (_in_genomefile == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_genomefile, _tmp_genomefile, _len_genomefile);
		_in_genomefile[_len_genomefile - 1] = '\0';
	}
	if (_tmp_outfile != NULL) {
		_in_outfile = (char*)malloc(_len_outfile);
		if (_in_outfile == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_outfile, _tmp_outfile, _len_outfile);
		_in_outfile[_len_outfile - 1] = '\0';
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
	ms_ecall_bcfenclave_ccall_t* ms = SGX_CAST(ms_ecall_bcfenclave_ccall_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_mlpfile = ms->ms_mlpfile;
	size_t _len_mlpfile = _tmp_mlpfile ? strlen(_tmp_mlpfile) + 1 : 0;
	char* _in_mlpfile = NULL;
	char* _tmp_ccallfile = ms->ms_ccallfile;
	size_t _len_ccallfile = _tmp_ccallfile ? strlen(_tmp_ccallfile) + 1 : 0;
	char* _in_ccallfile = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bcfenclave_ccall_t));
	CHECK_UNIQUE_POINTER(_tmp_mlpfile, _len_mlpfile);
	CHECK_UNIQUE_POINTER(_tmp_ccallfile, _len_ccallfile);

	if (_tmp_mlpfile != NULL) {
		_in_mlpfile = (char*)malloc(_len_mlpfile);
		if (_in_mlpfile == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_mlpfile, _tmp_mlpfile, _len_mlpfile);
		_in_mlpfile[_len_mlpfile - 1] = '\0';
	}
	if (_tmp_ccallfile != NULL) {
		_in_ccallfile = (char*)malloc(_len_ccallfile);
		if (_in_ccallfile == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_ccallfile, _tmp_ccallfile, _len_ccallfile);
		_in_ccallfile[_len_ccallfile - 1] = '\0';
	}
	ms->ms_retval = ecall_bcfenclave_ccall(_in_mlpfile, _in_ccallfile);
err:
	if (_in_mlpfile) free(_in_mlpfile);
	if (_in_ccallfile) free(_in_ccallfile);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_ecall_bcfenclave_sample, 0},
		{(void*)(uintptr_t)sgx_ecall_bcfenclave_ccall, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[10][2];
} g_dyn_entry_table = {
	10,
	{
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
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
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
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
		__tmp = (void *)((size_t)__tmp + _len_mode);
		memcpy((void*)ms->ms_mode, mode, _len_mode);
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
		__tmp = (void *)((size_t)__tmp + _len_filename);
		memcpy((void*)ms->ms_filename, filename, _len_filename);
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
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size = size;
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

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
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy(ms->ms_buf, buf, _len_buf);
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
		__tmp = (void *)((size_t)__tmp + _len_message);
		memcpy(ms->ms_message, message, _len_message);
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
		__tmp = (void *)((size_t)__tmp + _len_file);
		memcpy(ms->ms_file, file, _len_file);
	} else if (file == NULL) {
		ms->ms_file = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size = size;
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_drand48(double* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_drand48_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_drand48_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_drand48_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_drand48_t));

	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

