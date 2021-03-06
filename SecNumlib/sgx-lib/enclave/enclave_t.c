#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

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

/* sgx_ocfree() just restores the original outside stack pointer. */
#define OCALLOC(val, type, len) do {	\
	void* __tmp = sgx_ocalloc(len);	\
	if (__tmp == NULL) {	\
		sgx_ocfree();	\
		return SGX_ERROR_UNEXPECTED;\
	}			\
	(val) = (type)__tmp;	\
} while (0)


typedef struct ms_add_secret_t {
	int ms_secret;
} ms_add_secret_t;



typedef struct ms_set_key_t {
	uint8_t* ms_key;
} ms_set_key_t;

typedef struct ms_print_ocall_t {
	char* ms_message;
} ms_print_ocall_t;

typedef struct ms_rewind_ocall_t {
	FILE* ms_file;
} ms_rewind_ocall_t;

typedef struct ms_fseek_ocall_t {
	int ms_retval;
	FILE* ms_file;
	long int ms_offset;
	int ms_origin;
} ms_fseek_ocall_t;

typedef struct ms_ftell_ocall_t {
	long int ms_retval;
	FILE* ms_file;
} ms_ftell_ocall_t;

typedef struct ms_fwrite_enclave_memory_ocall_t {
	size_t ms_retval;
	void* ms_buffer;
	size_t ms_size;
	size_t ms_count;
	FILE* ms_stream;
} ms_fwrite_enclave_memory_ocall_t;

typedef struct ms_fread_copy_into_enclave_memory_ocall_t {
	size_t ms_retval;
	void* ms_buffer;
	size_t ms_size;
	size_t ms_count;
	FILE* ms_stream;
} ms_fread_copy_into_enclave_memory_ocall_t;

typedef struct ms_fclose_ocall_t {
	int ms_retval;
	FILE* ms_stream;
} ms_fclose_ocall_t;

typedef struct ms_fopen_ocall_t {
	FILE* ms_retval;
	char* ms_filename;
	char* ms_mode;
} ms_fopen_ocall_t;

typedef struct ms__ftelli64_ocall_t {
	int64_t ms_retval;
	FILE* ms_file;
} ms__ftelli64_ocall_t;

typedef struct ms_fflush_ocall_t {
	int ms_retval;
	FILE* ms_file;
} ms_fflush_ocall_t;

typedef struct ms_fopen_s_ocall_t {
	int ms_retval;
	FILE** ms_file;
	char* ms_filename;
	char* ms_mode;
} ms_fopen_s_ocall_t;

typedef struct ms__fseeki64_ocall_t {
	int ms_retval;
	FILE* ms_file;
	int64_t ms_offset;
	int ms_origin;
} ms__fseeki64_ocall_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_add_secret(void* pms)
{
	ms_add_secret_t* ms = SGX_CAST(ms_add_secret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_add_secret_t));

	add_secret(ms->ms_secret);


	return status;
}

static sgx_status_t SGX_CDECL sgx_print_secrets(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	print_secrets();
	return status;
}

static sgx_status_t SGX_CDECL sgx_test_encryption(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	test_encryption();
	return status;
}

static sgx_status_t SGX_CDECL sgx_set_key(void* pms)
{
	ms_set_key_t* ms = SGX_CAST(ms_set_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_key = ms->ms_key;
	size_t _len_key = 128;
	uint8_t* _in_key = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_set_key_t));
	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);

	if (_tmp_key != NULL) {
		_in_key = (uint8_t*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_key, _tmp_key, _len_key);
	}
	set_key(_in_key);
err:
	if (_in_key) free(_in_key);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_add_secret, 0},
		{(void*)(uintptr_t)sgx_print_secrets, 0},
		{(void*)(uintptr_t)sgx_test_encryption, 0},
		{(void*)(uintptr_t)sgx_set_key, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[12][4];
} g_dyn_entry_table = {
	12,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL print_ocall(char* message)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_message = message ? strlen(message) + 1 : 0;

	ms_print_ocall_t* ms;
	OCALLOC(ms, ms_print_ocall_t*, sizeof(*ms));

	if (message != NULL && sgx_is_within_enclave(message, _len_message)) {
		OCALLOC(ms->ms_message, char*, _len_message);
		memcpy(ms->ms_message, message, _len_message);
	} else if (message == NULL) {
		ms->ms_message = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL rewind_ocall(FILE* file)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_rewind_ocall_t* ms;
	OCALLOC(ms, ms_rewind_ocall_t*, sizeof(*ms));

	ms->ms_file = SGX_CAST(FILE*, file);
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL fseek_ocall(int* retval, FILE* file, long int offset, int origin)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_fseek_ocall_t* ms;
	OCALLOC(ms, ms_fseek_ocall_t*, sizeof(*ms));

	ms->ms_file = SGX_CAST(FILE*, file);
	ms->ms_offset = offset;
	ms->ms_origin = origin;
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ftell_ocall(long int* retval, FILE* file)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ftell_ocall_t* ms;
	OCALLOC(ms, ms_ftell_ocall_t*, sizeof(*ms));

	ms->ms_file = SGX_CAST(FILE*, file);
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL fwrite_enclave_memory_ocall(size_t* retval, const void* buffer, size_t size, size_t count, FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = count * size;

	ms_fwrite_enclave_memory_ocall_t* ms;
	OCALLOC(ms, ms_fwrite_enclave_memory_ocall_t*, sizeof(*ms));

	if (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) {
		OCALLOC(ms->ms_buffer, void*, _len_buffer);
		memcpy((void*)ms->ms_buffer, buffer, _len_buffer);
	} else if (buffer == NULL) {
		ms->ms_buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size = size;
	ms->ms_count = count;
	ms->ms_stream = SGX_CAST(FILE*, stream);
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL fread_copy_into_enclave_memory_ocall(size_t* retval, void* buffer, size_t size, size_t count, FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = count * size;

	ms_fread_copy_into_enclave_memory_ocall_t* ms;
	OCALLOC(ms, ms_fread_copy_into_enclave_memory_ocall_t*, sizeof(*ms));

	if (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) {
		OCALLOC(ms->ms_buffer, void*, _len_buffer);
		memset(ms->ms_buffer, 0, _len_buffer);
	} else if (buffer == NULL) {
		ms->ms_buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size = size;
	ms->ms_count = count;
	ms->ms_stream = SGX_CAST(FILE*, stream);
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;
	if (buffer) memcpy((void*)buffer, ms->ms_buffer, _len_buffer);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL fclose_ocall(int* retval, FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_fclose_ocall_t* ms;
	OCALLOC(ms, ms_fclose_ocall_t*, sizeof(*ms));

	ms->ms_stream = SGX_CAST(FILE*, stream);
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL fopen_ocall(FILE** retval, const char* filename, const char* mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_mode = mode ? strlen(mode) + 1 : 0;

	ms_fopen_ocall_t* ms;
	OCALLOC(ms, ms_fopen_ocall_t*, sizeof(*ms));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		OCALLOC(ms->ms_filename, char*, _len_filename);
		memcpy((void*)ms->ms_filename, filename, _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (mode != NULL && sgx_is_within_enclave(mode, _len_mode)) {
		OCALLOC(ms->ms_mode, char*, _len_mode);
		memcpy((void*)ms->ms_mode, mode, _len_mode);
	} else if (mode == NULL) {
		ms->ms_mode = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL _ftelli64_ocall(int64_t* retval, FILE* file)
{
	sgx_status_t status = SGX_SUCCESS;

	ms__ftelli64_ocall_t* ms;
	OCALLOC(ms, ms__ftelli64_ocall_t*, sizeof(*ms));

	ms->ms_file = SGX_CAST(FILE*, file);
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL fflush_ocall(int* retval, FILE* file)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_fflush_ocall_t* ms;
	OCALLOC(ms, ms_fflush_ocall_t*, sizeof(*ms));

	ms->ms_file = SGX_CAST(FILE*, file);
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL fopen_s_ocall(int* retval, FILE** file, const char* filename, const char* mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_mode = mode ? strlen(mode) + 1 : 0;

	ms_fopen_s_ocall_t* ms;
	OCALLOC(ms, ms_fopen_s_ocall_t*, sizeof(*ms));

	ms->ms_file = SGX_CAST(FILE**, file);
	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		OCALLOC(ms->ms_filename, char*, _len_filename);
		memcpy((void*)ms->ms_filename, filename, _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (mode != NULL && sgx_is_within_enclave(mode, _len_mode)) {
		OCALLOC(ms->ms_mode, char*, _len_mode);
		memcpy((void*)ms->ms_mode, mode, _len_mode);
	} else if (mode == NULL) {
		ms->ms_mode = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(10, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL _fseeki64_ocall(int* retval, FILE* file, int64_t offset, int origin)
{
	sgx_status_t status = SGX_SUCCESS;

	ms__fseeki64_ocall_t* ms;
	OCALLOC(ms, ms__fseeki64_ocall_t*, sizeof(*ms));

	ms->ms_file = SGX_CAST(FILE*, file);
	ms->ms_offset = offset;
	ms->ms_origin = origin;
	status = sgx_ocall(11, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
