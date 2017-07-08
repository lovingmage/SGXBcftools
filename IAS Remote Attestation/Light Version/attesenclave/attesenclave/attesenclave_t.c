#include "attesenclave_t.h"

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


typedef struct ms_createReport_t {
	sgx_status_t ms_retval;
	sgx_target_info_t* ms_target_info;
	sgx_report_data_t* ms_report_data;
	sgx_report_t* ms_report;
} ms_createReport_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_createReport(void* pms)
{
	ms_createReport_t* ms = SGX_CAST(ms_createReport_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_target_info_t* _tmp_target_info = ms->ms_target_info;
	size_t _len_target_info = sizeof(*_tmp_target_info);
	sgx_target_info_t* _in_target_info = NULL;
	sgx_report_data_t* _tmp_report_data = ms->ms_report_data;
	size_t _len_report_data = sizeof(*_tmp_report_data);
	sgx_report_data_t* _in_report_data = NULL;
	sgx_report_t* _tmp_report = ms->ms_report;
	size_t _len_report = sizeof(*_tmp_report);
	sgx_report_t* _in_report = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_createReport_t));
	CHECK_UNIQUE_POINTER(_tmp_target_info, _len_target_info);
	CHECK_UNIQUE_POINTER(_tmp_report_data, _len_report_data);
	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);

	if (_tmp_target_info != NULL) {
		_in_target_info = (sgx_target_info_t*)malloc(_len_target_info);
		if (_in_target_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_target_info, _tmp_target_info, _len_target_info);
	}
	if (_tmp_report_data != NULL) {
		_in_report_data = (sgx_report_data_t*)malloc(_len_report_data);
		if (_in_report_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_report_data, _tmp_report_data, _len_report_data);
	}
	if (_tmp_report != NULL) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}
	ms->ms_retval = createReport((const sgx_target_info_t*)_in_target_info, (const sgx_report_data_t*)_in_report_data, _in_report);
err:
	if (_in_target_info) free((void*)_in_target_info);
	if (_in_report_data) free((void*)_in_report_data);
	if (_in_report) {
		memcpy(_tmp_report, _in_report, _len_report);
		free(_in_report);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_createReport, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


#ifdef _MSC_VER
#pragma warning(pop)
#endif
