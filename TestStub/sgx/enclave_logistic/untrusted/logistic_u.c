#include "logistic_u.h"
#include <errno.h>

typedef struct ms_ecall_logistic_sample_t {
	int ms_retval;
} ms_ecall_logistic_sample_t;

typedef struct ms_ocall_logistic_sample_t {
	char* ms_str;
} ms_ocall_logistic_sample_t;

static sgx_status_t SGX_CDECL logistic_ocall_logistic_sample(void* pms)
{
	ms_ocall_logistic_sample_t* ms = SGX_CAST(ms_ocall_logistic_sample_t*, pms);
	ocall_logistic_sample((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_logistic = {
	1,
	{
		(void*)logistic_ocall_logistic_sample,
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

