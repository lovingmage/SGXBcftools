#include "attesenclave_u.h"

typedef struct ms_createReport_t {
	sgx_status_t ms_retval;
	sgx_target_info_t* ms_target_info;
	sgx_report_data_t* ms_report_data;
	sgx_report_t* ms_report;
} ms_createReport_t;

static const struct {
	size_t nr_ocall;
	void * func_addr[1];
} ocall_table_attesenclave = {
	0,
	{ NULL },
};

sgx_status_t createReport(sgx_enclave_id_t eid, sgx_status_t* retval, const sgx_target_info_t* target_info, const sgx_report_data_t* report_data, sgx_report_t* report)
{
	sgx_status_t status;
	ms_createReport_t ms;
	ms.ms_target_info = (sgx_target_info_t*)target_info;
	ms.ms_report_data = (sgx_report_data_t*)report_data;
	ms.ms_report = report;
	status = sgx_ecall(eid, 0, &ocall_table_attesenclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

