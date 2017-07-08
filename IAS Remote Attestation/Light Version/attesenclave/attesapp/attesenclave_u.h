#ifndef ATTESENCLAVE_U_H__
#define ATTESENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_report.h"
#include "sgx_utils.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t createReport(sgx_enclave_id_t eid, sgx_status_t* retval, const sgx_target_info_t* target_info, const sgx_report_data_t* report_data, sgx_report_t* report);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
