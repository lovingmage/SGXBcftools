#ifndef ATTESENCLAVE_T_H__
#define ATTESENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_report.h"
#include "sgx_utils.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t createReport(const sgx_target_info_t* target_info, const sgx_report_data_t* report_data, sgx_report_t* report);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
