///////////////////////////////////////////////////////////////////////
// attesenclave.cpp - enclave packave for IAS Attestation            //
// ver 0.1                                                           //
// Language:    C++, Visual Studio 2015                              //
// Application: Intel SGX Enclave package for IAS Attestation        //
// Author:		Chenghong Wang,										 //
//				University of California, San Diego					 //
//				chw336@ucsd.edu										 //
//																	 //
///////////////////////////////////////////////////////////////////////

#include "attesenclave_t.h"

#include "attesenclave.h"


//-------<enclave ECALL function to create report for target enclave>-------------------
sgx_status_t createReport(const sgx_target_info_t *target_info,
						  const sgx_report_data_t *report_data,
						  sgx_report_t *report)
{
	sgx_status_t ret = SGX_SUCCESS;
	ret = sgx_create_report(target_info, report_data, report);

	return ret;
}
