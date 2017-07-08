#ifndef ATTESENCLAVE_H
#define ATTESENCLAVE_H
///////////////////////////////////////////////////////////////////////
// attesenclave.h - enclave packave for IAS Attestation              //
// ver 0.2                                                           //
// Language:    C++, Visual Studio 2015                              //
// Application: Intel SGX Enclave package for IAS Attestation        //
// Author:		Chenghong Wang,										 //
//				University of California, San Diego					 //
//				chw336@ucsd.edu										 //
//																	 //
///////////////////////////////////////////////////////////////////////
/*
 * Package Operations:
 * -------------------
 * This package is the Intel SGX Enclave package whic is used for remote
 * attestation with Intel Attestation Service, this enclave contains trusted
 * functions which may used during remote attestation process
 *
 * Build Process:
 * --------------
 * Required Files: attesenclave.h, attesenclave.cpp, attesenclave.edl,
 *				   attesenclave_private.pem, sgx_trts.h, sgx_utils.h, 
 *				   sgx_report.h
 *
 * Build Command: devenv attesenclave.sln /rebuild debug
 *
 * Maintenance History:
 * --------------------
 * ver 0.2 : 25 June 2016
 * - fixed the link error flagged by sgx_create_report();
 * - solved the dependency relation, add new function createReport to wrap 
 *   sgx_create_report() within the enclave.
 *
 * ver 0.1 : 16 June 2016
 * - start up attesenclave project
 *
 * Planned Additions and Changes:
 * ------------------------------
 * - none yet
 */

#include "sgx_trts.h"

#include "sgx_utils.h"
#include "sgx_report.h"


#endif