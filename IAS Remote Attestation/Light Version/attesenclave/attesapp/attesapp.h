#ifndef ATTESAPP_H
#define ATTESAPP_H
///////////////////////////////////////////////////////////////////////
// attesapp.h - application packave for IAS Attestation              //
// ver 0.1                                                           //
// Language:    C++, Visual Studio 2015                              //
// Application: Intel SGX Application package for IAS Attestation    //
// Author:		Chenghong Wang,										 //
//				University of California, San Diego					 //
//				chw336@ucsd.edu										 //
//																	 //
///////////////////////////////////////////////////////////////////////
/*
 * Package Operations:
 * -------------------
 * This package is the Intel SGX Application package whic is used for remote
 * attestation with Intel Attestation Service, this application contains defined
 * functions to request IAS by using HTTPS requests.
 *
 * Build Process:
 * --------------
 * Required Files: attesenclave_u.h, attesenclave_u.c, attesenclave.edl,
 *				   attesenclave.signed.dll, sgx_trts.h, sgx_uae_service, 
 *				   sgx_urts.h
 *
 * Build Command: devenv attesapp.sln /rebuild debug
 *
 * Maintenance History:
 * --------------------
 * ver 0.3 : 27 June 2016
 * - added the base64 encode for enclave's quote structure.
 * - supported two mode for getting quote structure, hex dump and encode mode.
 * - Extract hex dump and base64 encode into separate packages.
 * - Supported, local vars debugging.
 * 
 * ver 0.2 : 24 June 2016
 * - added the sequence of quote generation functions.
 * - added SPID into the original test mode, stored in application package.
 * - get group id from IAS which is 00000689 can be used later.
 *
 * ver 0.1 : 17 June 2016
 * - start up attesapp project
 * 
 * earlier version : 12 June 2016 
 * - shipped from Inter SGX SDK samplenclave, remote attestation
 * - In remote attestation sample code, they used a simulation SP, and the 
 *   attestation process is simulated always return with STATUS OK.
 *
 * Planned Additions and Changes:
 * ------------------------------
 * - none yet
 */
#include "sgx_urts.h"
#include "attesenclave_u.h"
#include "sgx_uae_service.h"
#include "../b64encoder/cencode.h"



#endif