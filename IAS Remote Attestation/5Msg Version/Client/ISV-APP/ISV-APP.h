//  Copyright (C) Intel Corporation, 2015 All Rights Reserved.
/**************************************************************************************************
FILENAME:       ISV-APP.h
DESCRIPTION:    Header file for ISV-APP.cpp, Client side implementation of the End to end Remote
Attestation process using C++ SDK, Casablanca and JSON format for data serialization and de-serialization
//INCLUDES: EnclaveManagement.h
//           |
//           +--->RemoteAttestation.h
//            |
//			  +-----> JsonDeserialization.h
//			     |
//			     +-----> RaMessages.h
FUNCTIONALITY: Different messages involved in the sigma protocol are framed and 
All the SGX function descriptions can be obtained in SGX User Guide
******************************************************************************************************/

#include "stdafx.h"
#include "EnclaveManagement.h"
#pragma once
using namespace std;

extern bool verbose;
extern bool b_pse;
extern bool keepEnclave;
extern string url;

/**
Fetches the search string from the configuration file, App.config.txt using basic File IO;
Prints an error message if the file is not found or if the search string
is not found in the file
**/
string findValue(string);

/*Fetches the verbose, b_pse, keepenclave, and SPUri flags value from the app.configuration.txt
*/
void InitSettings();