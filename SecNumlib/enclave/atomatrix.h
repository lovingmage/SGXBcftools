#ifndef ATOMATRIXLIB_H
#define ATOMATRIXLIB_H
///////////////////////////////////////////////////////////////////////
// atomatrix.h - matrix computing & atomic operation pakcage         //
// ver 0.1                                                           //
// Language:    C++, Visual Studio 2011                              //
// Application: matrix computing library for SecNumlib               //
// Author:		Chenghong Wang,										 //
//				University of California, San Diego					 //
//				chw336@ucsd.edu										 //
//																	 //
///////////////////////////////////////////////////////////////////////
/*
 * Package Operations:
 * -------------------
 * This package is used for the SecNumlib, which is secure numecial computing platform
 * based on Intel SGX platform. All methods and operations in this package is the atomic
 * operation for matrix computing in SecNumlib.
 *
 * Build Process:
 * --------------
 * Required Files: atomatrix.h, atomatrix.cpp
 *
 * Build Command: devenv atomatrix.sln /rebuild debug
 *
 * Maintenance History:
 * --------------------
 *
 * ver 0.1 : 19 July 2016
 * - start up atomatrix project
 *
 * Planned Additions and Changes:
 * ------------------------------
 * - none yet
 */

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

typedef struct {
	int col;
	int row;
	double data[1024];
} sgx_matrix;


void atom_matrix_add(sgx_matrix *_opin1, sgx_matrix *_opin2, sgx_matrix *_opout);
void atom_matrix_subtract(sgx_matrix *_opin1, sgx_matrix *_opin2, sgx_matrix *_opout);
int atom_matrix_mul(sgx_matrix *_opin1, sgx_matrix *_opin2, sgx_matrix *_opout);

#endif