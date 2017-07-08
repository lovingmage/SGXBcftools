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

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "atomatrix.h"

//-------------< Atomic Matrix Addition Operation >----------------------------
void atom_matrix_add(sgx_matrix *_opin1, sgx_matrix *_opin2, sgx_matrix *_opout)
{
	int matrix_size = (_opin1->col)*(_opin1->row);
	_opout->col = _opin1->col;
	_opout->row = _opin1->col;
	int i = 1;

	for (i; i < matrix_size; i++)
	{
		_opout->data[i] = _opin1->data[i] + _opin2->data[i];
	}

}

//-------------< Atomic Matrix Subtraction Operation >----------------------------
void atom_matrix_subtract(sgx_matrix *_opin1, sgx_matrix *_opin2, sgx_matrix *_opout)
{
	int matrix_size = (_opin1->col)*(_opin1->row);
	_opout->col = _opin1->col;
	_opout->row = _opin1->col;
	int i = 1;

	for (i; i < matrix_size; i++)
	{
		_opout->data[i] = _opin1->data[i] - _opin2->data[i];
	}

}

//-------------< Atomic Matrix Multiple Operation >-----------------------------
int atom_matrix_mul(sgx_matrix *_opin1, sgx_matrix *_opin2, sgx_matrix *_opout)
{
	if (!(_opin1->col == _opin2->row))
		return 1;

	int bound = _opin1->row;
	_opout->col = _opin2->col;
	_opout->row = _opin1->row;
	int i, j, iter;


	for (i = 0; i < bound; i++)
	{
		for(j = 0; j < bound; j++)
		{
			int index = i * bound + j;
			_opout->data[index] = 0;

			for(iter = 0; iter < bound; iter++)
			{
				int index_a = iter * bound + j;
				int index_b = i * bound + iter;
				//printf("%d  %d  \n", index_a, index_b);
				_opout->data[index] += ( _opin1->data[index_a]) * (_opin1->data[index_b] );

			}
		}
	}
}

#ifdef TEST_MATRIXLIB

//------------------< Test Stub >--------------------------------------
int main()
{
	
	int a=3;
	int b=3;
	double num[9] = {1.13, 4.22, 5.31, 6.05, 7.15, 8.31, 9.01, 2.41, 1.08};

	sgx_matrix *MA = (sgx_matrix*)malloc(sizeof(sgx_matrix));
	sgx_matrix *MB = (sgx_matrix*)malloc(sizeof(sgx_matrix));
	sgx_matrix *MC = (sgx_matrix*)malloc(sizeof(sgx_matrix));
	MA->col = MB->col = a;
	MA->row = MB->row = b;
	memcpy_s(MA->data, sizeof(num), num, sizeof(num));
	memcpy_s(MB->data, sizeof(num), num, sizeof(num));
	atom_matrix_mul(MA,MB,MC);


	printf("%lf", MC->data[4]);
	
	
	//printf("%f", MA->data[4*1]);
	getchar();
	return 0;
}

#endif