#ifndef BASE64_CENCODE_H
#define BASE64_CENCODE_H
///////////////////////////////////////////////////////////////////////
// b64encoder.h - base64 encoding package for						 //
//				  arbitrary data structure stored in mem block       //
// ver 0.1                                                           //
// Language:    C++, Visual Studio 2015                              //
// Application: Base64 Encoding Package for IAS usage                //
// Author:		Chenghong Wang,										 //
//				University of California, San Diego					 //
//				chw336@ucsd.edu										 //
//																	 //
///////////////////////////////////////////////////////////////////////
/*
 * Package Operations:
 * -------------------
 * This package is the base64 encoding package which is used for encode
 * memory blocks, data structures, etc. It support any kinds of memory 
 * blocks and data structure.
 *
 * Build Process:
 * --------------
 * Required Files: cencode.h
 *
 * Build Command: devenv b64encoder.sln /rebuild debug
 *
 * Maintenance History:
 * --------------------
 *
 * ver 0.1 : 27 June 2016
 * - start up b64encoder project
 * 
 * Planned Additions and Changes:
 * ------------------------------
 * - none yet
 */

typedef enum
{
	step_A, step_B, step_C
} base64_encodestep;

typedef struct
{
	base64_encodestep step;
	char result;
	int stepcount;
} base64_encodestate;

void base64_init_encodestate(base64_encodestate* state_in);

char base64_encode_value(char value_in);

int base64_encode_block(const char* plaintext_in, int length_in, char* code_out, base64_encodestate* state_in);

int base64_encode_blockend(char* code_out, base64_encodestate* state_in);

long base64_encode(char *to, void *addr, unsigned int len);


#endif /* BASE64_CENCODE_H */
