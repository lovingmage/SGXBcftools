///////////////////////////////////////////////////////////////////////
// b64encoder.c - base64 encoding package for						 //
//				  arbitrary data structure stored in mem block       //
// ver 0.1                                                           //
// Language:    C++, Visual Studio 2015                              //
// Application: Base64 Encoding Package for IAS usage                //
// Author:		Chenghong Wang,										 //
//				University of California, San Diego					 //
//				chw336@ucsd.edu										 //
//																	 //
///////////////////////////////////////////////////////////////////////

#include "cencode.h"
#include <stdio.h>
#include <stdlib.h>

//-----------< Predefined Base 64 Encode Length for Each Line >-----
const int CHARS_PER_LINE = 72;

//-----------< Init Encode State >----------------------------------
void base64_init_encodestate(base64_encodestate* state_in)
{
	state_in->step = step_A;
	state_in->result = 0;
	state_in->stepcount = 0;
}

//------------< Init Encode Value >----------------------------------
char base64_encode_value(char value_in)
{
	static const char* encoding = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	if (value_in > 63) return '=';
	return encoding[(int)value_in];
}

//------------< Function to B64Encode Memory Blocks >----------------
int base64_encode_block(const char* plaintext_in, int length_in, char* code_out, base64_encodestate* state_in)
{
	const char* plainchar = plaintext_in;
	const char* const plaintextend = plaintext_in + length_in;
	char* codechar = code_out;
	char result;
	char fragment;
	
	result = state_in->result;
	
	switch (state_in->step)
	{
		while (1)
		{
	case step_A:
			if (plainchar == plaintextend)
			{
				state_in->result = result;
				state_in->step = step_A;
				return codechar - code_out;
			}
			fragment = *plainchar++;
			result = (fragment & 0x0fc) >> 2;
			*codechar++ = base64_encode_value(result);
			result = (fragment & 0x003) << 4;
	case step_B:
			if (plainchar == plaintextend)
			{
				state_in->result = result;
				state_in->step = step_B;
				return codechar - code_out;
			}
			fragment = *plainchar++;
			result |= (fragment & 0x0f0) >> 4;
			*codechar++ = base64_encode_value(result);
			result = (fragment & 0x00f) << 2;
	case step_C:
			if (plainchar == plaintextend)
			{
				state_in->result = result;
				state_in->step = step_C;
				return codechar - code_out;
			}
			fragment = *plainchar++;
			result |= (fragment & 0x0c0) >> 6;
			*codechar++ = base64_encode_value(result);
			result  = (fragment & 0x03f) >> 0;
			*codechar++ = base64_encode_value(result);
			
			/* Stepcount used to identify characters in each lines. */
			++(state_in->stepcount);
			if (state_in->stepcount == CHARS_PER_LINE/4)
			{
				*codechar++ = '\n';
				state_in->stepcount = 0;
			}
		}
	}
	/* control should not reach here */
	return codechar - code_out;
}

//------------< Encode Block End >---------------------------------------
int base64_encode_blockend(char* code_out, base64_encodestate* state_in)
{
	char* codechar = code_out;
	
	switch (state_in->step)
	{
	case step_B:
		*codechar++ = base64_encode_value(state_in->result);
		*codechar++ = '=';
		*codechar++ = '=';
		break;
	case step_C:
		*codechar++ = base64_encode_value(state_in->result);
		*codechar++ = '=';
		break;
	case step_A:
		break;
	}
	*codechar++ = '\n';
	
	return codechar - code_out;
}

//-----------< Wrapped Function for base64 encoding >---------------------
long base64_encode(char *to, void* addr, unsigned int len)
{
	char *from = (char*)addr;
    base64_encodestate state;
    int size;
    base64_init_encodestate(&state);
    size = base64_encode_block(from, len, to, &state);
    size+= base64_encode_blockend(to + size, &state);
    return size;
}



//----------------< Test Stub >--------------------------------------------

#ifdef TEST_B64ENCODE

int main()
{
	char f[3] = {
	0x08, 0x13, 0x31
	};

	char t[5];
	int ret, len, i;
	len = base64_encode(t, f, 3);
	for(i = 0; i < len; i++)
	{
		printf("%c", t[i]);
	}
	printf("\n");
	
	getchar();
	return 0;
}

#endif