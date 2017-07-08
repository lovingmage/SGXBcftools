///////////////////////////////////////////////////////////////////////
// attesapp.cpp - application packave for IAS Attestation            //
// ver 0.1                                                           //
// Language:    C++, Visual Studio 2015                              //
// Application: Intel SGX Application package for IAS Attestation    //
// Author:		Chenghong Wang,										 //
//				University of California, San Diego					 //
//				chw336@ucsd.edu										 //
//																	 //
///////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#define ENCLAVE_FILE _T("attesenclave.signed.dll")

#include "attesapp.h"

static sgx_target_info_t g_qe_target_info;

//-----------< predefine const elements >--------------------------
const sgx_spid_t p_spid[] = 
{0x45, 0x30, 0x44, 0x36, 0x34, 0x34, 0x42, 0x32, 0x46, 0x31, 0x33, 
 0x36, 0x46, 0x45, 0x30, 0x41, 0x32, 0x35, 0x44, 0x30, 0x46, 0x43, 
 0x46, 0x36, 0x32, 0x33, 0x39, 0x35, 0x31, 0x39, 0x36, 0x46};

//------------< Dump any data structure into HEX >-----------------
void hexDumpPrint (char *desc, void *addr, int len) {
    int					i;
    unsigned char		buff[17];
    unsigned char		*pc = (unsigned char*)addr;

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }
        printf (" %02x", pc[i]);

        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }
    printf ("  %s\n", buff);
}

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

//-----------< Function Used To Dump out Quote Structure >-----------------
sgx_status_t getQuote(sgx_enclave_id_t	eid, sgx_quote_t *p_quote, uint32_t *p_quote_size)

{

	sgx_status_t		ret   = SGX_SUCCESS;

	/* predefined vars & elements for quote generation */
	sgx_target_info_t	p_target_info;
	sgx_epid_group_id_t p_gid = {0};
	sgx_report_data_t	report_data;
	sgx_report_t		report;
	sgx_status_t		retrival;
	//uint32_t			p_quote_size;
	//sgx_quote_t			p_quote;


	//* init quote - sgx_init_quote() */
	memset(&p_target_info, 0, sizeof(p_target_info));

	ret = sgx_init_quote(&p_target_info, &p_gid);
	if (ret != SGX_SUCCESS) {
        printf("\nApp: error %#x, failed to init quote.\n", ret);
    }
	printf("\nLog: Testing Init Quote -> STATUS: Successful.\n");

	//g_ukey_spin_lock.lock();
	if(memcpy_s(&g_qe_target_info, sizeof(g_qe_target_info),
             &p_target_info, sizeof(p_target_info)) != 0)
    {
        //g_ukey_spin_lock.unlock();
        return SGX_ERROR_UNEXPECTED;
    }

	/* create report - createReport() enclave ECALL */
	memset(&report, 0, sizeof(report));
	sgx_quote_nonce_t nonce;
    sgx_report_t qe_report;
    sgx_target_info_t qe_target_info;

	memset(&nonce, 0, sizeof(nonce));
    memset(&qe_report, 0, sizeof(qe_report));

	if(memcpy_s(&qe_target_info, sizeof(qe_target_info),
                &g_qe_target_info, sizeof(g_qe_target_info)) != 0)
    {
           ret = SGX_ERROR_UNEXPECTED;
    }

	ret = createReport(eid, &retrival, &qe_target_info, &report_data, &report);
	if (ret != SGX_SUCCESS) {
        printf("\nApp: error %#x, failed to create report.\n", ret);
    }
	printf("\nLog: Testing Create Report -> STATUS: Successful.\n");

	
	/* Get quote size first */
	ret = sgx_get_quote_size(NULL, p_quote_size);
	if (ret != SGX_SUCCESS) {
        printf("\nApp: error %#x, failed to get quote size.\n", ret);
    }
	printf("\nLog: Testing Get Quote Size -> STATUS: Successful.\n");
	

	/* Get quote, no exist SIGRL assign NULL to all related fields */
	ret = sgx_get_quote(&report, 
						SGX_UNLINKABLE_SIGNATURE, p_spid, 
						NULL, NULL, NULL, NULL, p_quote, *p_quote_size);
	if (ret != SGX_SUCCESS) {
        printf("\nApp: error %#x, failed to get quote.\n", ret);
    }
	printf("\nLog: Testing Get Quote -> STATUS: Successful.\n");

	return ret;
}

#define TEST_ATTESENCLAVE
#ifdef TEST_ATTESENCLAVE

//-------------< Test Stub >--------------------------------------
/*
* This test stub is used to simulate the workflow when enclave application
* reccevices challenge from SP, the enclave application workflow can be
* described as follow:
*
* 1. Init Quote Structure, allocate memory space.						<sgx_init_quote()>
* 2. Generate Report Structure for target enclve.						< createReport() >
*    - createReport() is an ECALL function defeined in 
*	 - attesenclave.edl.
* 3. Get the quote size													< sgx_get_quote_size() >
* 4. Get quote structure from quote enclave.							< sgx_get_quote() >
* 5. Dump quote structure into hex format from memory.					< DumpHex() >
* 6. Base64 encode the corresponding block for quote structure.         < Base64_Encode() >
* 7. Send encoded base64 string to SP.
*
* Once SP get the base64 encoded quote string, SP can request IAS with. 
* the generated string, and register for a attestation report.
*/
int main()
{
	/* predefined vars & elements for enclave processing */
	sgx_enclave_id_t	eid;
    sgx_status_t		ret   = SGX_SUCCESS;
    sgx_launch_token_t	token = {0};
    int					updated = 0;
	int					enclave_lost_retry_time = 1;
	int					busy_retry_time = 2;

	uint32_t			p_quote_size = 0;
	sgx_quote_t			p_quote;

	/* Create Enclaves */
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("\nApp: error %#x, failed to create enclave.\n", ret);
    }
	printf("\nEnclave Created.\n");

	/* Get Quote Structure */
	ret = getQuote(eid, &p_quote, &p_quote_size);
	

#define DUMP_MODE
#ifdef DUMP_MODE
	/* Method 1 - Dump Quote Structure from Memory */
	hexDumpPrint ("quote structure dump", &p_quote, p_quote_size);
#endif

#ifdef ENCODE_MODE
	/* To replace this party using _sgx_ra_msg3_t struct*/
	/* Method 2 - Base64 Encode Quote Structure */
	char* b64Quote;
	b64Quote = (char*)malloc(p_quote_size);

	int len, iter;
	len = base64_encode(b64Quote, &p_quote, p_quote_size);
	for(iter = 0; iter < len; iter++)
	{
		printf("%c", b64Quote[iter]);
	}
	printf("\n");
#endif
	/* Delete Enclave */
	if(SGX_SUCCESS != sgx_destroy_enclave(eid))
        printf("\nApp: error, failed to destroy enclave.\n");
	printf("\nEnclaves Destoried\n");

    getchar();
    return 0;

}

#endif