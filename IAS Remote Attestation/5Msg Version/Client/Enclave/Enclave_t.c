#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_enclave_init_ra_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_p_context;
} ms_enclave_init_ra_t;

typedef struct ms_process_RA_status_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_attestationStatus;
	uint8_t* ms_cmacStatus;
	uint8_t* ms_p_payload;
	int ms_payLen;
	int ms_cryptLen;
	uint8_t* ms_p_iv;
	uint8_t* ms_sealedSecret;
} ms_process_RA_status_t;

typedef struct ms_unsealSecret_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealedSecret;
} ms_unsealSecret_t;

typedef struct ms_encryptWithSecretKey_t {
	sgx_status_t ms_retval;
	uint32_t ms_length;
	uint8_t* ms_clear;
	uint8_t* ms_crypt;
	uint8_t* ms_crypt_mac;
	uint8_t* ms_iv;
} ms_encryptWithSecretKey_t;

typedef struct ms_decryptWithSecretKey_t {
	sgx_status_t ms_retval;
	uint32_t ms_length;
	uint8_t* ms_clear;
	uint8_t* ms_crypt;
	uint8_t* ms_crypt_mac;
	uint8_t* ms_iv;
} ms_decryptWithSecretKey_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ra_msg2_t* ms_p_msg2;
	sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_enclave_init_ra(void* pms)
{
	ms_enclave_init_ra_t* ms = SGX_CAST(ms_enclave_init_ra_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_p_context = ms->ms_p_context;
	size_t _len_p_context = sizeof(*_tmp_p_context);
	sgx_ra_context_t* _in_p_context = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_enclave_init_ra_t));
	CHECK_UNIQUE_POINTER(_tmp_p_context, _len_p_context);

	if (_tmp_p_context != NULL) {
		if ((_in_p_context = (sgx_ra_context_t*)malloc(_len_p_context)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_context, 0, _len_p_context);
	}
	ms->ms_retval = enclave_init_ra(ms->ms_b_pse, _in_p_context);
err:
	if (_in_p_context) {
		memcpy(_tmp_p_context, _in_p_context, _len_p_context);
		free(_in_p_context);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_process_RA_status(void* pms)
{
	ms_process_RA_status_t* ms = SGX_CAST(ms_process_RA_status_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_attestationStatus = ms->ms_attestationStatus;
	size_t _len_attestationStatus = 4 * sizeof(*_tmp_attestationStatus);
	uint8_t* _in_attestationStatus = NULL;
	uint8_t* _tmp_cmacStatus = ms->ms_cmacStatus;
	size_t _len_cmacStatus = 16 * sizeof(*_tmp_cmacStatus);
	uint8_t* _in_cmacStatus = NULL;
	uint8_t* _tmp_p_payload = ms->ms_p_payload;
	int _tmp_payLen = ms->ms_payLen;
	size_t _len_p_payload = _tmp_payLen * sizeof(*_tmp_p_payload);
	uint8_t* _in_p_payload = NULL;
	uint8_t* _tmp_p_iv = ms->ms_p_iv;
	size_t _len_p_iv = 28 * sizeof(*_tmp_p_iv);
	uint8_t* _in_p_iv = NULL;
	uint8_t* _tmp_sealedSecret = ms->ms_sealedSecret;
	size_t _len_sealedSecret = 632 * sizeof(*_tmp_sealedSecret);
	uint8_t* _in_sealedSecret = NULL;

	if (4 > (SIZE_MAX / sizeof(*_tmp_attestationStatus))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	if (16 > (SIZE_MAX / sizeof(*_tmp_cmacStatus))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	if ((size_t)_tmp_payLen > (SIZE_MAX / sizeof(*_tmp_p_payload))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	if (28 > (SIZE_MAX / sizeof(*_tmp_p_iv))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	if (632 > (SIZE_MAX / sizeof(*_tmp_sealedSecret))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_process_RA_status_t));
	CHECK_UNIQUE_POINTER(_tmp_attestationStatus, _len_attestationStatus);
	CHECK_UNIQUE_POINTER(_tmp_cmacStatus, _len_cmacStatus);
	CHECK_UNIQUE_POINTER(_tmp_p_payload, _len_p_payload);
	CHECK_UNIQUE_POINTER(_tmp_p_iv, _len_p_iv);
	CHECK_UNIQUE_POINTER(_tmp_sealedSecret, _len_sealedSecret);

	if (_tmp_attestationStatus != NULL) {
		_in_attestationStatus = (uint8_t*)malloc(_len_attestationStatus);
		if (_in_attestationStatus == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_attestationStatus, _tmp_attestationStatus, _len_attestationStatus);
	}
	if (_tmp_cmacStatus != NULL) {
		_in_cmacStatus = (uint8_t*)malloc(_len_cmacStatus);
		if (_in_cmacStatus == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_cmacStatus, _tmp_cmacStatus, _len_cmacStatus);
	}
	if (_tmp_p_payload != NULL) {
		_in_p_payload = (uint8_t*)malloc(_len_p_payload);
		if (_in_p_payload == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_payload, _tmp_p_payload, _len_p_payload);
	}
	if (_tmp_p_iv != NULL) {
		_in_p_iv = (uint8_t*)malloc(_len_p_iv);
		if (_in_p_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_iv, _tmp_p_iv, _len_p_iv);
	}
	if (_tmp_sealedSecret != NULL) {
		if ((_in_sealedSecret = (uint8_t*)malloc(_len_sealedSecret)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealedSecret, 0, _len_sealedSecret);
	}
	ms->ms_retval = process_RA_status(ms->ms_context, _in_attestationStatus, _in_cmacStatus, _in_p_payload, _tmp_payLen, ms->ms_cryptLen, _in_p_iv, _in_sealedSecret);
err:
	if (_in_attestationStatus) free(_in_attestationStatus);
	if (_in_cmacStatus) free(_in_cmacStatus);
	if (_in_p_payload) free(_in_p_payload);
	if (_in_p_iv) free(_in_p_iv);
	if (_in_sealedSecret) {
		memcpy(_tmp_sealedSecret, _in_sealedSecret, _len_sealedSecret);
		free(_in_sealedSecret);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_unsealSecret(void* pms)
{
	ms_unsealSecret_t* ms = SGX_CAST(ms_unsealSecret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealedSecret = ms->ms_sealedSecret;
	size_t _len_sealedSecret = 632 * sizeof(*_tmp_sealedSecret);
	uint8_t* _in_sealedSecret = NULL;

	if (632 > (SIZE_MAX / sizeof(*_tmp_sealedSecret))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_unsealSecret_t));
	CHECK_UNIQUE_POINTER(_tmp_sealedSecret, _len_sealedSecret);

	if (_tmp_sealedSecret != NULL) {
		_in_sealedSecret = (uint8_t*)malloc(_len_sealedSecret);
		if (_in_sealedSecret == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sealedSecret, _tmp_sealedSecret, _len_sealedSecret);
	}
	ms->ms_retval = unsealSecret(_in_sealedSecret);
err:
	if (_in_sealedSecret) free(_in_sealedSecret);

	return status;
}

static sgx_status_t SGX_CDECL sgx_encryptWithSecretKey(void* pms)
{
	ms_encryptWithSecretKey_t* ms = SGX_CAST(ms_encryptWithSecretKey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_clear = ms->ms_clear;
	uint32_t _tmp_length = ms->ms_length;
	size_t _len_clear = _tmp_length * sizeof(*_tmp_clear);
	uint8_t* _in_clear = NULL;
	uint8_t* _tmp_crypt = ms->ms_crypt;
	size_t _len_crypt = _tmp_length * sizeof(*_tmp_crypt);
	uint8_t* _in_crypt = NULL;
	uint8_t* _tmp_crypt_mac = ms->ms_crypt_mac;
	size_t _len_crypt_mac = 16 * sizeof(*_tmp_crypt_mac);
	uint8_t* _in_crypt_mac = NULL;
	uint8_t* _tmp_iv = ms->ms_iv;
	size_t _len_iv = 12 * sizeof(*_tmp_iv);
	uint8_t* _in_iv = NULL;

	if ((size_t)_tmp_length > (SIZE_MAX / sizeof(*_tmp_clear))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	if ((size_t)_tmp_length > (SIZE_MAX / sizeof(*_tmp_crypt))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	if (16 > (SIZE_MAX / sizeof(*_tmp_crypt_mac))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	if (12 > (SIZE_MAX / sizeof(*_tmp_iv))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_encryptWithSecretKey_t));
	CHECK_UNIQUE_POINTER(_tmp_clear, _len_clear);
	CHECK_UNIQUE_POINTER(_tmp_crypt, _len_crypt);
	CHECK_UNIQUE_POINTER(_tmp_crypt_mac, _len_crypt_mac);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);

	if (_tmp_clear != NULL) {
		_in_clear = (uint8_t*)malloc(_len_clear);
		if (_in_clear == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_clear, _tmp_clear, _len_clear);
	}
	if (_tmp_crypt != NULL) {
		if ((_in_crypt = (uint8_t*)malloc(_len_crypt)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_crypt, 0, _len_crypt);
	}
	if (_tmp_crypt_mac != NULL) {
		if ((_in_crypt_mac = (uint8_t*)malloc(_len_crypt_mac)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_crypt_mac, 0, _len_crypt_mac);
	}
	if (_tmp_iv != NULL) {
		_in_iv = (uint8_t*)malloc(_len_iv);
		if (_in_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_iv, _tmp_iv, _len_iv);
	}
	ms->ms_retval = encryptWithSecretKey(_tmp_length, _in_clear, _in_crypt, _in_crypt_mac, _in_iv);
err:
	if (_in_clear) free(_in_clear);
	if (_in_crypt) {
		memcpy(_tmp_crypt, _in_crypt, _len_crypt);
		free(_in_crypt);
	}
	if (_in_crypt_mac) {
		memcpy(_tmp_crypt_mac, _in_crypt_mac, _len_crypt_mac);
		free(_in_crypt_mac);
	}
	if (_in_iv) free(_in_iv);

	return status;
}

static sgx_status_t SGX_CDECL sgx_decryptWithSecretKey(void* pms)
{
	ms_decryptWithSecretKey_t* ms = SGX_CAST(ms_decryptWithSecretKey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_clear = ms->ms_clear;
	uint32_t _tmp_length = ms->ms_length;
	size_t _len_clear = _tmp_length * sizeof(*_tmp_clear);
	uint8_t* _in_clear = NULL;
	uint8_t* _tmp_crypt = ms->ms_crypt;
	size_t _len_crypt = _tmp_length * sizeof(*_tmp_crypt);
	uint8_t* _in_crypt = NULL;
	uint8_t* _tmp_crypt_mac = ms->ms_crypt_mac;
	size_t _len_crypt_mac = 16 * sizeof(*_tmp_crypt_mac);
	uint8_t* _in_crypt_mac = NULL;
	uint8_t* _tmp_iv = ms->ms_iv;
	size_t _len_iv = 12 * sizeof(*_tmp_iv);
	uint8_t* _in_iv = NULL;

	if ((size_t)_tmp_length > (SIZE_MAX / sizeof(*_tmp_clear))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	if ((size_t)_tmp_length > (SIZE_MAX / sizeof(*_tmp_crypt))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	if (16 > (SIZE_MAX / sizeof(*_tmp_crypt_mac))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	if (12 > (SIZE_MAX / sizeof(*_tmp_iv))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_decryptWithSecretKey_t));
	CHECK_UNIQUE_POINTER(_tmp_clear, _len_clear);
	CHECK_UNIQUE_POINTER(_tmp_crypt, _len_crypt);
	CHECK_UNIQUE_POINTER(_tmp_crypt_mac, _len_crypt_mac);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);

	if (_tmp_clear != NULL) {
		if ((_in_clear = (uint8_t*)malloc(_len_clear)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_clear, 0, _len_clear);
	}
	if (_tmp_crypt != NULL) {
		_in_crypt = (uint8_t*)malloc(_len_crypt);
		if (_in_crypt == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_crypt, _tmp_crypt, _len_crypt);
	}
	if (_tmp_crypt_mac != NULL) {
		_in_crypt_mac = (uint8_t*)malloc(_len_crypt_mac);
		if (_in_crypt_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_crypt_mac, _tmp_crypt_mac, _len_crypt_mac);
	}
	if (_tmp_iv != NULL) {
		_in_iv = (uint8_t*)malloc(_len_iv);
		if (_in_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_iv, _tmp_iv, _len_iv);
	}
	ms->ms_retval = decryptWithSecretKey(_tmp_length, _in_clear, _in_crypt, _in_crypt_mac, _in_iv);
err:
	if (_in_clear) {
		memcpy(_tmp_clear, _in_clear, _len_clear);
		free(_in_clear);
	}
	if (_in_crypt) free(_in_crypt);
	if (_in_crypt_mac) free(_in_crypt_mac);
	if (_in_iv) free(_in_iv);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(*_tmp_g_a);
	sgx_ec256_public_t* _in_g_a = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	if (_tmp_g_a != NULL) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}
	ms->ms_retval = sgx_ra_get_ga(ms->ms_context, _in_g_a);
err:
	if (_in_g_a) {
		memcpy(_tmp_g_a, _in_g_a, _len_g_a);
		free(_in_g_a);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_msg2_t* _tmp_p_msg2 = ms->ms_p_msg2;
	size_t _len_p_msg2 = sizeof(*_tmp_p_msg2);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	sgx_target_info_t* _tmp_p_qe_target = ms->ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(*_tmp_p_qe_target);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(*_tmp_p_report);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = ms->ms_p_nonce;
	size_t _len_p_nonce = sizeof(*_tmp_p_nonce);
	sgx_quote_nonce_t* _in_p_nonce = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	if (_tmp_p_msg2 != NULL) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_msg2, _tmp_p_msg2, _len_p_msg2);
	}
	if (_tmp_p_qe_target != NULL) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_qe_target, _tmp_p_qe_target, _len_p_qe_target);
	}
	if (_tmp_p_report != NULL) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}
	ms->ms_retval = sgx_ra_proc_msg2_trusted(ms->ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
err:
	if (_in_p_msg2) free((void*)_in_p_msg2);
	if (_in_p_qe_target) free((void*)_in_p_qe_target);
	if (_in_p_report) {
		memcpy(_tmp_p_report, _in_p_report, _len_p_report);
		free(_in_p_report);
	}
	if (_in_p_nonce) {
		memcpy(_tmp_p_nonce, _in_p_nonce, _len_p_nonce);
		free(_in_p_nonce);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = ms->ms_qe_report;
	size_t _len_qe_report = sizeof(*_tmp_qe_report);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = ms->ms_p_msg3;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	if (_tmp_qe_report != NULL) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_qe_report, _tmp_qe_report, _len_qe_report);
	}
	ms->ms_retval = sgx_ra_get_msg3_trusted(ms->ms_context, ms->ms_quote_size, _in_qe_report, _tmp_p_msg3, ms->ms_msg3_size);
err:
	if (_in_qe_report) free(_in_qe_report);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_enclave_init_ra, 0},
		{(void*)(uintptr_t)sgx_process_RA_status, 0},
		{(void*)(uintptr_t)sgx_unsealSecret, 0},
		{(void*)(uintptr_t)sgx_encryptWithSecretKey, 0},
		{(void*)(uintptr_t)sgx_decryptWithSecretKey, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[9][8];
} g_dyn_entry_table = {
	9,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(*sid);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) ? _len_sid : 0;
	ocalloc_size += (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) ? _len_dh_msg1 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));

	if (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) {
		ms->ms_sid = (uint32_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_sid);
		memset(ms->ms_sid, 0, _len_sid);
	} else if (sid == NULL) {
		ms->ms_sid = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) {
		ms->ms_dh_msg1 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		memset(ms->ms_dh_msg1, 0, _len_dh_msg1);
	} else if (dh_msg1 == NULL) {
		ms->ms_dh_msg1 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg1_size = dh_msg1_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(0, ms);

	if (retval) *retval = ms->ms_retval;
	if (sid) memcpy((void*)sid, ms->ms_sid, _len_sid);
	if (dh_msg1) memcpy((void*)dh_msg1, ms->ms_dh_msg1, _len_dh_msg1);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) ? _len_dh_msg2 : 0;
	ocalloc_size += (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) ? _len_dh_msg3 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));

	ms->ms_sid = sid;
	if (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) {
		ms->ms_dh_msg2 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		memcpy(ms->ms_dh_msg2, dh_msg2, _len_dh_msg2);
	} else if (dh_msg2 == NULL) {
		ms->ms_dh_msg2 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg2_size = dh_msg2_size;
	if (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) {
		ms->ms_dh_msg3 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		memset(ms->ms_dh_msg3, 0, _len_dh_msg3);
	} else if (dh_msg3 == NULL) {
		ms->ms_dh_msg3 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg3_size = dh_msg3_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(1, ms);

	if (retval) *retval = ms->ms_retval;
	if (dh_msg3) memcpy((void*)dh_msg3, ms->ms_dh_msg3, _len_dh_msg3);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));

	ms->ms_sid = sid;
	ms->ms_timeout = timeout;
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) ? _len_pse_message_req : 0;
	ocalloc_size += (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) ? _len_pse_message_resp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));

	if (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) {
		ms->ms_pse_message_req = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
		memcpy(ms->ms_pse_message_req, pse_message_req, _len_pse_message_req);
	} else if (pse_message_req == NULL) {
		ms->ms_pse_message_req = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_req_size = pse_message_req_size;
	if (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) {
		ms->ms_pse_message_resp = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
		memset(ms->ms_pse_message_resp, 0, _len_pse_message_resp);
	} else if (pse_message_resp == NULL) {
		ms->ms_pse_message_resp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_resp_size = pse_message_resp_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;
	if (pse_message_resp) memcpy((void*)pse_message_resp, ms->ms_pse_message_resp, _len_pse_message_resp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(4, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
