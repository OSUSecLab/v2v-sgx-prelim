#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_seal_keys_t {
	sgx_status_t ms_retval;
	uint8_t* ms_plaintext;
	size_t ms_plaintext_len;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_seal_keys_t;

typedef struct ms_prepare_broadcast_t {
	sgx_status_t ms_retval;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
	char* ms_encMessageOut;
	size_t ms_lenOut;
} ms_prepare_broadcast_t;

typedef struct ms_receive_broadcast_t {
	sgx_status_t ms_retval;
	char* ms_rcvdEncMessageIn;
	size_t ms_rcvdEncMessageInLen;
	char* ms_resultOut;
	size_t ms_resultOutLen;
} ms_receive_broadcast_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_print_uint8_array_t {
	uint8_t* ms_array;
	size_t ms_len;
} ms_ocall_print_uint8_array_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_uint8_array(void* pms)
{
	ms_ocall_print_uint8_array_t* ms = SGX_CAST(ms_ocall_print_uint8_array_t*, pms);
	ocall_print_uint8_array(ms->ms_array, ms->ms_len);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_Enclave = {
	2,
	{
		(void*)Enclave_ocall_print,
		(void*)Enclave_ocall_print_uint8_array,
	}
};
sgx_status_t seal_keys(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status;
	ms_seal_keys_t ms;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t prepare_broadcast(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, char* encMessageOut, size_t lenOut)
{
	sgx_status_t status;
	ms_prepare_broadcast_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	ms.ms_encMessageOut = encMessageOut;
	ms.ms_lenOut = lenOut;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t receive_broadcast(sgx_enclave_id_t eid, sgx_status_t* retval, char* rcvdEncMessageIn, size_t rcvdEncMessageInLen, char* resultOut, size_t resultOutLen)
{
	sgx_status_t status;
	ms_receive_broadcast_t ms;
	ms.ms_rcvdEncMessageIn = rcvdEncMessageIn;
	ms.ms_rcvdEncMessageInLen = rcvdEncMessageInLen;
	ms.ms_resultOut = resultOut;
	ms.ms_resultOutLen = resultOutLen;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

