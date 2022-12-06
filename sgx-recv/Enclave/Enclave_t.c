#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_seal_keys(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_seal_keys_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_seal_keys_t* ms = SGX_CAST(ms_seal_keys_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_plaintext = ms->ms_plaintext;
	size_t _tmp_plaintext_len = ms->ms_plaintext_len;
	size_t _len_plaintext = _tmp_plaintext_len;
	uint8_t* _in_plaintext = NULL;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ( _len_plaintext % sizeof(*_tmp_plaintext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_plaintext = (uint8_t*)malloc(_len_plaintext);
		if (_in_plaintext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_plaintext, _len_plaintext, _tmp_plaintext, _len_plaintext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ((_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}

	ms->ms_retval = seal_keys(_in_plaintext, _tmp_plaintext_len, _in_sealed_data, _tmp_sealed_size);
	if (_in_sealed_data) {
		if (memcpy_s(_tmp_sealed_data, _len_sealed_data, _in_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_plaintext) free(_in_plaintext);
	if (_in_sealed_data) free(_in_sealed_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_prepare_broadcast(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_prepare_broadcast_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_prepare_broadcast_t* ms = SGX_CAST(ms_prepare_broadcast_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;
	char* _tmp_encMessageOut = ms->ms_encMessageOut;
	size_t _tmp_lenOut = ms->ms_lenOut;
	size_t _len_encMessageOut = _tmp_lenOut;
	char* _in_encMessageOut = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_encMessageOut, _len_encMessageOut);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_data, _len_sealed_data, _tmp_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_encMessageOut != NULL && _len_encMessageOut != 0) {
		if ( _len_encMessageOut % sizeof(*_tmp_encMessageOut) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encMessageOut = (char*)malloc(_len_encMessageOut)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encMessageOut, 0, _len_encMessageOut);
	}

	ms->ms_retval = prepare_broadcast(_in_sealed_data, _tmp_sealed_size, _in_encMessageOut, _tmp_lenOut);
	if (_in_encMessageOut) {
		if (memcpy_s(_tmp_encMessageOut, _len_encMessageOut, _in_encMessageOut, _len_encMessageOut)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_encMessageOut) free(_in_encMessageOut);
	return status;
}

static sgx_status_t SGX_CDECL sgx_receive_broadcast(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_receive_broadcast_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_receive_broadcast_t* ms = SGX_CAST(ms_receive_broadcast_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_rcvdEncMessageIn = ms->ms_rcvdEncMessageIn;
	size_t _tmp_rcvdEncMessageInLen = ms->ms_rcvdEncMessageInLen;
	size_t _len_rcvdEncMessageIn = _tmp_rcvdEncMessageInLen;
	char* _in_rcvdEncMessageIn = NULL;
	char* _tmp_resultOut = ms->ms_resultOut;
	size_t _tmp_resultOutLen = ms->ms_resultOutLen;
	size_t _len_resultOut = _tmp_resultOutLen;
	char* _in_resultOut = NULL;

	CHECK_UNIQUE_POINTER(_tmp_rcvdEncMessageIn, _len_rcvdEncMessageIn);
	CHECK_UNIQUE_POINTER(_tmp_resultOut, _len_resultOut);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_rcvdEncMessageIn != NULL && _len_rcvdEncMessageIn != 0) {
		if ( _len_rcvdEncMessageIn % sizeof(*_tmp_rcvdEncMessageIn) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rcvdEncMessageIn = (char*)malloc(_len_rcvdEncMessageIn);
		if (_in_rcvdEncMessageIn == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rcvdEncMessageIn, _len_rcvdEncMessageIn, _tmp_rcvdEncMessageIn, _len_rcvdEncMessageIn)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_resultOut != NULL && _len_resultOut != 0) {
		if ( _len_resultOut % sizeof(*_tmp_resultOut) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_resultOut = (char*)malloc(_len_resultOut)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_resultOut, 0, _len_resultOut);
	}

	ms->ms_retval = receive_broadcast(_in_rcvdEncMessageIn, _tmp_rcvdEncMessageInLen, _in_resultOut, _tmp_resultOutLen);
	if (_in_resultOut) {
		if (memcpy_s(_tmp_resultOut, _len_resultOut, _in_resultOut, _len_resultOut)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_rcvdEncMessageIn) free(_in_rcvdEncMessageIn);
	if (_in_resultOut) free(_in_resultOut);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_seal_keys, 0, 0},
		{(void*)(uintptr_t)sgx_prepare_broadcast, 0, 0},
		{(void*)(uintptr_t)sgx_receive_broadcast, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][3];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_uint8_array(uint8_t* array, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_array = len;

	ms_ocall_print_uint8_array_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_uint8_array_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(array, _len_array);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (array != NULL) ? _len_array : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_uint8_array_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_uint8_array_t));
	ocalloc_size -= sizeof(ms_ocall_print_uint8_array_t);

	if (array != NULL) {
		ms->ms_array = (uint8_t*)__tmp;
		if (_len_array % sizeof(*array) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, array, _len_array)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_array);
		ocalloc_size -= _len_array;
	} else {
		ms->ms_array = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

