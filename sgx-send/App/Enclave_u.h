#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_tseal.h"
#include "common.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif
#ifndef OCALL_PRINT_UINT8_ARRAY_DEFINED__
#define OCALL_PRINT_UINT8_ARRAY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_uint8_array, (uint8_t* array, size_t len));
#endif

sgx_status_t seal_keys(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t prepare_broadcast(sgx_enclave_id_t eid, sgx_status_t* retval, char* encMessageOut, size_t lenOut);
sgx_status_t receive_broadcast(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, char* rcvdEncMessageIn, size_t rcvdEncMessageInLen, char* resultOut, size_t resultOutLen);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
