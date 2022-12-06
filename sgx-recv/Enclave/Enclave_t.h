#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tseal.h"
#include "common.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t seal_keys(uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t prepare_broadcast(sgx_sealed_data_t* sealed_data, size_t sealed_size, char* encMessageOut, size_t lenOut);
sgx_status_t receive_broadcast(char* rcvdEncMessageIn, size_t rcvdEncMessageInLen, char* resultOut, size_t resultOutLen);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_print_uint8_array(uint8_t* array, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
